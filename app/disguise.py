"""Detection and reversal of disguised archives.

Two disguises are handled generically:

1. "Tail-reversed" (Apate style)
   layout = [decoy media header (L bytes)][middle][reverse(first L bytes)][L as u32 LE]
   The last 4 bytes hold L, so the original archive is
       reverse(trailing L bytes) + middle.

2. "Appended archive"
   A real media file followed by a complete archive (optionally after some
   padding).  Detected by scanning for archive signatures.

Nothing here is tied to one creator's tool: every check is structural.
"""

from __future__ import annotations

import os
import struct
import zlib
from dataclasses import dataclass, field

# archive container signatures
SIG_7Z = b"7z\xbc\xaf\x27\x1c"
SIG_RAR5 = b"Rar!\x1a\x07\x01\x00"
SIG_RAR4 = b"Rar!\x1a\x07\x00"
SIG_ZIP_LOCAL = b"PK\x03\x04"
SIG_ZIP_EOCD = b"PK\x05\x06"
# 拷贝分块：实测 8MB 在跨盘（D:->H:）比 1MB 快 30%，比 32MB 也快
COPY_CHUNK = 8 << 20
SIG_GZIP = b"\x1f\x8b\x08"

ARCHIVE_SIGS = (SIG_7Z, SIG_RAR5, SIG_RAR4, SIG_ZIP_LOCAL)

# 容器类型 -> 建议的扩展名（用于给去掉扩展名的压缩包起个好名字）
CONTAINER_EXT = {
    "gzip": ".gz",
    "7z": ".7z",
    "zip": ".zip",
    "rar": ".rar",
}


def sniff_container(path: str) -> str | None:
    """按文件头判断容器类型，不依赖文件名。

    资源站常把扩展名整个去掉（如 "课件196" 实为 gzip、"617" 实为 7z），
    只看后缀会完全漏掉这些文件。返回 'gzip'/'7z'/'zip'/'rar' 或 None。
    """
    try:
        with open(path, "rb") as f:
            head = f.read(8)
    except OSError:
        return None
    if head.startswith(SIG_7Z):
        return "7z"
    if head[:2] == SIG_GZIP[:2] and len(head) >= 3 and head[2] == SIG_GZIP[2]:
        return "gzip"
    if head.startswith(SIG_RAR5) or head.startswith(SIG_RAR4):
        return "rar"
    if head.startswith(SIG_ZIP_LOCAL):
        return "zip"
    return None

# media signatures used to recognise a decoy header
MEDIA_SIGS = (
    b"ftyp",        # mp4/mov (at offset 4)
    b"\xff\xd8\xff",  # jpeg
    b"\x89PNG\r\n\x1a\n",  # png
    b"RIFF",        # webp/wav/avi
    b"GIF8",        # gif
    b"\x1a\x45\xdf\xa3",  # matroska/webm
    b"ID3",         # mp3
    b"OggS",        # ogg
)


@dataclass
class Detection:
    kind: str                      # "tail_reversed" | "appended" | "plain"
    decoy_len: int = 0
    archive_offset: int = 0        # offset where the archive begins
    signature: str = ""
    notes: list[str] = field(default_factory=list)


def _read_head(path: str, n: int) -> bytes:
    with open(path, "rb") as f:
        return f.read(n)


def _read_tail(path: str, n: int) -> bytes:
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        f.seek(max(0, size - n))
        return f.read(n)


def _sig_name(buf: bytes) -> str:
    if buf.startswith(SIG_7Z):
        return "7z"
    if buf.startswith(SIG_RAR5):
        return "rar5"
    if buf.startswith(SIG_RAR4):
        return "rar4"
    if buf.startswith(SIG_ZIP_LOCAL):
        return "zip"
    if buf.startswith(SIG_GZIP):
        return "gz"
    return ""


def is_incomplete_7z(path: str) -> bool:
    """判断是不是"缺后续分卷"的 7z 首卷。

    7z 起始头里记录了整个流的大小（nextHeaderOffset + nextHeaderSize）。
    如果文件实际比它小，说明还有后续分卷没到 —— 此时应该把文件名
    规范成 .7z.001，让 7-Zip 去找 .002。
    """
    try:
        with open(path, "rb") as f:
            head = f.read(32)
    except OSError:
        return False
    if len(head) < 32 or not head.startswith(SIG_7Z):
        return False
    try:
        nho, nhs = struct.unpack("<QQ", head[12:28])
    except struct.error:
        return False
    if nho == 0 or nhs == 0:
        return False
    total = 32 + nho + nhs
    return total > os.path.getsize(path)


def missing_volume_bytes(path: str) -> int:
    """首卷还缺多少字节才算完整；不缺（或不是首卷）返回 0。

    只拿首卷自己跟头里的总大小比会误判：分卷集的首卷本来就"比整个归档小"。
    必须把同目录下的 .002/.003... 一起累加，才能分清是真缺卷，还是
    分卷都在、只是密码不对（头部加密时 7-Zip 报的是 Wrong password）。
    """
    if not path.lower().endswith(".001"):
        return 0
    try:
        with open(path, "rb") as f:
            head = f.read(32)
        if len(head) < 32 or not head.startswith(SIG_7Z):
            return 0
        nho, nhs = struct.unpack("<QQ", head[12:28])
        if nho == 0 or nhs == 0:
            return 0
        need = 32 + nho + nhs
        have = 0
        base = path[:-4]
        for i in range(1, 1000):
            vol = f"{base}.{i:03d}"
            if os.path.exists(vol):
                have += os.path.getsize(vol)
            elif i > 1:
                break       # 分卷编号必须连续，断了就是缺卷
        return max(0, need - have)
    except (OSError, struct.error):
        return 0


def _looks_like_media(head: bytes) -> bool:
    for sig in MEDIA_SIGS:
        idx = head.find(sig)
        if 0 <= idx <= 12:
            return True
    return False


def _is_blank(buf: bytes) -> bool:
    """All zero bytes — 网盘未下载的部分会被填零。"""
    return len(buf) > 0 and buf == b"\x00" * len(buf)


# Apate 的面具是媒体/可执行文件（mp4/jpg/mov/EXE），不是归档 —— 反转尾部
# 之后如果出现这些"文件头"，同样说明这是尾部反转伪装
_FILE_HEADS = (
    b"ftyp", b"moov", b"mdat", b"\xff\xd8\xff", b"\x89PNG", b"GIF8", b"RIFF",
    b"\x1aE\xdf\xa3", b"MZ", b"%PDF", b"OggS", b"FLV", b"wOFF", b"OTTO",
    b"\x7fELF", b"BM", b"II*\x00", b"MM\x00*", b"\x00\x00\x01\x00",
)
# Apate 源码里的上限：面具最长 2GB/7 ≈ 306MB；超过这个值就不可能是面具长度
MAX_MASK_LEN = 2147483647 // 7


def _looks_like_file_head(b: bytes) -> bool:
    """这段字节像不像一个文件的开头（用于判断"反转尾部得到的是原文件头"）。"""
    for sig in _FILE_HEADS:
        if b.startswith(sig):
            return True
    # ftyp 在偏移 4 处（如 00 00 00 20 66 74 79 70 ...）
    if len(b) >= 8 and b[4:8] in (b"ftyp", b"moov", b"mdat"):
        return True
    return False


def _tail_reversed_ok(path: str, size: int) -> Detection | None:
    """Try to interpret the file as [decoy][body][reverse(decoy)][L].

    Accepts when the reversed trailer starts with a real archive signature.
    The decoy header itself may be zeroed out on an incomplete download, so
    looking like a media file is supporting evidence, not a requirement.
    """
    if size <= 16:
        return None
    last4 = _read_tail(path, 4)
    L = int.from_bytes(last4, "little")
    if not (0 < L < size - 8 and L <= size - 4 - L):
        return None
    tail_block = _read_tail(path, 4 + L)[:L]
    reversed_head = tail_block[::-1]
    sig = _sig_name(reversed_head)
    if not sig:
        # 归档签名没有，但"反转后的尾部"如果是媒体/可执行文件头，
        # 那同样是 Apate 这类"面具伪装"（面具是 mp4/jpg/EXE，不是压缩包）
        if _looks_like_file_head(reversed_head):
            notes = [f"decoy {L} bytes, 反转尾部是文件头（面具伪装）"]
            head = _read_head(path, 64)
            if _looks_like_media(head):
                notes.append("decoy looks like media")
            return Detection("tail_reversed", L, 0, "", notes)
        return None

    head = _read_head(path, 64)
    notes = [f"decoy {L} bytes, restored head is {sig}"]
    if _looks_like_media(head):
        notes.append("decoy looks like media")
    elif _is_blank(head):
        notes.append("decoy header is blank (可能下载不完整)")
    else:
        notes.append("decoy header unrecognised; accepted by trailer signature")
    return Detection("tail_reversed", L, 0, sig, notes)


def _archive_header_ok(path: str, off: int, sig: bytes) -> bool:
    """判断某个偏移处的"归档签名"是不是真的归档头。

    随机数据里撞出 4 字节签名的概率并不低（9GB 的文件里有 1~2 次），
    我们真的踩到过：一个加密伪装包里 7.3GB 处有个假 PK，
    结果白拷贝了 1.79GB 才发现不是 zip。所以这里按各格式的头字段再验一遍。
    """
    try:
        with open(path, "rb") as f:
            f.seek(off)
            head = f.read(64)
    except OSError:
        return False
    if not head.startswith(sig):
        return False
    if sig == SIG_ZIP_LOCAL:
        if len(head) < 30:
            return False
        ver, flags, method = struct.unpack("<HHH", head[4:10])
        namelen, extralen = struct.unpack("<HH", head[26:30])
        return (10 <= ver <= 63) and (method <= 100)             and (0 < namelen <= 4096) and (extralen <= 65536)
    if sig == SIG_7Z:
        if len(head) < 32:
            return False
        crc = struct.unpack("<I", head[8:12])[0]
        return zlib.crc32(head[12:32]) == crc     # 7z 起始头自带 CRC32
    if sig == SIG_RAR5:
        return len(head) >= 8 and 8 <= struct.unpack("<H", head[5:7])[0] <= (1 << 20)
    if sig == SIG_RAR4:
        return len(head) >= 9 and 7 <= struct.unpack("<H", head[7:9])[0] <= (1 << 20)
    return True


def detect(path: str) -> Detection:
    """Classify how (if at all) the file is disguised."""
    size = os.path.getsize(path)
    head = _read_head(path, 64)

    # already a real archive?
    if _sig_name(head):
        return Detection("plain", 0, 0, _sig_name(head),
                         ["file already starts with an archive signature"])

    # --- tail-reversed (Apate style) ---
    d = _tail_reversed_ok(path, size)
    if d is not None:
        return d

    # --- appended archive: 从媒体结构结束处往后找最外层的包 ---
    start = _media_end(path, size) or 0
    best: tuple[int, bytes] | None = None
    for sig in ARCHIVE_SIGS:
        off = _find_signature(path, sig, start=start)
        # 一直往后找，直到找到"头字段也说得通"的那个（防随机撞签名）
        while off is not None and off > 0 and not _archive_header_ok(path, off, sig):
            off = _find_signature(path, sig, start=off + 1)
        if off is not None and off > 0:
            if best is None or off < best[0]:
                best = (off, sig)
    if best is not None:
        off, sig = best
        notes = [f"archive signature at offset {off}"]
        if start:
            notes.append(f"媒体结构结束于 {start}")
        return Detection("appended", off, off, _sig_name(sig), notes)

    return Detection("plain", 0, 0, "", ["no disguise detected"])


def _media_end(path: str, size: int, limit: int = 64) -> int | None:
    """若文件以媒体容器开头，返回其结构结束的偏移。

    用于定位"媒体 + 附加压缩包"这类伪装：从媒体结束处往后找，
    才能找到最外层的那个包。返回 None 表示不是可解析的媒体容器。
    """
    head = _read_head(path, 16)
    if len(head) < 16:
        return None

    # MP4 / MOV：顶层 box 链（ftyp → moov → mdat …）
    if head[4:8] == b"ftyp":
        pos = 0
        with open(path, "rb") as f:
            for _ in range(limit):
                if pos + 8 > size:
                    break
                f.seek(pos)
                h = f.read(16)
                if len(h) < 8:
                    break
                s = struct.unpack(">I", h[:4])[0]
                t = h[4:8]
                hl = 8
                if s == 1:
                    if len(h) < 16:
                        break
                    s = struct.unpack(">Q", h[8:16])[0]
                    hl = 16
                elif s == 0:
                    s = size - pos
                if s < hl or pos + s > size or not all(32 <= c < 127 for c in t):
                    return pos
                pos += s
        return pos

    # JPEG：找 EOI 标记
    if head[:2] == b"\xff\xd8":
        with open(path, "rb") as f:
            base = 0
            carry = b""
            while True:
                buf = f.read(8 << 20)
                if not buf:
                    return None
                data = carry + buf
                i = data.rfind(b"\xff\xd9")
                if i >= 0 and data[i + 2:].strip(b"\x00") == b"":
                    return base - len(carry) + i + 2
                carry = data[-1:]
                base += len(buf)

    # PNG：找 IEND 块
    if head[:8] == b"\x89PNG\r\n\x1a\n":
        off = _find_signature(path, b"IEND")
        if off is not None:
            return off + 8
    return None


def _find_signature(path: str, sig: bytes, chunk: int = 8 << 20, max_hits: int = 1,
                    start: int = 0):
    """Return the first offset of sig at/after *start*, or None. Streams the file."""
    with open(path, "rb") as f:
        f.seek(start)
        base = start
        carry = b""
        while True:
            buf = f.read(chunk)
            if not buf:
                return None
            data = carry + buf
            i = data.find(sig)
            if i >= 0:
                return base - len(carry) + i
            carry = data[-(len(sig) - 1):]
            base += len(buf)


def restore(path: str, out: str, det: Detection, progress=None) -> str:
    """Write the recovered archive to *out* and return out.

    progress: optional callable(done_bytes, total_bytes).
    """
    if det.kind == "tail_reversed":
        return _restore_tail_reversed(path, out, det.decoy_len, progress)
    if det.kind == "appended":
        return _restore_appended(path, out, det.archive_offset, progress)
    # plain: just copy
    _copy(path, out, 0, None, progress)
    return out


def _restore_tail_reversed(path, out, L, progress=None):
    size = os.path.getsize(path)
    t_start = size - 4 - L
    # head = reverse(last L bytes before the marker)
    with open(path, "rb") as f:
        f.seek(t_start)
        head = f.read(L)[::-1]
    middle_len = t_start - L
    total = L + middle_len
    done = 0
    with open(out, "wb") as fo:
        fo.write(head)
        done += L
        if progress:
            progress(done, total)
        with open(path, "rb") as f:
            f.seek(L)
            remaining = middle_len
            chunk = COPY_CHUNK
            while remaining > 0:
                b = f.read(min(chunk, remaining))
                if not b:
                    break
                fo.write(b)
                remaining -= len(b)
                done += len(b)
                if progress:
                    progress(done, total)
    return out


def _restore_appended(path, out, offset, progress=None):
    size = os.path.getsize(path)
    _copy(path, out, offset, None, progress)
    return out


def _copy(path, out, start, length=None, progress=None):
    size = os.path.getsize(path)
    if length is None:
        length = size - start
    done = 0
    with open(path, "rb") as fi, open(out, "wb") as fo:
        fi.seek(start)
        remaining = length
        chunk = COPY_CHUNK
        while remaining > 0:
            b = fi.read(min(chunk, remaining))
            if not b:
                break
            fo.write(b)
            remaining -= len(b)
            done += len(b)
            if progress:
                progress(done, length)
