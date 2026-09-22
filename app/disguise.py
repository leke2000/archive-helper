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
from dataclasses import dataclass, field

# archive container signatures
SIG_7Z = b"7z\xbc\xaf\x27\x1c"
SIG_RAR5 = b"Rar!\x1a\x07\x01\x00"
SIG_RAR4 = b"Rar!\x1a\x07\x00"
SIG_ZIP_LOCAL = b"PK\x03\x04"
SIG_ZIP_EOCD = b"PK\x05\x06"

ARCHIVE_SIGS = (SIG_7Z, SIG_RAR5, SIG_RAR4, SIG_ZIP_LOCAL)

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
    return ""


def _looks_like_media(head: bytes) -> bool:
    for sig in MEDIA_SIGS:
        idx = head.find(sig)
        if 0 <= idx <= 12:
            return True
    return False


def _is_blank(buf: bytes) -> bool:
    """All zero bytes — 网盘未下载的部分会被填零。"""
    return len(buf) > 0 and buf == b"\x00" * len(buf)


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
            chunk = 32 << 20
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
        chunk = 32 << 20
        while remaining > 0:
            b = fi.read(min(chunk, remaining))
            if not b:
                break
            fo.write(b)
            remaining -= len(b)
            done += len(b)
            if progress:
                progress(done, length)
