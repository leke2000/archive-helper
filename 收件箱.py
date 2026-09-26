# Windows 上用 py / python 启动即可（这行原来是 shebang，会害 py.exe 找错解释器）
"""收件箱模式：扫描目录，自动识别伪装/分卷/加密压缩包，解压并分类归档。

用法（在 解压助手 目录下）:
    收件箱.py                      # 默认 D:\\dowm -> H:\\赏花阁
    收件箱.py <收件目录> <归档目录>
    收件箱.py --delete-source      # 归档成功后删除源压缩包

密码从 <收件目录>\\解压密码.txt 读取（每行一个），也会自动从说明文件和
目录名里提取 "密码:xxx"。详见 app/passwords.py。

处理能力：
  * 普通压缩包 / 分卷 (.7z.001, .zip.001, .rar.001 ...)
  * 伪装扩展名 (xxx.7z.001.pdf, xxx.zip.mp4 ...)
  * 卷号后面带杂字 (26.7z.001删)
  * 首卷丢了卷号 (26.7z + 26.7z.002)
  * 分卷分散在不同子文件夹
  * 尾部反转 / 追加型伪装 (Apate 类，见 app/disguise.py)
  * 浏览器重复下载的副本自动去重
  * 下载中的 .qkdownloading 文件自动跳过
  * 解压后按 图片/视频/其他 分类归档
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

from app.disguise import detect, sniff_container, is_incomplete_7z, CONTAINER_EXT
from app.pipeline import Pipeline
from app.sevenzip import SevenZip

DEFAULT_INBOX = r"D:\dowm"
DEFAULT_DEST = r"H:\赏花阁"
PASSWORD_FILE = "解压密码.txt"
STAGING = r"D:\_staging"

# 处理成功过的源文件记录（路径 -> 大小:修改时间），避免重复解压已归档的包。
# 重新下载同一个包会刷新修改时间，那时会正常再处理一遍。
DONE_FILE = os.path.join(_HERE, "_done.json")

# 这些目录不是收件箱（工具自身、已解压好的游戏），递归时跳过
SKIP_DIRS = {
    "解压助手",
    "$RECYCLE.BIN",
    "System Volume Information",
    "《碧蓝航线》本地一键端",
}

# 形如 <base>.001 / <base>.002 ... ，后面允许跟杂字（如 "26.7z.001删"）
_PART_RE = re.compile(r"^(?P<base>.*\.(?:7z|zip|rar))(?P<vol>\.\d{3})?(?P<tail>.*)$",
                      re.IGNORECASE)
# 名字像媒体 -> 可能是伪装包
_MEDIA_EXT = {".mp4", ".mov", ".mkv", ".ts", ".jpg", ".jpeg", ".png", ".pdf",
              ".avi", ".webm", ".m4v", ".gif", ".webp"}

# 这些扩展名已有明确含义，不必再按文件头猜（其中 docx/xlsx/pptx/apk 本身就是 zip，
# 猜了反而会误判成压缩包）
_KNOWN_EXT = _MEDIA_EXT | {
    ".txt", ".url", ".lnk", ".pptx", ".docx", ".xlsx", ".doc", ".xls", ".ppt",
    ".exe", ".dll", ".sys", ".msi", ".apk", ".ipa", ".jar", ".py", ".js", ".json",
    ".csv", ".log", ".ini", ".cfg", ".bat", ".cmd", ".ps1", ".sh", ".html", ".htm",
    ".css", ".xml", ".md", ".mp3", ".wav", ".flac", ".m4a", ".aac", ".ogg", ".psd",
    ".ttf", ".otf", ".ico", ".svg", ".db", ".sqlite", ".iso", ".img",
}


def log(msg: str) -> None:
    print(msg, flush=True)


def human(n: float) -> str:
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f}{u}"
        n /= 1024
    return f"{n:.0f}PB"


def read_passwords(inbox: str) -> list[str]:
    """读取可用密码（与图形界面共用 app.passwords 的实现）。"""
    from app.passwords import PasswordStore
    store = PasswordStore(os.path.join(inbox, PASSWORD_FILE), inbox)
    return store.get()


def parse_part(name: str):
    """解析文件名 -> (base, volume_no)。

    volume_no 为 None 表示名字里没有卷号（可能是首卷，也可能是单文件包）。
      '218.花柒Hana.7z.7z.001.pdf' -> ('218.花柒Hana.7z.7z', 1)
      '26.7z.001删'                -> ('26.7z', 1)
      'rizunya.7z.002'             -> ('rizunya.7z', 2)
      '26.7z'                      -> ('26.7z', None)
      'video.mp4'                  -> (None, None)
    """
    m = _PART_RE.match(name)
    if not m:
        return None, None
    base = m.group("base")
    vol = m.group("vol")
    return base, (int(vol[1:]) if vol else None)


def _digest(path: str, chunk: int = 8 << 20) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def _dedup(paths: list[str]) -> tuple[list[str], list[tuple[str, str]]]:
    """按内容去重，返回 (保留的路径, [(被丢弃的, 保留的)])。"""
    keep: list[str] = []
    dups: list[tuple[str, str]] = []
    seen: dict[tuple[int, str], str] = {}
    for p in paths:
        try:
            sz = os.path.getsize(p)
            dg = _digest(p)
        except OSError:
            continue
        key = (sz, dg)
        if key in seen:
            dups.append((p, seen[key]))
        else:
            seen[key] = p
            keep.append(p)
    return keep, dups


def _link_into(dirpath: str, src: str, canonical: str) -> str:
    """在 dirpath 下建一个名为 canonical 的入口指向 src。

    优先硬链接（同盘瞬时完成、不占空间），失败则退回复制。
    """
    dst = os.path.join(dirpath, canonical)
    if os.path.exists(dst):
        try:
            if os.path.samefile(dst, src):
                return dst
        except OSError:
            pass
        try:
            os.chmod(dst, 0o666)
            os.remove(dst)
        except OSError:
            pass
    try:
        os.link(src, dst)
    except OSError:
        shutil.copy2(src, dst)
    return dst


def collect(inbox: str):
    """扫描收件箱，返回 [(标签, 待打开路径, 源文件列表)]。

    分卷会跨文件夹归组，并在暂存区建一套规范命名的入口，这样即使
    首卷丢了卷号、卷号后面带杂字、各卷分散在不同目录，7-Zip 也能解。
    """
    parts: dict[str, dict] = {}      # base -> {vol_or_None: [paths]}
    disguised: list[str] = []        # 伪装成媒体文件的包
    sniffed: list[tuple[str, str]] = []   # (源路径, 补齐后的名字)

    for root, dirs, files in os.walk(inbox):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in sorted(files):
            if name.endswith(".qkdownloading"):
                continue
            p = os.path.join(root, name)
            base, vol = parse_part(name)
            if base is None:
                ext = os.path.splitext(name)[1].lower()
                # 名字不像压缩包：可能是尾部反转 / 追加型伪装
                if ext in _MEDIA_EXT:
                    try:
                        if detect(p).kind in ("tail_reversed", "appended"):
                            disguised.append(p)
                            continue
                    except Exception:
                        pass
                # 扩展名不认识（含完全没有扩展名）：按文件头猜
                # 例：课件196 == gzip，617 == 7z
                if ext not in _KNOWN_EXT:
                    kind = sniff_container(p)
                    if kind:
                        sniffed.append((p, name + CONTAINER_EXT[kind]))
                continue
            parts.setdefault(base, {}).setdefault(vol, []).append(p)

    items: list[tuple[str, str, list[str]]] = []
    links_dir = os.path.join(STAGING, "_parts")

    # 无扩展名 / 未知扩展名的包：建一个带正确后缀的入口再解
    if sniffed:
        os.makedirs(links_dir, exist_ok=True)
    for src, target_name in sniffed:
        if target_name.lower().endswith(".7z") and is_incomplete_7z(src):
            # 缺后续分卷的 7z 首卷，补成 .001 让 7-Zip 按分卷去找
            target_name += ".001"
        try:
            entry = _link_into(links_dir, src, target_name)
        except Exception as exc:
            log(f"  !! {os.path.basename(src)} 建立入口失败: {exc}")
            continue
        items.append((f"{os.path.relpath(src, inbox)}（按文件头识别为 {os.path.splitext(target_name)[1].lstrip('.')}）",
                      entry, [src]))

    for base, volmap in sorted(parts.items()):
        numbered = sorted(v for v in volmap if v)
        all_paths = [p for lst in volmap.values() for p in lst]

        # 没有第二卷及以上 -> 当成独立包逐个处理
        if not any(v >= 2 for v in numbered):
            keep, dups = _dedup(all_paths)
            if dups:
                log(f"  (跳过 {len(dups)} 个重复副本)")
            for p in keep:
                items.append((os.path.relpath(p, inbox), p, [p]))
            continue

        # 分卷：确定每一卷用哪个文件
        maxv = max(numbered)
        chosen: dict[int, str] = {}
        # 第一卷：优先带 .001 的，没有就用无卷号的那个
        first_pool = volmap.get(1) or volmap.get(None) or []
        if first_pool:
            keep, _ = _dedup(first_pool)
            if keep:
                chosen[1] = keep[0]
        for v in numbered:
            if v < 2:
                continue
            keep, _ = _dedup(volmap[v])
            if keep:
                chosen[v] = keep[0]

        missing = [v for v in range(1, maxv + 1) if v not in chosen]
        if missing:
            log(f"  !! {base} 缺少分卷 {missing}，跳过")
            continue

        os.makedirs(links_dir, exist_ok=True)
        try:
            entries = [_link_into(links_dir, chosen[v], f"{base}.{v:03d}")
                       for v in sorted(chosen)]
        except Exception as exc:
            log(f"  !! {base} 建立分卷入口失败: {exc}")
            continue
        items.append((f"{base}（{len(chosen)} 卷）", entries[0], all_paths))

    # 伪装成媒体文件的包
    for fp in disguised:
        items.append((os.path.relpath(fp, inbox), fp, [fp]))

    return _drop_duplicates(items)


def _drop_duplicates(items: list) -> list:
    """同一内容的多个副本只保留一个（浏览器重复下载会产生 "xxx(1)"）。"""
    by_size: dict[int, list] = {}
    for it in items:
        try:
            sz = os.path.getsize(it[1])
        except OSError:
            continue
        by_size.setdefault(sz, []).append(it)

    keep: list = []
    dups: list = []
    for sz, group in by_size.items():
        if len(group) == 1:
            keep.extend(group)
            continue
        seen: dict[str, str] = {}
        for it in group:
            try:
                dg = _digest(it[1])
            except OSError:
                keep.append(it)
                continue
            if dg in seen:
                dups.append((it[0], seen[dg]))
            else:
                seen[dg] = it[0]
                keep.append(it)

    if dups:
        log(f"发现 {len(dups)} 个重复副本，已跳过：")
        for dup, orig in dups:
            log(f"   {dup}  ==  {orig}")
    return keep


def _sig(path: str) -> str:
    """源文件的"指纹"：大小 + 修改时间。重新下载会改变它。"""
    st = os.stat(path)
    return f"{st.st_size}:{int(st.st_mtime)}"


def filter_done(items: list, redo: bool = False, done: dict | None = None):
    """滤掉已经解压归档过的包，返回 (待处理, 已跳过, 记录表)。

    重新下载同一个包会刷新修改时间，那时会照常再处理一遍。
    """
    if done is None:
        done = {} if redo else _load_done()
    keep, skipped = [], []
    for it in items:
        srcs = [s for s in dict.fromkeys(it[2]) if os.path.exists(s)]
        if srcs and all(done.get(s) == _sig(s) for s in srcs):
            skipped.append(it)
        else:
            keep.append(it)
    return keep, skipped, done


def mark_done(done: dict, sources) -> None:
    """记下这些源文件已经处理成功（只在归档成功后才该调用）。"""
    for s in dict.fromkeys(sources):
        try:
            done[s] = _sig(s)
        except OSError:
            pass


def _load_done() -> dict:
    try:
        with open(DONE_FILE, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_done(done: dict) -> None:
    try:
        tmp = DONE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(done, f, ensure_ascii=False, indent=1)
        os.replace(tmp, DONE_FILE)
    except OSError as exc:
        log(f"  (处理记录写入失败: {exc})")


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    delete_source = "--delete-source" in sys.argv
    ignore_done = "--redo" in sys.argv
    inbox = args[0] if len(args) > 0 else DEFAULT_INBOX
    dest = args[1] if len(args) > 1 else DEFAULT_DEST

    passwords = read_passwords(inbox)
    if not passwords:
        log(f"! 未找到密码文件: {os.path.join(inbox, PASSWORD_FILE)}")

    staging_dir = os.path.join(STAGING, "_inbox")
    os.makedirs(staging_dir, exist_ok=True)

    items = collect(inbox)
    log(f"收件箱 {inbox}：待处理 {len(items)} 个，可用密码 {len(passwords)} 个"
        + (f"（{'、'.join(passwords)}）" if passwords else ""))
    if not items:
        log("没有需要处理的压缩包。")
        return 0

    done = {} if ignore_done else _load_done()
    items, skipped, done = filter_done(items, ignore_done, done)
    if skipped:
        log(f"已有 {len(skipped)} 个包解压归档过，自动跳过（--redo 可强制重来）：")
        for it in skipped[:8]:
            log(f"   {it[0]}")
        if len(skipped) > 8:
            log(f"   ... 另外 {len(skipped) - 8} 个")
    if not items:
        log("没有新的需要处理的压缩包。")
        return 0

    pipe = Pipeline(SevenZip(), salvage=True)
    ok_n = fail_n = 0
    all_works: list[dict] = []
    t_all = time.time()

    for i, (label, open_path, sources) in enumerate(items, 1):
        t0 = time.time()
        outdir = os.path.join(staging_dir, "out")
        workdir = os.path.join(staging_dir, "work")
        shutil.rmtree(outdir, ignore_errors=True)
        shutil.rmtree(workdir, ignore_errors=True)

        log(f"=== [{i}/{len(items)}] {label} ===")
        res = pipe.process(open_path, workdir, outdir, passwords, recurse=True,
                           log=lambda m: log("   " + m))
        if not res.ok:
            log(f"   !! 失败: {res.error}")
            fail_n += 1
            continue

        # 闸门 1：解压结果必须像样（防止把空壳当成功、进而误删源）
        src_total = sum(os.path.getsize(s) for s in dict.fromkeys(sources)
                        if os.path.exists(s))
        bad = []
        if res.files == 0:
            bad.append("没有解出任何文件")
        if res.bytes_ < 1024 * 1024 and src_total > 10 * 1024 * 1024:
            bad.append(f"解出仅 {res.bytes_} 字节，源包却有 {human(src_total)}")
        if src_total and res.bytes_ < src_total * 0.01:
            bad.append("解出体积不足源包的 1%")
        if bad:
            log("   !! 解压结果可疑，保留源文件不删除:")
            for b in bad:
                log(f"       - {b}")
            fail_n += 1
            continue

        # 闸门 2：归档不能有遗留
        works: list[dict] = []
        try:
            moved, mbytes, errors = pipe.archive_by_type(
                outdir, dest, move=True, works_out=works,
                log=lambda m: log("   " + m))
        except Exception as exc:
            log(f"   !! 归档异常: {exc}")
            fail_n += 1
            continue
        if errors:
            keep_dir = os.path.join(staging_dir, "kept", label.replace(os.sep, "_"))
            os.makedirs(os.path.dirname(keep_dir), exist_ok=True)
            shutil.rmtree(keep_dir, ignore_errors=True)
            try:
                shutil.move(outdir, keep_dir)
                where = keep_dir
            except Exception:
                where = outdir
            log(f"   !! {len(errors)} 个文件未能归档，已保留在 {where}，源包未删除")
            for e in errors[:5]:
                log(f"       {e}")
            fail_n += 1
            continue

        all_works.extend(works)

        mark_done(done, sources)

        if delete_source:
            for s in dict.fromkeys(sources):
                try:
                    os.chmod(s, 0o666)
                except OSError:
                    pass
                try:
                    os.remove(s)
                except OSError:
                    pass

        detail = "，".join(f"{w['kind']} {w['files']}" for w in works[:4])
        log(f"   -> {res.files} 个文件 / {human(res.bytes_)}  "
            f"[{time.time()-t0:.0f}s]  {detail}"
            + ("  源包已删除" if delete_source else ""))
        ok_n += 1

    shutil.rmtree(staging_dir, ignore_errors=True)
    if not ignore_done:
        _save_done(done)
    log(f"完成：成功 {ok_n}，失败 {fail_n}，总用时 {time.time()-t_all:.0f}s")

    if all_works:
        try:
            from app import recent
            recent.record(dest, all_works)
        except Exception:
            pass

    if ok_n:
        try:
            import importlib
            idx = importlib.import_module("建索引")
            log("更新检索清单...")
            idx.main_quiet(dest)
        except Exception as exc:
            log(f"清单生成失败（不影响解压）: {exc}")

    return 0 if fail_n == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
