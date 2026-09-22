"""Batch / command-line driver for the extractor.

Adds an "auto" mode that chains the whole workflow for many files at once:

    source archive -> restore -> test -> extract to staging
                   -> archive media to destination
                   -> delete source + staging

Peak disk use stays near one archive, so a large queue fits on a small disk.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys

from .pipeline import Pipeline
from .sevenzip import SevenZip


def _fmt(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}PB"


def _stem(name: str) -> str:
    """Strip media + archive extensions: 'a.7z.mp4' -> 'a'."""
    base = name
    for ext in (".mp4", ".mov", ".mkv", ".avi", ".webm", ".jpg", ".jpeg", ".png",
                ".7z", ".zip", ".rar", ".001"):
        if base.lower().endswith(ext):
            base = base[: -len(ext)]
            break
    for ext in (".7z", ".zip", ".rar"):
        if base.lower().endswith(ext):
            base = base[: -len(ext)]
            break
    return base


def collect_sources(src_dir: str, only: list[str] | None = None,
                    recursive: bool = True, already: set[str] | None = None):
    """Gather candidate files.

    Returns a list of (path, rel_key) where rel_key uniquely identifies the
    file relative to src_dir (used for the processed-marker).

    A file is considered processed if either its relative path or its bare
    file name appears in *already*, so switching between recursive and
    non-recursive scanning still de-duplicates correctly.
    """
    already = already or set()

    def seen(rel: str, name: str) -> bool:
        return rel in already or name in already

    out = []
    if recursive:
        for r, _dirs, fs in os.walk(src_dir):
            for n in fs:
                p = os.path.join(r, n)
                rel = os.path.relpath(p, src_dir)
                if n.endswith(".qkdownloading"):
                    continue
                if only and n not in only and rel not in only:
                    continue
                if seen(rel, n):
                    continue
                out.append((p, rel))
    else:
        for n in sorted(os.listdir(src_dir)):
            p = os.path.join(src_dir, n)
            if not os.path.isfile(p):
                continue
            if n.endswith(".qkdownloading"):
                continue
            if only and n not in only:
                continue
            if seen(n, n):
                continue
            out.append((p, n))
    out.sort(key=lambda t: os.path.getsize(t[0]))
    return out


def _is_archive_candidate(path: str) -> bool:
    """Cheap pre-filter: skip obvious non-archives (docs, installers)."""
    ext = os.path.splitext(path)[1].lower()
    if ext in (".mp4", ".mov", ".mkv", ".avi", ".webm", ".jpg", ".jpeg",
               ".png", ".gif", ".webp", ".7z", ".zip", ".rar", ".001"):
        return True
    return False


def run_auto(
    src_dir: str,
    staging: str,
    dest: str,
    passwords,
    move: bool = True,
    keep_source: bool = False,
    only: list[str] | None = None,
    skip_ok_marker: bool = True,
    recursive: bool = True,
) -> int:
    """Process every complete file under src_dir. Returns count of failures."""
    pipe = Pipeline(SevenZip())
    done_file = os.path.join(staging, "_processed.txt")
    already: set[str] = set()
    if skip_ok_marker and os.path.isfile(done_file):
        with open(done_file, encoding="utf-8", errors="replace") as f:
            already = {ln.strip() for ln in f if ln.strip()}

    files = collect_sources(src_dir, only, recursive, already)
    files = [(p, k) for p, k in files if _is_archive_candidate(p)]

    os.makedirs(staging, exist_ok=True)
    os.makedirs(dest, exist_ok=True)

    print(f"待处理 {len(files)} 个文件（递归={recursive}）")
    failures = 0
    for i, (src, key) in enumerate(files, 1):
        name = os.path.basename(src)
        try:
            size = os.path.getsize(src)
        except OSError:
            continue
        stem = _stem(name)

        print(f"\n=== [{i}/{len(files)}] {key}  ({_fmt(size)}) ===")
        sys.stdout.flush()

        outdir = os.path.join(staging, stem)
        workdir = os.path.join(staging, "_work")

        # 单个文件失败不应中断整批（磁盘掉线、坏包等）
        try:
            res = pipe.process(
                src, workdir, outdir, passwords,
                log=lambda m: print("   " + m),
                recurse=True,
            )
            if not res.ok:
                print(f"   !! 跳过: {res.error}")
                failures += 1
                shutil.rmtree(outdir, ignore_errors=True)
                continue

            # archive the extracted media, then drop the staging copy
            moved, mbytes, errors = pipe.archive_by_type(
                outdir, dest, log=lambda m: print("   " + m), move=True,
            )

            if errors:
                # 安全闸门：有文件没能归档时，保留暂存内容和源包，绝不丢数据
                print(f"   !! 有 {len(errors)} 个问题，保留 {outdir}，源文件未删除")
                for e in errors[:5]:
                    print("      " + e)
                failures += 1
                continue

            shutil.rmtree(outdir, ignore_errors=True)
            shutil.rmtree(workdir, ignore_errors=True)

            if not keep_source:
                try:
                    os.chmod(src, 0o666)
                except OSError:
                    pass
                try:
                    os.remove(src)
                    print("   已删除源文件")
                except OSError as e:
                    print(f"   源文件删除失败: {e}")
        except Exception as exc:
            print(f"   !! 异常，跳过该文件: {type(exc).__name__}: {exc}")
            failures += 1
            shutil.rmtree(outdir, ignore_errors=True)
            continue

        with open(done_file, "a", encoding="utf-8") as f:
            f.write(key + "\n")
            if key != name:
                f.write(name + "\n")

    print(f"\n完成。成功 {len(files) - failures} 个，失败 {failures} 个。")
    return failures


def main(argv=None):
    ap = argparse.ArgumentParser(description="通用解压归档助手 - 批量模式")
    ap.add_argument("src", help="源目录（含伪装压缩包）")
    ap.add_argument("--staging", default=r"D:\_staging", help="暂存目录")
    ap.add_argument("--dest", default=r"H:\赏花阁", help="归档目标目录")
    ap.add_argument("-p", "--password", action="append", default=[],
                    help="密码，可多次指定")
    ap.add_argument("--keep-source", action="store_true", help="保留源压缩包")
    ap.add_argument("--only", nargs="*", help="只处理指定文件名")
    ap.add_argument("--no-recursive", action="store_true",
                    help="只处理顶层文件，不进入子目录")
    ap.add_argument("--gui", action="store_true", help="启动图形界面")
    args = ap.parse_args(argv)

    if args.gui:
        from .gui import main as gui_main
        gui_main()
        return 0

    return run_auto(
        args.src, args.staging, args.dest, args.password,
        keep_source=args.keep_source, only=args.only,
        recursive=not args.no_recursive,
    )


if __name__ == "__main__":
    sys.exit(main())
