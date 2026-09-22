#!/usr/bin/env python
"""一键处理：扫描收件箱 -> 解压 -> 分类归档 -> 刷新清单 -> 打开刚解压的。

用法：
    一键.py                 # 用默认目录，处理完自动打开看图
    一键.py --no-open       # 不自动打开
    一键.py --delete-source # 处理成功后删除源压缩包

配合桌面快捷方式，双击即可完成整条流程。
"""

from __future__ import annotations

import os
import shutil
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

from app import recent
from app.passwords import PasswordStore
from app.pipeline import Pipeline
from app.sevenzip import SevenZip

INBOX = r"D:\dowm"
DEST = r"H:\赏花阁"
STAGING = r"D:\_staging"

SKIP_DIRS = {
    "解压助手", "$RECYCLE.BIN", "System Volume Information",
    "《碧蓝航线》本地一键端",
}


def human(n: float) -> str:
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f}{u}"
        n /= 1024
    return f"{n:.1f}PB"


def main() -> int:
    open_when_done = "--no-open" not in sys.argv
    delete_source = "--delete-source" in sys.argv

    inbox = INBOX
    dest = DEST
    for a in sys.argv[1:]:
        if a.startswith("--inbox="):
            inbox = a.split("=", 1)[1]
        elif a.startswith("--dest="):
            dest = a.split("=", 1)[1]

    import 收件箱 as inbox_mod

    store = PasswordStore(os.path.join(inbox, "解压密码.txt"), inbox)
    passwords = store.get

    t_all = time.time()
    print("=" * 60)
    print(f"一键处理  收件箱 {inbox}")
    print(f"          归档到 {dest}")
    print(f"          密码 {len(store.get())} 个：{'、'.join(store.get()) or '（无）'}")
    print("=" * 60)

    items = inbox_mod.collect(inbox)
    if not items:
        print("收件箱里没有待处理的压缩包。")
        if open_when_done:
            print()
            print(recent.open_latest())
        return 0

    print(f"待处理 {len(items)} 个：")
    for label, _p, srcs in items:
        print(f"  · {label}" + (f"（{len(srcs)} 个文件）" if len(srcs) > 1 else ""))
    print()

    staging = os.path.join(STAGING, "_oneclick")
    os.makedirs(staging, exist_ok=True)

    pipe = Pipeline(SevenZip(), salvage=True)
    ok_n = fail_n = 0
    all_works: list[dict] = []
    failed: list[str] = []

    for i, (label, open_path, sources) in enumerate(items, 1):
        t0 = time.time()
        print(f"[{i}/{len(items)}] {label}")
        outdir = os.path.join(staging, "out")
        workdir = os.path.join(staging, "work")
        shutil.rmtree(outdir, ignore_errors=True)
        shutil.rmtree(workdir, ignore_errors=True)

        res = pipe.process(open_path, workdir, outdir, passwords,
                           log=lambda m: print("    " + m), recurse=True)
        if not res.ok:
            print(f"    !! 失败: {res.error}")
            fail_n += 1
            failed.append(label)
            continue

        # 闸门 1：解压结果必须像样
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
            print("    !! 解压结果可疑，保留源文件：")
            for b in bad:
                print(f"        - {b}")
            fail_n += 1
            failed.append(label)
            continue

        works: list[dict] = []
        _m, _b, errors = pipe.archive_by_type(outdir, dest, move=True,
                                             log=lambda m: print("    " + m),
                                             works_out=works)
        if errors:
            print(f"    !! {len(errors)} 个文件未能归档，源文件保留：")
            for e in errors[:5]:
                print("        " + e)
            fail_n += 1
            failed.append(label)
            continue

        all_works.extend(works)

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
        print(f"    -> {res.files} 个文件 / {human(res.bytes_)}  "
              f"[{time.time()-t0:.0f}s]  {detail}"
              + ("   源包已删除" if delete_source else ""))
        ok_n += 1

    shutil.rmtree(staging, ignore_errors=True)

    # 记录这次归档了什么，供"一键查看刚解压的"
    if all_works:
        recent.record(dest, all_works)

    print()
    print(f"完成：成功 {ok_n}，失败 {fail_n}，总用时 {time.time()-t_all:.0f}s")
    if failed:
        print("未成功：" + "、".join(failed))

    # 刷新检索清单
    if ok_n:
        try:
            import 建索引
            print("刷新检索清单...")
            建索引.main_quiet(dest)
        except Exception as exc:
            print(f"清单生成失败（不影响解压）: {exc}")

    print()
    print("=" * 60)
    print(recent.open_latest() if open_when_done else "（本次未自动打开）")
    print("=" * 60)

    # 桌面双击运行时，留个窗口让用户看到结果
    if sys.stdout.isatty() and os.name == "nt":
        try:
            input("\n按回车关闭...")
        except EOFError:
            pass
    return 0 if fail_n == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
