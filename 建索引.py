#!/usr/bin/env python
"""为归档目录生成检索清单，方便快速找到想看的资源。

用法:
    建索引.py                        # 默认扫描 H:\\赏花阁
    建索引.py <归档目录>

产出（放在归档目录下）:
    索引.csv      每个文件一行：类型,作品,文件名,相对路径,大小KB,修改日期
    作品清单.csv  每个作品一行：类型,作品,文件数,总MB,最新日期
                   —— 用 Excel / FastStone 快速定位到某个作品

配合 FastStone Image Viewer 用法：用它的浏览面板找到 <作品> 目录即可；
需要先筛选时，用 Excel 打开 作品清单.csv 按名称/日期排序。
"""

from __future__ import annotations

import os
import sys
import time

DEFAULT_DEST = r"H:\赏花阁"

IMG_EXT = {".jpg", ".jpeg", ".jfif", ".png", ".gif", ".webp", ".bmp",
           ".tif", ".tiff", ".avif", ".heic", ".heif", ".jpe"}
VID_EXT = {".mp4", ".mov", ".mkv", ".avi", ".wmv", ".flv", ".webm", ".m4v",
           ".ts", ".m2ts", ".rmvb", ".mpg", ".mpeg", ".3gp", ".vob", ".rm", ".f4v"}

SKIP_DIRS = {"$RECYCLE.BIN", "System Volume Information"}


def scan(root: str):
    """返回 [(类型, 作品, 文件名, 相对路径, 字节, 修改时间)]。"""
    rows = []
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        rel_dir = os.path.relpath(base, root)
        parts = rel_dir.split(os.sep)
        if parts and parts[0] in ("图片", "视频", "其他"):
            kind = parts[0]
            work = parts[1] if len(parts) > 1 else "_(根目录)"
        elif rel_dir == ".":
            kind, work = "其他", "_(根目录)"
        else:
            kind, work = "其他", parts[0]
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if ext in IMG_EXT:
                t = "图片"
            elif ext in VID_EXT:
                t = "视频"
            else:
                continue
            fp = os.path.join(base, f)
            try:
                st = os.stat(fp)
            except OSError:
                continue
            rows.append((t, work, f, os.path.relpath(fp, root).replace(os.sep, "/"),
                         st.st_size, int(st.st_mtime)))
    return rows


def _csv_cell(s: str) -> str:
    return '"%s"' % s.replace('"', '""')


def write_csv(root: str, rows) -> str:
    out = os.path.join(root, "索引.csv")
    with open(out, "w", encoding="utf-8-sig", newline="") as f:
        f.write("类型,作品,文件名,相对路径,大小KB,修改日期\n")
        for t, work, name, rel, size, mt in rows:
            date = time.strftime("%Y-%m-%d %H:%M", time.localtime(mt))
            f.write(f"{t},{_csv_cell(work)},{_csv_cell(name)},{_csv_cell(rel)},"
                    f"{size // 1024},{date}\n")
    return out


def write_works(root: str, rows) -> str:
    """作品级汇总：一行一个作品，便于速览和排序。"""
    agg: dict[tuple[str, str], list] = {}
    for t, work, _name, _rel, size, mt in rows:
        e = agg.setdefault((t, work), [0, 0, 0])
        e[0] += 1
        e[1] += size
        e[2] = max(e[2], mt)
    out = os.path.join(root, "作品清单.csv")
    with open(out, "w", encoding="utf-8-sig", newline="") as f:
        f.write("类型,作品,文件数,总MB,最新日期\n")
        for (t, work), (cnt, tot, mt) in sorted(
                agg.items(), key=lambda kv: (-kv[1][1], kv[0][1])):
            date = time.strftime("%Y-%m-%d", time.localtime(mt))
            f.write(f"{t},{_csv_cell(work)},{cnt},{tot // 1048576},{date}\n")
    return out


def _summary(root: str, rows) -> tuple[int, int]:
    img = sum(1 for r in rows if r[0] == "图片")
    vid = sum(1 for r in rows if r[0] == "视频")
    return img, vid


def main_quiet(root: str = DEFAULT_DEST) -> None:
    """供其它脚本调用：重建清单，只输出一行摘要。"""
    if not os.path.isdir(root):
        return
    t0 = time.time()
    rows = scan(root)
    write_csv(root, rows)
    write_works(root, rows)
    img, vid = _summary(root, rows)
    print(f"  清单已更新: 图片 {img}, 视频 {vid}, 共 {len(rows)} 项 ({time.time()-t0:.0f}s)",
          flush=True)


def main() -> int:
    root = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_DEST
    if not os.path.isdir(root):
        print("目录不存在:", root)
        return 1
    t0 = time.time()
    rows = scan(root)
    img, vid = _summary(root, rows)
    print(f"扫描完成: 图片 {img}, 视频 {vid}, 共 {len(rows)} 项 ({time.time()-t0:.1f}s)")
    print(" ", write_csv(root, rows))
    print(" ", write_works(root, rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
