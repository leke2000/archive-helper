#!/usr/bin/env python
"""收件箱模式：扫描目录，自动识别伪装/分卷/加密压缩包，解压并分类归档。

用法（在 解压助手 目录下）:
    收件箱.py                      # 默认 D:\\dowm -> H:\\赏花阁
    收件箱.py <收件目录> <归档目录>

密码从 <收件目录>\\解压密码.txt 读取，每行一个，可写多个。

处理能力：
  * 普通压缩包 / 分卷 (.7z.001, .zip.001, .rar.001 ...)
  * 伪装扩展名 (xxx.7z.001.pdf, xxx.zip.mp4 ...)
  * 尾部反转伪装 (Apate 类，见 disguise.py)
  * 下载中的 .qkdownloading 文件自动跳过
  * 解压后按 图片/视频 分类归档，并删除源压缩包
"""

from __future__ import annotations

import os
import re
import shutil
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

from app.disguise import detect
from app.pipeline import Pipeline
from app.sevenzip import SevenZip

DEFAULT_INBOX = r"D:\dowm"
DEFAULT_DEST = r"H:\赏花阁"
PASSWORD_FILE = "解压密码.txt"
STAGING = r"D:\_staging"

# 这些目录不是收件箱（工具自身、已解压好的游戏），递归时跳过
SKIP_DIRS = {
    "解压助手",
    "$RECYCLE.BIN",
    "System Volume Information",
    "《碧蓝航线》本地一键端",
}

_VOL_TAIL = re.compile(r"\.(7z|zip|rar)\.(\d{3})$", re.IGNORECASE)
_SOLID_TAIL = re.compile(r"\.(7z|zip|rar)$", re.IGNORECASE)
_PW_RE = re.compile(r"密码\s*[:：]?\s*([^\s,，、;；|]+)")


def log(msg: str) -> None:
    print(msg, flush=True)


def _read_text(path: str) -> str | None:
    for enc in ("utf-8-sig", "utf-8", "gbk", "utf-16"):
        try:
            with open(path, encoding=enc) as f:
                return f.read()
        except (UnicodeDecodeError, UnicodeError):
            continue
    return None


def read_passwords(inbox: str) -> list[str]:
    """密码来源：
      1) 解压密码.txt —— 每行一个（本工具维护的清单）
      2) 收件箱里任何 .txt 中出现 '密码:xxx' 的自动提取
    这样下载自带的说明文件也能直接用，无需手工登记。
    """
    pws: list[str] = []

    def add(s: str) -> None:
        s = s.strip().strip('"\'')
        if s and s not in pws:
            pws.append(s)

    p = os.path.join(inbox, PASSWORD_FILE)
    if os.path.isfile(p):
        text = _read_text(p)
        if text:
            for line in text.splitlines():
                s = line.strip()
                if s and "密码" not in s:
                    add(s)

    for name in sorted(os.listdir(inbox)):
        if not name.lower().endswith(".txt") or name == PASSWORD_FILE:
            continue
        text = _read_text(os.path.join(inbox, name))
        if not text or "密码" not in text:
            continue
        for m in _PW_RE.finditer(text):
            add(m.group(1))

    # 子目录名里也可能写着密码，例如 "解压密码：xiaohutao"
    for root, dirs, _files in os.walk(inbox):
        for d in dirs:
            if "密码" in d:
                for m in _PW_RE.finditer(d):
                    add(m.group(1))
    return pws


def normalize(name: str):
    """剥掉尾部伪装扩展名，找出真正的分卷名。

    返回 (real_name, volume_no, is_archive)：
      '218.花柒Hana.7z.7z.001.pdf' -> ('218.花柒Hana.7z.7z.001', 1, True)
      'rizunya.7z.001'             -> ('rizunya.7z.001', 1, True)
      '#2026年7月10日.zip.mp4'      -> ('#2026年7月10日.zip', 0, True)
      'video.mp4'                  -> ('video.mp4', 0, False)
    """
    parts = name.split(".")
    for cut in range(len(parts), 0, -1):
        cand = ".".join(parts[:cut])
        m = _VOL_TAIL.search(cand)
        if m and m.end() == len(cand):
            return cand, int(m.group(2)), True
        m2 = _SOLID_TAIL.search(cand)
        if m2 and m2.end() == len(cand):
            return cand, 0, True
    return name, 0, False


def base_of(real: str) -> str:
    m = _VOL_TAIL.search(real)
    return real[: m.start()] if m else real


def human(n: float) -> str:
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f}{u}"
        n /= 1024
    return f"{n:.0f}PB"


def collect(inbox: str):
    """递归扫描收件箱，返回 [(标签, 待打开路径, 源文件列表)]。"""
    entries = []
    disguised = []          # 伪装包：文件名像媒体，实际是压缩包
    for root, dirs, files in os.walk(inbox):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in sorted(files):
            low = name.lower()
            if low.endswith(".qkdownloading"):
                continue
            fp = os.path.join(root, name)
            real, no, is_arc = normalize(name)
            if is_arc:
                entries.append((root, name, fp, real, no))
                continue
            # 名字不像压缩包，但可能尾部反转伪装成媒体文件
            ext = os.path.splitext(name)[1].lower()
            if ext in (".mp4", ".mov", ".mkv", ".ts", ".jpg", ".jpeg", ".png", ".pdf"):
                try:
                    if detect(fp).kind in ("tail_reversed", "appended"):
                        disguised.append(fp)
                except Exception:
                    pass

    groups: dict[tuple, list] = {}
    for e in entries:
        groups.setdefault((e[0], base_of(e[3])), []).append(e)

    items = []
    for (root, base), members in groups.items():
        primary = next((m for m in members if m[4] == 1), None)
        if primary is None:
            primary = next((m for m in members if m[4] == 0), None)
        if primary is None:
            continue

        _, name, path, real, _no = primary
        sources = [m[2] for m in members]
        links = []
        if real != name:
            # 分卷必须用 7-Zip 认得的名字才能找到后续卷：建硬链接
            for (_r, n2, p2, r2, _v) in members:
                if r2 == n2:
                    continue
                lk = os.path.join(root, r2)
                if os.path.exists(lk):
                    continue
                try:
                    os.link(p2, lk)
                except OSError:
                    shutil.copy2(p2, lk)
                links.append(lk)
            open_path = os.path.join(root, real)
        else:
            open_path = path
        items.append((os.path.relpath(open_path, inbox), open_path, sources + links))

    # 伪装成媒体文件的包（如 xxx.mp4 实为尾部反转 zip）
    for fp in disguised:
        items.append((os.path.relpath(fp, inbox), fp, [fp]))
    return items


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    delete_source = "--delete-source" in sys.argv
    inbox = args[0] if len(args) > 0 else DEFAULT_INBOX
    dest = args[1] if len(args) > 1 else DEFAULT_DEST

    passwords = read_passwords(inbox)
    if not passwords:
        log(f"! 未找到密码文件: {os.path.join(inbox, PASSWORD_FILE)}")

    staging_dir = os.path.join(STAGING, "_inbox")
    os.makedirs(staging_dir, exist_ok=True)

    items = collect(inbox)
    log(f"收件箱 {inbox}：待处理 {len(items)} 个，可用密码 {len(passwords)} 个")
    if not items:
        log("没有需要处理的压缩包。")
        return 0

    pipe = Pipeline(SevenZip(), salvage=True)
    ok_n = fail_n = 0
    t_all = time.time()

    for i, (label, open_path, sources) in enumerate(items, 1):
        t0 = time.time()
        outdir = os.path.join(staging_dir, "out")
        workdir = os.path.join(staging_dir, "work")
        shutil.rmtree(outdir, ignore_errors=True)
        shutil.rmtree(workdir, ignore_errors=True)

        res = pipe.process(open_path, workdir, outdir, passwords, recurse=True)
        if not res.ok:
            log(f"[{i}/{len(items)}] {label}  !! 失败: {res.error}")
            fail_n += 1
            continue

        # 安全闸门 1：解压结果必须"像样"。全是 0 字节或体积远小于源包，
        # 说明解压不完整或是空壳包，此时绝不能删源文件。
        files_in_out = res.files
        bytes_in_out = res.bytes_
        src_total = sum(os.path.getsize(s) for s in dict.fromkeys(sources) if os.path.exists(s))
        suspicious = []
        if files_in_out == 0:
            suspicious.append("没有解出任何文件")
        if bytes_in_out < 1024 * 1024 and src_total > 10 * 1024 * 1024:
            suspicious.append(f"解出内容仅 {bytes_in_out} 字节，源包却有 {human(src_total)}")
        if src_total and bytes_in_out < src_total * 0.01:
            suspicious.append(f"解出体积不足源包的 1%")

        # 安全闸门 2：归档不能有遗留
        if suspicious:
            log(f"[{i}/{len(items)}] {label}  !! 解压结果可疑，保留源文件不删除:")
            for s in suspicious:
                log(f"       - {s}")
            fail_n += 1
            continue

        try:
            moved, mbytes, errors = pipe.archive_by_type(outdir, dest, move=True)
        except Exception as exc:
            log(f"[{i}/{len(items)}] {label}  !! 归档异常: {exc}")
            fail_n += 1
            continue

        if errors:
            keep_dir = os.path.join(staging_dir, "kept", os.path.basename(label))
            os.makedirs(os.path.dirname(keep_dir), exist_ok=True)
            if os.path.isdir(keep_dir):
                shutil.rmtree(keep_dir, ignore_errors=True)
            try:
                shutil.move(outdir, keep_dir)
                where = keep_dir
            except Exception:
                where = outdir
            log(f"[{i}/{len(items)}] {label}  !! 有 {len(errors)} 个文件未能归档，"
                f"已保留在 {where}，源压缩包未删除")
            for e in errors[:5]:
                log(f"      {e}")
            fail_n += 1
            continue

        # 默认保留源文件；只有显式 --delete-source 且全部检查通过才删除
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
            log(f"[{i}/{len(items)}] {label}  -> {files_in_out} 个文件 / "
                f"{human(bytes_in_out)}  {time.time()-t0:.0f}s  (源包已删除)")
        else:
            log(f"[{i}/{len(items)}] {label}  -> {files_in_out} 个文件 / "
                f"{human(bytes_in_out)}  {time.time()-t0:.0f}s  (源包保留)")
        ok_n += 1

    shutil.rmtree(staging_dir, ignore_errors=True)
    log(f"完成：成功 {ok_n}，失败 {fail_n}，总用时 {time.time()-t_all:.0f}s")

    if ok_n:
        # 刷新画廊索引，方便之后找图
        try:
            import importlib
            idx = importlib.import_module("建索引")
            log("更新画廊索引...")
            idx.main_quiet(dest)
        except Exception as exc:
            log(f"索引生成失败（不影响解压）: {exc}")

    return 0 if fail_n == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
