"""处理记录 + 源包清理。

_done.json 记的是"这个源文件已经成功解压归档过了"（大小 + 修改时间），
两件事都靠它：

  * 跑批时跳过已经处理过的包（收件箱 / 一键 / 界面）
  * "一键删除已解压的源包"只删记录里仍然存在、指纹也没变的文件 ——
    重新下载过的包指纹会变，不会被误删
"""

from __future__ import annotations

import json
import os

from . import trash
from .sevenzip import app_root

DONE_FILE = os.path.join(app_root(), "_done.json")


def sig(path: str) -> str:
    """源文件的"指纹"：大小 + 修改时间。重新下载会改变它。"""
    st = os.stat(path)
    return f"{st.st_size}:{int(st.st_mtime)}"


def load_done(path: str | None = None) -> dict:
    try:
        with open(path or DONE_FILE, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_done(done: dict, path: str | None = None, log=None,
              merge: bool = False) -> None:
    """写回处理记录。

    merge=True 时先重新读盘再合并 —— 图形界面和命令行同时跑的时候，
    各跑各的进程各自持有一份内存副本，直接整体覆盖会把对方刚写入的记录抹掉
    （结果是已经归档过的包又被解一遍）。
    """
    target = path or DONE_FILE
    if merge:
        current = load_done(target)
        current.update(done)
        done = current
    try:
        tmp = target + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(done, f, ensure_ascii=False, indent=1)
        os.replace(tmp, target)
    except OSError as exc:
        if log:
            log(f"  (处理记录写入失败: {exc})")


def filter_done(items: list, redo: bool = False, done: dict | None = None):
    """滤掉已经解压归档过的包，返回 (待处理, 已跳过, 记录表)。"""
    if done is None:
        done = {} if redo else load_done()
    keep, skipped = [], []
    for it in items:
        srcs = [s for s in dict.fromkeys(it[2]) if os.path.exists(s)]
        if srcs and all(done.get(s) == sig(s) for s in srcs):
            skipped.append(it)
        else:
            keep.append(it)
    return keep, skipped, done


def mark_done(done: dict, sources) -> None:
    """记下这些源文件已经处理成功（只在归档成功后才该调用）。"""
    for s in dict.fromkeys(sources):
        try:
            done[s] = sig(s)
        except OSError:
            pass


def prune_empty_dirs(paths, keep_roots: list[str] | None = None) -> list[str]:
    """源包删掉后，把它们空掉的父目录也一起收掉。

    只删"空目录"（os.rmdir 非空会失败，天然安全），并且只在 keep_roots
    范围之内动手 —— 收件箱本身和盘根永远不会被删。
    keep_roots 没给就取这些文件所在目录的最深公共父目录。
    """
    paths = [os.path.abspath(p) for p in paths]
    if not paths:
        return []
    if not keep_roots:
        dirs = {os.path.dirname(p) for p in paths}
        if len(dirs) == 1:
            # 都在同一个包里：允许连这个包目录一起收掉（但绝不动盘根，
            # 也不动直接装着文件的收件箱本身）
            only = next(iter(dirs))
            parent = os.path.dirname(only)
            keep_roots = [parent if os.path.dirname(parent) != parent else only]
        else:
            try:
                keep_roots = [os.path.commonpath(list(dirs))]
            except ValueError:          # 跨盘，各算各的
                keep_roots = sorted(dirs)
    def norm(x: str) -> str:
        # Windows 路径大小写不敏感，短名/长名也可能不一致，统一归一化再比
        return os.path.normcase(os.path.normpath(os.path.abspath(x)))

    keep = [norm(r) for r in keep_roots if r]
    removed: list[str] = []
    for p in paths:
        d = os.path.dirname(os.path.abspath(p))
        while True:
            da = os.path.abspath(d)
            dna = norm(da)
            if os.path.dirname(da) == da:        # 到盘根，停
                break
            if any(dna == k for k in keep):      # 到保留目录，停
                break
            if not any(dna.startswith(k + os.sep) for k in keep):
                break                            # 不在允许范围内，别动
            try:
                os.rmdir(da)                      # 只在空目录时成功
            except OSError:
                break
            removed.append(da)
            d = os.path.dirname(da)
    return removed


def scan_cleanable(done: dict | None = None) -> tuple[list[dict], list[str]]:
    """找出记录里"可以删"的源文件。

    返回 (可删列表, 过期记录)。每项含 path / size / mtime。
    指纹变了的（重新下载过）不算可删，避免误删还没处理的包。
    """
    done = load_done() if done is None else done
    ok: list[dict] = []
    stale: list[str] = []
    for path, recorded in done.items():
        if not os.path.exists(path):
            stale.append(path)
            continue
        try:
            if sig(path) == recorded:
                st = os.stat(path)
                ok.append({"path": path, "size": st.st_size})
        except OSError:
            stale.append(path)
    ok.sort(key=lambda d: d["path"])
    return ok, stale


def clean_sources(
    done: dict | None = None,
    to_trash: bool = True,
    dry_run: bool = False,
    log=None,
    keep_roots: list[str] | None = None,
) -> dict:
    """删除已经成功归档的源包，并从记录里移除。

    返回 {count, bytes, errors, paths, stale}。
    """
    say = log or (lambda m: None)
    done = load_done() if done is None else done
    items, stale = scan_cleanable(done)
    total = sum(it["size"] for it in items)

    for p in stale:
        done.pop(p, None)

    if dry_run:
        for it in items:
            say(f"   {it['size']/1048576:9.1f}MB  {it['path']}")
        return {"count": len(items), "bytes": total, "errors": [],
                "paths": [it["path"] for it in items], "stale": stale,
                "dry_run": True}

    paths = [it["path"] for it in items]
    ok, bad = trash.delete(paths, to_trash=to_trash)
    for p in ok:
        done.pop(p, None)
    pruned = prune_empty_dirs(ok, keep_roots)
    for d in pruned:
        say(f"   顺手收掉空目录: {d}")
    if not dry_run and done is not None:
        save_done(done, log=say)

    return {"count": len(ok), "bytes": sum(
        it["size"] for it in items if it["path"] in set(ok)),
        "errors": bad, "paths": ok, "stale": stale, "dry_run": False,
        "pruned": pruned}
