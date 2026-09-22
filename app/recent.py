"""记录最近一次解压归档的结果，供"一键查看刚解压的"使用。

状态文件放在程序目录下，内容形如：
    {
      "time": 1699999999,
      "dest": "H:\\赏花阁",
      "items": [
        {"kind": "图片", "name": "205.秋楚楚",
         "path": "H:\\赏花阁\\图片\\205.秋楚楚", "files": 785, "bytes": 9912}
      ]
    }
"""

from __future__ import annotations

import json
import os
import time

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE_FILE = os.path.join(_HERE, "_recent.json")

# 常见的图片查看器（用于"一键看图"）
VIEWER_CANDIDATES = (
    r"D:\Software\FSViewer85\FSViewer.exe",
    r"C:\Program Files\FastStone Image Viewer\FSViewer.exe",
    r"C:\Program Files (x86)\FastStone Image Viewer\FSViewer.exe",
    r"C:\Program Files\Honeyview\Honeyview.exe",
)


def find_viewer() -> str | None:
    for p in VIEWER_CANDIDATES:
        if os.path.isfile(p):
            return p
    for name in ("FSViewer", "Honeyview", "XnView"):
        for root in (r"C:\Program Files", r"C:\Program Files (x86)", r"D:\Software"):
            if not os.path.isdir(root):
                continue
            for d in os.listdir(root):
                if name.lower() in d.lower():
                    exe = os.path.join(root, d, name + ".exe")
                    if os.path.isfile(exe):
                        return exe
    return None


def record(dest: str, works: list[dict]) -> None:
    """写入最近一次解压的结果。works 由 archive 阶段收集。"""
    if not works:
        return
    data = {
        "time": time.time(),
        "when": time.strftime("%Y-%m-%d %H:%M:%S"),
        "dest": dest,
        "items": works,
    }
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except OSError:
        pass


def latest() -> dict | None:
    """读取最近一次结果。"""
    if not os.path.isfile(STATE_FILE):
        return None
    try:
        with open(STATE_FILE, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    items = [it for it in data.get("items", []) if os.path.isdir(it.get("path", ""))]
    if not items:
        return None
    data["items"] = items
    return data


def open_latest(prefer_viewer: bool = True) -> str:
    """打开最近解压的内容。

    返回一句给用户看的说明。图片目录优先用看图软件打开，
    保证"一键就能看到刚解压的"。
    """
    data = latest()
    if not data:
        return "还没有解压记录。先跑一次「一键处理」吧。"

    items = data["items"]
    images = [it for it in items if it.get("kind") == "图片"]
    videos = [it for it in items if it.get("kind") == "视频"]
    others = [it for it in items if it.get("kind") not in ("图片", "视频")]

    opened = []
    viewer = find_viewer() if prefer_viewer else None

    # 图片：优先用看图软件直接定位到该目录
    for it in images[:3]:
        p = it["path"]
        done = False
        if viewer:
            try:
                import subprocess
                subprocess.Popen([viewer, p])
                opened.append(("图片", it["name"], os.path.basename(viewer)))
                done = True
            except Exception:
                done = False
        if not done:
            try:
                os.startfile(p)
                opened.append(("图片", it["name"], "资源管理器"))
            except Exception:
                pass

    # 视频：用系统默认播放器/资源管理器
    for it in videos[:2]:
        try:
            os.startfile(it["path"])
            opened.append(("视频", it["name"], "默认程序"))
        except Exception:
            pass

    # 其他：资源管理器
    for it in others[:1]:
        try:
            os.startfile(it["path"])
            opened.append(("其他", it["name"], "资源管理器"))
        except Exception:
            pass

    if not opened:
        return "记录里的目录都不在了。"

    lines = [f"刚解压的内容（{data.get('when','')}）："]
    for kind, name, how in opened:
        lines.append(f"  [{kind}] {name}  →  {how}")
    return "\n".join(lines)
