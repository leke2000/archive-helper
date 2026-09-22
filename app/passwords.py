"""密码集合，支持热加载。

三个来源，合并去重：
  1) 一个专门的密码文件（每行一个），会被监视变化自动重载
  2) 收件目录里任何 .txt 中出现 "密码:xxx" 的内容（自动提取）
  3) 运行时在界面上手动添加的（会写回密码文件）

界面在跑批处理的过程中，只要文件被改动或手动添加，新密码立刻对
后续的压缩包生效，不需要重启程序。
"""

from __future__ import annotations

import os
import re
import threading
import time

DEFAULT_PASSWORD_FILE = r"D:\dowm\解压密码.txt"

# 收件目录里出现 "密码:xxx" / "密码：xxx" 时提取
_PW_INLINE = re.compile(r"密码\s*[:：]\s*([^\s,，、;；|]+)")


def _plausible_password(s: str) -> bool:
    """过滤掉误匹配：URL、路径、说明性长句都不是密码。"""
    s = (s or "").strip().strip("\"'")
    if not s or len(s) > 64:
        return False
    if "://" in s or s.lower().startswith(("http", "www.")):
        return False
    if any(ch in s for ch in ("\\", "/", "（", "）", "(", ")")):
        return False
    if s.endswith((".txt", ".png", ".jpg", ".mp4", ".exe", ".url")):
        return False
    if "密码" in s:
        return False
    return True


def _read_text(path: str) -> str | None:
    for enc in ("utf-8-sig", "utf-8", "gbk", "utf-16"):
        try:
            with open(path, encoding=enc) as f:
                return f.read()
        except (UnicodeDecodeError, UnicodeError, OSError):
            continue
    return None


class PasswordStore:
    """线程安全的密码集合。"""

    def __init__(self, path: str = DEFAULT_PASSWORD_FILE, scan_dir: str | None = None):
        self.path = path
        self.scan_dir = scan_dir
        self._lock = threading.Lock()
        self._pws: list[str] = []
        # 只记录"手动维护"的密码，写回文件时用这个，避免把自动扫描到的
        # 说明文字/URL 固化进密码清单。
        self._manual: list[str] = []
        self._mtime = 0.0
        self._found_files: list[str] = []
        self.last_load = 0.0
        self.reload(force=True)

    # -- 读取 -------------------------------------------------------------
    def _read_file(self) -> list[str]:
        out: list[str] = []
        text = _read_text(self.path) if os.path.isfile(self.path) else None
        if text:
            for line in text.splitlines():
                s = line.strip().strip("\"'")
                if _plausible_password(s) and s not in out:
                    out.append(s)
        return out

    def _scan_txt(self) -> list[str]:
        """从收件目录的说明 txt / 目录名里提取 '密码:xxx'。"""
        out: list[str] = []
        d = self.scan_dir
        if not d or not os.path.isdir(d):
            return out

        def add(v: str):
            v = v.strip().strip("\"'")
            if _plausible_password(v) and v not in out:
                out.append(v)

        for root, dirs, files in os.walk(d):
            dirs[:] = [x for x in dirs if x not in ("解压助手", "$RECYCLE.BIN",
                                                    "System Volume Information")]
            # 目录名里可能写着密码，例如 "解压密码：abc"
            for dn in dirs:
                if "密码" in dn:
                    for m in _PW_INLINE.finditer(dn):
                        add(m.group(1))
            for name in files:
                if not name.lower().endswith(".txt"):
                    continue
                p = os.path.join(root, name)
                if os.path.abspath(p) == os.path.abspath(self.path):
                    continue
                text = _read_text(p)
                if not text or "密码" not in text:
                    continue
                for m in _PW_INLINE.finditer(text):
                    add(m.group(1))
        return out

    def reload(self, force: bool = False) -> bool:
        """重新读取。返回是否发生了变化。"""
        try:
            mtime = os.path.getmtime(self.path) if os.path.isfile(self.path) else 0.0
        except OSError:
            mtime = 0.0
        if not force and mtime == self._mtime:
            return False
        with self._lock:
            from_file = self._read_file()
            merged: list[str] = []
            for pw in from_file + self._scan_txt() + self._manual:
                if pw and pw not in merged:
                    merged.append(pw)
            changed = merged != self._pws
            self._pws = merged
            self._manual = from_file
            self._mtime = mtime
            self.last_load = time.time()
            # 文件里若有不符合规则的残留（例如早先误写入的 URL），顺手清理
            stale = [ln.strip().strip("\"'")
                     for ln in (_read_text(self.path) or "").splitlines()
                     if ln.strip() and not _plausible_password(ln.strip().strip("\"'"))]
        if stale:
            self._write_file(from_file)
        return changed

    # -- 写回 -------------------------------------------------------------
    def _write_file(self, pws: list[str]) -> None:
        """写回密码文件。

        只落盘"手动维护的密码"（self._manual），不把自动扫描到的内容写进去，
        否则说明文件里的 URL / 广告词会被固化进密码清单。
        """
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
            with open(self.path, "w", encoding="utf-8") as f:
                for pw in pws:
                    f.write(pw + "\n")
            self._mtime = os.path.getmtime(self.path)
        except OSError:
            pass

    def add(self, pw: str) -> bool:
        pw = (pw or "").strip()
        if not pw or not _plausible_password(pw):
            return False
        with self._lock:
            if pw in self._pws:
                return False
            self._pws.insert(0, pw)
            if pw not in self._manual:
                self._manual.insert(0, pw)
            snapshot = list(self._manual)
        self._write_file(snapshot)
        return True

    def remove(self, pw: str) -> bool:
        with self._lock:
            if pw in self._pws:
                self._pws.remove(pw)
            if pw in self._manual:
                self._manual.remove(pw)
            else:
                return False
            snapshot = list(self._manual)
        self._write_file(snapshot)
        return True

    # -- 供流程使用 -------------------------------------------------------
    def get(self) -> list[str]:
        """返回当前密码快照（每次调用都重新检查文件变化 → 热加载）。"""
        self.reload()
        with self._lock:
            return list(self._pws)

    def __call__(self) -> list[str]:
        """让密码集合本身可调用，便于直接把 store 传给流程。"""
        return self.get()
