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


def _clean_line(s: str) -> str:
    """密码文件里的一行：去掉空白和引号，原文使用。"""
    return (s or "").strip().strip("\"'")


def _plausible_password(s: str) -> bool:
    """过滤掉误匹配：URL、路径、说明性长句都不是密码。

    只用于"自动扫描"到的候选（说明文本、目录名）——
    手工写进密码文件的条目一律原文采信，见 _read_file()。
    """
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


def _is_password_line(s: str) -> bool:
    """密码文件里的这一行算不算一个密码。

    故意比 _plausible_password 宽松：密码本身就是"长得像别的东西"才安全，
    www.moehui.com、有斜杠的句子、超过 64 字符的都有可能真是密码。
    只排除空行和 # 注释。
    """
    s = _clean_line(s)
    return bool(s) and not s.startswith("#") and len(s) <= 200


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
        """密码文件里的条目一律原文采信。

        密码是用户自己写的，长什么样都可能（www.moehui.com 这种域名很常见）。
        以前这里套了"像不像密码"的过滤，结果把域名密码吃掉、还顺手从文件里
        删掉，等于把用户的密码弄丢了。
        """
        out: list[str] = []
        text = _read_text(self.path) if os.path.isfile(self.path) else None
        if text:
            for line in text.splitlines():
                if not _is_password_line(line):
                    continue
                s = _clean_line(line)
                if s not in out:
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
        # 注意：这里绝不能"顺手清理"密码文件里看着不像密码的行 ——
        # 那会把用户的密码（比如 www.moehui.com）直接从文件里删掉。
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
        """手动添加密码：原文采信（用户敲进去的就是密码）。"""
        pw = _clean_line(pw)
        if not _is_password_line(pw):
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
