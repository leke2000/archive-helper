"""7-Zip command line wrapper.

Locates the bundled 7za.exe and exposes list / test / extract helpers that
return plain Python data instead of raw console text.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys

# Hide the console window that would otherwise flash on Windows.
_CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0


def app_root() -> str:
    """Directory that contains the application (works frozen or from source)."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def find_7za() -> str | None:
    """Return the path to a usable 7za/7z executable, or None."""
    root = app_root()
    candidates = [
        os.path.join(root, "bin", "7za.exe"),
        os.path.join(root, "bin", "7z.exe"),
        os.path.join(root, "bin", "7za"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path
    for name in ("7za", "7za.exe", "7z", "7z.exe"):
        found = shutil.which(name)
        if found:
            return found
    return None


class SevenZip:
    def __init__(self, exe: str | None = None):
        self.exe = exe or find_7za()
        if not self.exe:
            raise FileNotFoundError(
                "找不到 7za.exe。请把 7za.exe 放到程序的 bin 目录，"
                "或安装 7-Zip 并加入 PATH。"
            )

    # -- low level ---------------------------------------------------------
    def run(self, args: list[str], timeout: int | None = None) -> tuple[int, str]:
        proc = subprocess.run(
            [self.exe, *args],
            capture_output=True,
            text=True,
            errors="replace",
            creationflags=_CREATE_NO_WINDOW,
            timeout=timeout,
        )
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")

    # -- operations --------------------------------------------------------
    def list(self, path: str, password: str | None = None) -> tuple[bool, str, str]:
        """Return (ok, archive_type, raw_output)."""
        args = ["l", "-slt"]
        if password:
            args.append("-p" + password)
        args.append(path)
        rc, out = self.run(args)
        atype = ""
        m = re.search(r"^Type = (.+)$", out, re.MULTILINE)
        if m:
            atype = m.group(1).strip()
        ok = rc == 0 and "Cannot open" not in out and "Is not archive" not in out
        return ok, atype, out

    def test(self, path: str, password: str | None = None) -> tuple[bool, str]:
        """Integrity test. Returns (ok, output)."""
        args = ["t"]
        if password:
            args.append("-p" + password)
        args.append(path)
        rc, out = self.run(args)
        if "Wrong password" in out or "Invalid password" in out:
            return False, out
        ok = "Everything is Ok" in out
        return ok, out

    def extract(
        self,
        path: str,
        outdir: str,
        password: str | None = None,
        overwrite: bool = True,
    ) -> tuple[bool, str]:
        args = ["x", "-y"]
        if overwrite:
            args.append("-aoa")
        args.append("-o" + outdir)
        if password:
            args.append("-p" + password)
        args.append(path)
        rc, out = self.run(args)
        ok = "Everything is Ok" in out
        return ok, out

    def is_archive(self, path: str, password: str | None = None) -> bool:
        ok, _, _ = self.list(path, password)
        return ok
