"""删除文件：优先送进回收站（能反悔），不行再硬删。

网盘下载的文件常带只读属性，路径也可能很长，这里一并处理掉。
"""

from __future__ import annotations

import ctypes
import os
import stat
from ctypes import wintypes

_IS_WINDOWS = os.name == "nt"

# SHFileOperationW 的常量
_FO_DELETE = 3
_FOF_SILENT = 0x0004
_FOF_NOCONFIRMATION = 0x0010
_FOF_ALLOWUNDO = 0x0040
_FOF_NOERRORUI = 0x0400
_FOF_WANTNUKEWARNING = 0x4000

_LONG_PREFIX = "\\\\?\\"


class _SHFILEOPSTRUCTW(ctypes.Structure):
    _fields_ = [
        ("hwnd", wintypes.HWND),
        ("wFunc", wintypes.UINT),
        ("pFrom", wintypes.LPCWSTR),
        ("pTo", wintypes.LPCWSTR),
        ("fFlags", ctypes.c_uint16),
        ("fAnyOperationsAborted", wintypes.BOOL),
        ("hNameMappings", ctypes.c_void_p),
        ("lpszProgressTitle", wintypes.LPCWSTR),
    ]


def _long(path: str) -> str:
    """加 \\\\?\\ 前缀，绕开 260 字符路径限制。"""
    p = os.path.abspath(path)
    if p.startswith(_LONG_PREFIX):
        return p
    if p.startswith("\\\\"):          # UNC：\\server\share -> \\?\UNC\server\share
        return _LONG_PREFIX + "UNC" + p[1:]
    return _LONG_PREFIX + p


def clear_readonly(path: str) -> None:
    """清掉只读属性（网盘下载经常带），否则删不掉。"""
    try:
        os.chmod(_long(path), stat.S_IWRITE | stat.S_IREAD)
    except OSError:
        pass


def send_to_trash(paths) -> tuple[list[str], list[str]]:
    """把文件/文件夹送进回收站。返回 (成功, 失败)。

    SHFileOperationW 不认 \\\\?\\ 前缀，所以这里用普通路径；
    太长的路径它自己处理不了时会失败，由调用方退回硬删。
    """
    paths = [os.path.abspath(p) for p in paths]
    if not paths:
        return [], []
    if not _IS_WINDOWS:
        return [], list(paths)

    # 路径列表要以两个 \0 结尾
    joined = "\0".join(paths) + "\0\0"
    op = _SHFILEOPSTRUCTW(
        None, _FO_DELETE, joined, None,
        _FOF_ALLOWUNDO | _FOF_NOCONFIRMATION | _FOF_SILENT
        | _FOF_NOERRORUI | _FOF_WANTNUKEWARNING,
        False, None, None,
    )
    try:
        rc = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(op))
    except OSError:
        return [], list(paths)
    if rc != 0 or op.fAnyOperationsAborted:
        # 整批失败时逐个再试，尽量救回能删的
        ok, bad = [], []
        for p in paths:
            one = "\0" + p + "\0\0"
            o = _SHFILEOPSTRUCTW(
                None, _FO_DELETE, one, None,
                _FOF_ALLOWUNDO | _FOF_NOCONFIRMATION | _FOF_SILENT
                | _FOF_NOERRORUI | _FOF_WANTNUKEWARNING,
                False, None, None,
            )
            if ctypes.windll.shell32.SHFileOperationW(ctypes.byref(o)) == 0 \
                    and not o.fAnyOperationsAborted:
                ok.append(p)
            else:
                bad.append(p)
        return ok, bad
    return paths, []


def hard_delete(path: str) -> bool:
    """直接删除（不进回收站），只读和长路径都处理。"""
    p = _long(path)
    clear_readonly(path)
    try:
        if os.path.isdir(p) and not os.path.islink(p):
            import shutil
            shutil.rmtree(p, ignore_errors=False)
        else:
            os.remove(p)
        return True
    except OSError:
        # 目录里可能有只读文件，递归清一遍再试
        try:
            if os.path.isdir(p):
                for root, dirs, files in os.walk(p):
                    for n in files:
                        clear_readonly(os.path.join(root, n))
                import shutil
                shutil.rmtree(p, ignore_errors=True)
                return not os.path.exists(p)
        except OSError:
            pass
        return not os.path.exists(p)


def delete(paths, to_trash: bool = True) -> tuple[list[str], list[str]]:
    """删除一批文件。返回 (成功, 失败)。

    to_trash=True 时先送回收站；回收站失败（比如单文件超过回收站上限）
    再硬删 —— 反正这些源包都已经归档好了。
    """
    paths = list(paths)
    if not paths:
        return [], []
    ok: list[str] = []
    bad: list[str] = []
    if to_trash and _IS_WINDOWS:
        ok, bad = send_to_trash(paths)
    else:
        bad = paths
    for p in bad:
        if os.path.exists(p):
            (ok if hard_delete(p) else bad).append(p)
    return ok, [p for p in bad if os.path.exists(p)]
