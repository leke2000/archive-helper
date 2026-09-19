"""End-to-end pipeline: detect disguise -> restore -> test -> extract -> recurse.

Designed to be driven by a GUI, so every step reports progress through a
callback and never calls sys.exit.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import dataclass, field
from typing import Callable, Iterable

from . import disguise
from .sevenzip import SevenZip

IMG_EXT = {".jpg", ".jpeg", ".jfif", ".png", ".gif", ".webp", ".bmp",
           ".tif", ".tiff", ".avif", ".heic", ".heif", ".jpe"}
VID_EXT = {".mp4", ".mov", ".mkv", ".avi", ".wmv", ".flv", ".webm", ".m4v",
           ".ts", ".m2ts", ".rmvb", ".mpg", ".mpeg", ".3gp", ".vob", ".rm", ".f4v"}

ARCHIVE_EXT = (".7z", ".zip", ".rar", ".001", ".z01")


@dataclass
class Result:
    source: str
    ok: bool
    outdir: str = ""
    files: int = 0
    bytes_: int = 0
    steps: list[str] = field(default_factory=list)
    error: str = ""

    def add(self, msg: str):
        self.steps.append(msg)


LogFn = Callable[[str], None]
ProgressFn = Callable[[int, int], None]


class Pipeline:
    def __init__(self, sz: SevenZip | None = None, salvage: bool = True):
        self.sz = sz or SevenZip()
        # salvage=True: 数据校验失败时仍然尝试解压，尽量救出未损坏的部分
        self.salvage = salvage

    # -- helpers -----------------------------------------------------------
    @staticmethod
    def _media_kind(path: str) -> str | None:
        e = os.path.splitext(path)[1].lower()
        if e in IMG_EXT:
            return "image"
        if e in VID_EXT:
            return "video"
        return None

    @staticmethod
    def _dir_stats(root: str) -> tuple[int, int]:
        files = 0
        total = 0
        for r, _d, fs in os.walk(root):
            for f in fs:
                files += 1
                try:
                    total += os.path.getsize(os.path.join(r, f))
                except OSError:
                    pass
        return files, total

    def _try_passwords(self, path: str, passwords: Iterable[str]):
        """Yield (password, ok, out) for the first password that opens the archive."""
        seen = set()
        for pw in passwords:
            if pw in seen:
                continue
            seen.add(pw)
            ok, _atype, out = self.sz.list(path, pw)
            if ok:
                yield pw, True, out
                return
            # an unencrypted archive opens with no password
        ok, _atype, out = self.sz.list(path, None)
        yield None, ok, out

    # -- main --------------------------------------------------------------
    @staticmethod
    def _ensure_dir(path: str, retries: int = 12, delay: float = 5.0) -> None:
        """Create a directory, retrying while the volume is temporarily offline.

        外置硬盘/网络盘会短暂掉线，直接 makedirs 会抛 FileNotFoundError。
        """
        import time as _time
        last = None
        for attempt in range(retries):
            try:
                os.makedirs(path, exist_ok=True)
                return
            except (FileNotFoundError, OSError) as exc:
                last = exc
                _time.sleep(delay)
        raise RuntimeError(f"无法创建目录 {path}（磁盘可能离线）: {last}")

    def process(
        self,
        source: str,
        workdir: str,
        outdir: str,
        passwords: list[str],
        log: LogFn = lambda m: None,
        progress: ProgressFn | None = None,
        recurse: bool = True,
        keep_source: bool = True,
    ) -> Result:
        res = Result(source=source, ok=False)
        self._ensure_dir(workdir)
        self._ensure_dir(outdir)

        try:
            det = disguise.detect(source)
            res.add(f"检测: {det.kind} {det.signature} {'; '.join(det.notes)}")
            log(res.steps[-1])

            archive = source
            tmp_archive = None
            if det.kind in ("tail_reversed", "appended"):
                tmp_archive = os.path.join(workdir, "_restored.bin")
                log("还原伪装文件...")
                disguise.restore(source, tmp_archive, det, progress=progress)
                archive = tmp_archive
                res.add(f"已还原为 {os.path.getsize(tmp_archive):,} 字节")
                log(res.steps[-1])

            # test integrity first (avoids producing half-extracted junk)
            pw_used = None
            tested = False
            salvaged = False
            for pw, ok, _out in self._try_passwords(archive, passwords):
                if not ok:
                    continue
                good, _tout = self.sz.test(archive, pw)
                pw_used = pw
                tested = good
                if good:
                    res.add(f"完整性校验通过 (密码: {pw or '无'})")
                    log(res.steps[-1])
                    break
                # 数据校验失败通常是下载不完整（有零区）。仍然尝试解压，
                # 能救出多少算多少，只是内容可能不完整。
                res.add(f"密码 {pw} 可打开但数据校验失败（可能下载不完整）")
                log(res.steps[-1])
                salvaged = True

            if not tested and not (salvaged and self.salvage):
                res.error = "无法通过完整性校验（密码错误或文件损坏）"
                log("错误: " + res.error)
                return res
            if not tested:
                log("尝试抢救式解压（文件不完整，可能只有部分内容）...")
                res.add("抢救式解压：仅能恢复未损坏的部分")

            # extract
            log("解压中...")
            ok, out = self.sz.extract(archive, outdir, pw_used)
            if not ok and not tested:
                # 7z 对损坏包返回非零，但仍可能已写出可用文件
                files_now, _ = self._dir_stats(outdir)
                if files_now == 0:
                    res.error = "解压失败"
                    log("错误: " + res.error)
                    return res
                log(f"解压报告异常，但已恢复 {files_now} 个文件")

            # recurse into any nested volumes (salvage path needs this too)
            if recurse:
                self._extract_nested(outdir, passwords, log)

            if tmp_archive and os.path.exists(tmp_archive):
                os.remove(tmp_archive)

            files, total = self._dir_stats(outdir)
            res.ok = True
            res.outdir = outdir
            res.files = files
            res.bytes_ = total
            res.add(f"完成: {files} 个文件, {total/1048576:.1f} MB")
            log(res.steps[-1])
            return res

        except Exception as exc:  # keep the GUI alive
            res.error = f"{type(exc).__name__}: {exc}"
            log("异常: " + res.error)
            return res

    def _extract_nested(self, root: str, passwords: list[str], log: LogFn):
        """Extract split volumes / nested archives found under root."""
        for _ in range(3):
            targets = []
            for r, _d, fs in os.walk(root):
                for f in fs:
                    low = f.lower()
                    if low.endswith(".001") or low.endswith(".z01"):
                        targets.append(os.path.join(r, f))
            if not targets:
                return
            progressed = False
            for t in targets:
                if not os.path.exists(t):
                    continue
                for pw, ok, _o in self._try_passwords(t, passwords):
                    if not ok:
                        break
                    log(f"解压嵌套分卷 {os.path.basename(t)}")
                    self.sz.extract(t, os.path.dirname(t), pw)
                    # 无论 7z 是否报告完全成功，都清掉分卷避免下一轮重复处理
                    self._delete_volume_set(t)
                    progressed = True
                    break
            if not progressed:
                return

    @staticmethod
    def _delete_volume_set(vol001: str):
        base = vol001[:-4]
        i = 1
        while i <= 999:
            v = f"{base}.{i:03d}"
            if os.path.exists(v):
                try:
                    os.remove(v)
                except OSError:
                    pass
                i += 1
            else:
                break

    # -- archiving ---------------------------------------------------------
    def archive_by_type(
        self,
        src_root: str,
        dest_root: str,
        log: LogFn = lambda m: None,
        move: bool = True,
        progress: ProgressFn | None = None,
        skip_dirs: set[str] | None = None,
    ) -> tuple[int, int, list[str]]:
        """Split media under src_root into <dest_root>/图片 and /视频.

        Returns (moved_files, moved_bytes, errors).
        """
        skip_dirs = skip_dirs or set()
        plan: list[tuple[str, str, str]] = []  # (src, dest, kind)

        for name in sorted(os.listdir(src_root)):
            p = os.path.join(src_root, name)
            if os.path.isdir(p):
                if name in skip_dirs:
                    continue
                for r, _d, fs in os.walk(p):
                    for f in fs:
                        fp = os.path.join(r, f)
                        kind = self._media_kind(fp)
                        if not kind:
                            continue
                        rel = os.path.relpath(fp, p)
                        sub = self._strip_dup(rel, name)
                        top = "图片" if kind == "image" else "视频"
                        plan.append((fp, os.path.join(dest_root, top, name, sub), kind))
            else:
                kind = self._media_kind(p)
                if kind:
                    top = "图片" if kind == "image" else "视频"
                    plan.append((p, os.path.join(dest_root, top, name), kind))

        total = len(plan)
        done = 0
        moved = 0
        moved_bytes = 0
        errors: list[str] = []

        for src, dst, _kind in plan:
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            try:
                ssz = os.path.getsize(src)
                # already archived with identical size? just drop the source copy
                try:
                    dsz = os.path.getsize(dst)
                except OSError:
                    dsz = -1
                if dsz == ssz:
                    if move:
                        self._force_remove(src)
                    moved += 1
                    moved_bytes += dsz
                else:
                    if dsz >= 0:
                        self._clear_readonly(dst)
                    shutil.copy2(src, dst)
                    if os.path.getsize(dst) != ssz:
                        raise OSError("大小不一致")
                    self._clear_readonly(dst)
                    if move:
                        self._force_remove(src)
                    moved += 1
                    moved_bytes += ssz
            except Exception as exc:
                errors.append(f"{src} -> {dst}: {exc}")
            done += 1
            if progress and (done % 25 == 0 or done == total):
                progress(done, total)
        log(f"归档完成: {moved} 个文件, {moved_bytes/1048576:.1f} MB"
            + (f", {len(errors)} 个失败" if errors else ""))
        return moved, moved_bytes, errors

    @staticmethod
    def _clear_readonly(path: str):
        """网盘下载的文件常带只读属性，覆盖/删除前先清掉。"""
        try:
            import stat as _stat
            os.chmod(path, _stat.S_IWRITE | _stat.S_IREAD)
        except OSError:
            pass

    @classmethod
    def _force_remove(cls, path: str) -> bool:
        cls._clear_readonly(path)
        try:
            os.remove(path)
            return True
        except OSError:
            return False

    @staticmethod
    def _strip_dup(rel: str, top: str) -> str:
        parts = rel.split(os.sep)
        while parts and parts[0] == top:
            parts.pop(0)
        return os.path.join(*parts) if parts else ""
