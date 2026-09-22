"""End-to-end pipeline: detect disguise -> restore -> test -> extract -> recurse.

Designed to be driven by a GUI, so every step reports progress through a
callback and never calls sys.exit.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable, Iterable

from . import disguise
from .sevenzip import SevenZip

IMG_EXT = {".jpg", ".jpeg", ".jfif", ".png", ".gif", ".webp", ".bmp",
           ".tif", ".tiff", ".avif", ".heic", ".heif", ".jpe"}
VID_EXT = {".mp4", ".mov", ".mkv", ".avi", ".wmv", ".flv", ".webm", ".m4v",
           ".ts", ".m2ts", ".rmvb", ".mpg", ".mpeg", ".3gp", ".vob", ".rm", ".f4v"}

ARCHIVE_EXT = (".7z", ".zip", ".rar", ".001", ".z01")

# 7-Zip 在密码不正确时的提示（中英文都覆盖）
_WRONG_PW_MARKERS = (
    "wrong password", "invalid password", "密码错误", "密码不正确",
    "data error in encrypted file",
)


def _looks_like_wrong_password(output: str) -> bool:
    low = (output or "").lower()
    return any(m in low for m in _WRONG_PW_MARKERS)


def _looks_encrypted(list_output: str) -> bool:
    """7-Zip 列出加密压缩包时会带上这些标记。"""
    low = (list_output or "").lower()
    return ("encrypted" in low or "aes" in low or "加密" in list_output)


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
    def __init__(self, sz: SevenZip | None = None, salvage: bool = True,
                 copy_workers: int | None = None):
        self.sz = sz or SevenZip()
        # salvage=True: 数据校验失败时仍然尝试解压，尽量救出未损坏的部分
        self.salvage = salvage
        # 归档时的并行拷贝线程数。文件多且小的时候收益很大（实测快十几倍）。
        self.copy_workers = copy_workers or min(8, (os.cpu_count() or 4) * 2)

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

    def _resolve_passwords(self, passwords) -> list[str]:
        """passwords 可以是列表，也可以是个可调用对象。

        传可调用对象时，每次尝试密码都会重新取值 —— 这就是"热加载"：
        界面里新加的密码对后续压缩包（以及正在处理的队列）立刻生效。
        """
        try:
            vals = passwords() if callable(passwords) else passwords
        except Exception:
            return []
        return [str(v) for v in (vals or []) if str(v).strip()]

    def _try_passwords(self, path: str, passwords):
        """逐个尝试密码，产出所有"能打开"的候选。

        注意：加密的 7z 即使密码错误也能列出文件头，所以这里不能一遇到
        list 成功就认定密码对 —— 把候选都交给上层用 test 判定。密码文件里
        通常只有几个候选，成本可以接受。
        """
        seen = set()
        for pw in self._resolve_passwords(passwords):
            if pw in seen:
                continue
            seen.add(pw)
            ok, _atype, out = self.sz.list(path, pw)
            if ok:
                yield pw, True, out

        # 未加密的包：空密码也能列出内容，此时 test 应当通过。
        # 但如果这是个加密包（list 输出里带加密标记），空密码就是无效候选，
        # 不要让它去走"数据损坏"的抢救流程。
        ok, _atype, out = self.sz.list(path, None)
        if ok and not _looks_encrypted(out):
            yield None, True, out

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
        passwords: "list[str] | Callable[[], list[str]]",
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
                good, tout = self.sz.test(archive, pw)
                # 密码错和数据坏都会让 test 失败，但处理方式完全不同：
                #   - 密码错：赶紧换下一个密码，别浪费时间抢救
                #   - 数据坏：才是下载不完整，值得尝试抢救
                if not good and _looks_like_wrong_password(tout):
                    log(f"密码 {pw or '无'} 不正确，继续尝试其他密码")
                    continue
                pw_used = pw
                tested = good
                if good:
                    res.add(f"完整性校验通过 (密码: {pw or '无'})")
                    log(res.steps[-1])
                    break
                # 数据校验失败通常是下载不完整（有零区）。仍然尝试解压，
                # 能救出多少算多少，只是内容可能不完整。
                res.add(f"密码 {pw} 正确，但数据校验失败（可能下载不完整）")
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

    # 压缩包文件头，用于不依赖扩展名的识别
    _ARCH_MAGIC = (
        (b"7z\xbc\xaf\x27\x1c", "7z"),
        (b"PK\x03\x04", "zip"),
        (b"Rar!\x1a\x07\x01\x00", "rar"),
        (b"Rar!\x1a\x07\x00", "rar"),
    )

    @classmethod
    def _sniff_archive(cls, path: str) -> str | None:
        """按文件头判断是不是压缩包，忽略扩展名。

        有些资源会把内层包改名（如 .7z删除、.bin），只看后缀会漏掉。
        """
        try:
            with open(path, "rb") as f:
                head = f.read(8)
        except OSError:
            return None
        for magic, kind in cls._ARCH_MAGIC:
            if head.startswith(magic):
                return kind
        return None

    def _extract_nested(self, root: str, passwords, log: LogFn):
        """解开解压结果里嵌套的压缩包。

        三层保险避免漏解：
          1) 分卷 (.001/.z01 ...)
          2) 有压缩包后缀 (.7z/.zip/.rar)
          3) 上述都没有时，按文件头嗅探（应对 .7z删除 / .bin 这类改名）
        每轮扫描一次，最多三轮，避免无限递归。
        """
        for _ in range(3):
            volumes = []
            named = []
            sniffed = []
            for r, _d, fs in os.walk(root):
                for f in fs:
                    low = f.lower()
                    if low.endswith(".qkdownloading"):
                        continue
                    fp = os.path.join(r, f)
                    if low.endswith(".001") or low.endswith(".z01"):
                        volumes.append(fp)
                    elif low.endswith((".7z", ".zip", ".rar")):
                        named.append(fp)
                    elif self._sniff_archive(fp):
                        sniffed.append(fp)

            # 优先分卷，其次明确后缀，最后才嗅探；嗅探放最后避免误伤媒体文件
            targets = volumes + named + sniffed[:20]
            if not targets:
                return
            progressed = False
            for t in targets:
                if not os.path.exists(t):
                    continue
                for pw, ok, _o in self._try_passwords(t, passwords):
                    if not ok:
                        break
                    before = self._dir_stats(root)[0]
                    self.sz.extract(t, os.path.dirname(t), pw)
                    after = self._dir_stats(root)[0]
                    if t.lower().endswith((".001", ".z01")):
                        self._delete_volume_set(t)
                    elif after > before:
                        # 确实解出了新内容，才删掉内层包
                        try:
                            os.chmod(t, 0o666)
                        except OSError:
                            pass
                        try:
                            os.remove(t)
                        except OSError:
                            pass
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
        include_other: bool = True,
        works_out: list[dict] | None = None,
    ) -> tuple[int, int, list[str]]:
        """把 src_root 下的文件分类搬到目标目录。

        图片 -> <dest>/图片/<顶层目录>/...
        视频 -> <dest>/视频/<顶层目录>/...
        其它 -> <dest>/其他/<顶层目录>/...   （include_other=True 时）

        重要：绝不能静默丢弃文件。搬不动的会记进 errors，调用方据此决定
        是否删除源文件。返回 (moved_files, moved_bytes, errors)。
        """
        skip_dirs = skip_dirs or set()
        plan: list[tuple[str, str]] = []  # (src, dest)
        # 记录每个作品目录的去向与统计，供"一键查看刚解压的"用
        works: dict[tuple[str, str], list[int]] = {}

        def plan_tree(top_name: str, dir_path: str):
            for r, _d, fs in os.walk(dir_path):
                for f in fs:
                    fp = os.path.join(r, f)
                    kind = self._media_kind(fp)
                    rel = os.path.relpath(fp, dir_path)
                    sub = self._strip_dup(rel, top_name)
                    if kind == "image":
                        bucket = "图片"
                    elif kind == "video":
                        bucket = "视频"
                    elif include_other:
                        bucket = "其他"
                    else:
                        continue
                    plan.append((fp, os.path.join(dest_root, bucket, top_name, sub)))
                    key = (bucket, top_name)
                    e = works.setdefault(key, [0, 0])
                    e[0] += 1
                    try:
                        e[1] += os.path.getsize(fp)
                    except OSError:
                        pass

        for name in sorted(os.listdir(src_root)):
            p = os.path.join(src_root, name)
            if os.path.isdir(p):
                if name in skip_dirs:
                    continue
                plan_tree(name, p)
            else:
                kind = self._media_kind(p)
                if kind == "image":
                    bucket = "图片"
                elif kind == "video":
                    bucket = "视频"
                elif include_other:
                    bucket = "其他"
                else:
                    continue
                plan.append((p, os.path.join(dest_root, bucket, name)))
                key = (bucket, name)
                e = works.setdefault(key, [0, 0])
                e[0] += 1
                try:
                    e[1] += os.path.getsize(p)
                except OSError:
                    pass

        total = len(plan)
        if total == 0:
            return 0, 0, []

        # 先批量把所有目标目录建好，避免多线程里反复 makedirs / 竞争
        dest_dirs = {os.path.dirname(d) for _s, d in plan}
        for d in dest_dirs:
            self._ensure_dir(d)

        # 同盘搬迁用 os.replace（瞬间完成）；跨盘才真的复制数据
        same_volume = self._same_volume(src_root, dest_root)

        done = 0
        moved = 0
        moved_bytes = 0
        errors: list[str] = []
        lock = threading.Lock()

        def do_one(item):
            src, dst = item
            nonlocal done, moved, moved_bytes
            err = None
            nbytes = 0
            try:
                ssz = os.path.getsize(src)
                try:
                    dsz = os.path.getsize(dst)
                except OSError:
                    dsz = -1
                if dsz == ssz:
                    # 目标已有一份且大小一致，直接处理源文件
                    if move:
                        self._force_remove(src)
                    nbytes = dsz
                elif same_volume and move:
                    self._clear_readonly(dst)
                    os.replace(src, dst)      # 同盘：瞬间改名，零拷贝
                    nbytes = ssz
                else:
                    if dsz >= 0:
                        self._clear_readonly(dst)
                    self._copy_file(src, dst)  # 跨盘：裸读写，避免元数据开销
                    if os.path.getsize(dst) != ssz:
                        raise OSError("大小不一致")
                    self._clear_readonly(dst)
                    if move:
                        self._force_remove(src)
                    nbytes = ssz
            except Exception as exc:
                err = f"{src} -> {dst}: {exc}"

            with lock:
                done += 1
                if err:
                    errors.append(err)
                else:
                    moved += 1
                    moved_bytes += nbytes
                if progress and (done % 25 == 0 or done == total):
                    progress(done, total)

        workers = self.copy_workers
        if workers > 1 and total > 1:
            with ThreadPoolExecutor(max_workers=workers) as ex:
                list(ex.map(do_one, plan))
        else:
            for it in plan:
                do_one(it)

        # 搬迁后仍留在源目录里的文件 = 没被安全归档的，必须报给调用方
        leftover = [os.path.join(r, f)
                    for r, _d, fs in os.walk(src_root) for f in fs]
        if leftover:
            errors.append(f"未能归档的文件 {len(leftover)} 个（保留在暂存区）: "
                          + ", ".join(os.path.basename(x) for x in leftover[:5]))

        # 把"这次归档了什么"回传给调用方（供一键查看刚解压的用）
        if works_out is not None:
            for (bucket, top_name), (cnt, tot) in sorted(
                    works.items(), key=lambda kv: (kv[0][0], kv[0][1])):
                works_out.append({
                    "kind": bucket,
                    "name": top_name,
                    "path": os.path.join(dest_root, bucket, top_name),
                    "files": cnt,
                    "bytes": tot,
                })

        log(f"归档完成: {moved} 个文件, {moved_bytes/1048576:.1f} MB"
            + (f", {len(errors)} 个问题" if errors else ""))
        return moved, moved_bytes, errors

    @staticmethod
    def _copy_file(src: str, dst: str, chunk: int = 4 << 20):
        """裸读写复制。比 shutil.copy2 快数倍——后者会逐个文件同步元数据，
        在网络盘/外置盘上这部分开销可能比数据本身还大。"""
        with open(src, "rb") as fi, open(dst, "wb") as fo:
            while True:
                b = fi.read(chunk)
                if not b:
                    break
                fo.write(b)

    @staticmethod
    def _same_volume(a: str, b: str) -> bool:
        """判断两个路径是否在同一卷（用于决定能否用瞬时的 rename 搬迁）。"""
        try:
            da = os.path.splitdrive(os.path.abspath(a))[0].lower()
            db = os.path.splitdrive(os.path.abspath(b))[0].lower()
            return bool(da) and da == db
        except Exception:
            return False

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
