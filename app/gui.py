"""Tkinter GUI for the universal extractor / archiver.

界面包含三个标签页：
  收件箱  —— 一键扫描收件目录、解压、分类归档（推荐日常用）
  解压    —— 手动选文件/文件夹解压
  归档    —— 只把已有目录按类型分类

密码面板支持热加载：新增密码立刻对后续包生效，也可自动从收件目录的
说明 txt 里提取 "密码:xxx"。
"""

from __future__ import annotations

import os
import queue
import shutil
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from . import recent
from .passwords import DEFAULT_PASSWORD_FILE, PasswordStore
from .pipeline import Pipeline
from .sevenzip import SevenZip, find_7za

PAD = 8

DEFAULT_INBOX = r"D:\dowm"
DEFAULT_DEST = r"H:\赏花阁"

# 只把像压缩包/媒体伪装包的文件送进流水线，避免把说明文档也拖进去
_CANDIDATE_EXT = {".mp4", ".mov", ".mkv", ".avi", ".webm", ".jpg", ".jpeg",
                  ".png", ".gif", ".webp", ".7z", ".zip", ".rar", ".001"}


def _is_candidate(path: str) -> bool:
    return os.path.splitext(path)[1].lower() in _CANDIDATE_EXT


def _stem_name(name: str) -> str:
    """剥掉媒体 + 压缩两种扩展名: 'a.7z.mp4' -> 'a'."""
    base = name
    for ext in (".mp4", ".mov", ".mkv", ".avi", ".webm", ".jpg", ".jpeg",
                ".png", ".gif", ".webp"):
        if base.lower().endswith(ext):
            base = base[:-len(ext)]
            break
    for ext in (".7z", ".zip", ".rar", ".001"):
        if base.lower().endswith(ext):
            base = base[:-len(ext)]
            break
    return base


def _human(n: float) -> str:
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f}{u}"
        n /= 1024
    return f"{n:.1f}PB"


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("通用解压归档助手")
        self.geometry("1040x760")
        self.minsize(880, 620)

        self.log_q: queue.Queue = queue.Queue()
        self.busy = False
        self.stop_flag = threading.Event()

        self.pw_store = PasswordStore(DEFAULT_PASSWORD_FILE, DEFAULT_INBOX)

        self._build()
        self.after(80, self._drain)
        self.after(500, self._poll_passwords)

    # -- layout ------------------------------------------------------------
    def _build(self):
        style = ttk.Style(self)
        try:
            style.theme_use("vista")
        except tk.TclError:
            pass

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=PAD, pady=(PAD, 0))

        self.tab_inbox = ttk.Frame(nb)
        self.tab_extract = ttk.Frame(nb)
        self.tab_archive = ttk.Frame(nb)
        self.tab_pw = ttk.Frame(nb)
        nb.add(self.tab_inbox, text="收件箱")
        nb.add(self.tab_extract, text="解压")
        nb.add(self.tab_archive, text="分类归档")
        nb.add(self.tab_pw, text="密码")

        self._build_inbox(self.tab_inbox)
        self._build_extract(self.tab_extract)
        self._build_archive(self.tab_archive)
        self._build_passwords(self.tab_pw)

        box = ttk.LabelFrame(self, text="日志")
        box.pack(fill="both", expand=True, padx=PAD, pady=(PAD, 0))
        self.log = tk.Text(box, height=11, wrap="word", state="disabled",
                           background="#11131a", foreground="#d8dee9",
                           insertbackground="#d8dee9")
        sb = ttk.Scrollbar(box, command=self.log.yview)
        self.log.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.log.pack(side="left", fill="both", expand=True)

        bar = ttk.Frame(self)
        bar.pack(fill="x", padx=PAD, pady=PAD)
        self.status = ttk.Label(bar, text="就绪", anchor="w")
        self.status.pack(side="left")
        self.pbar = ttk.Progressbar(bar, mode="determinate", length=260)
        self.pbar.pack(side="right")

        if not find_7za():
            self.write("警告: 未找到 7za.exe，解压功能不可用。请把 7za.exe 放到 bin 目录。")
        self._refresh_pw_list()

    # -- 收件箱 ------------------------------------------------------------
    def _build_inbox(self, root):
        f = ttk.Frame(root)
        f.pack(fill="x", padx=PAD, pady=PAD)

        ttk.Label(f, text="收件目录:").grid(row=0, column=0, sticky="w")
        self.inbox_var = tk.StringVar(value=DEFAULT_INBOX)
        ttk.Entry(f, textvariable=self.inbox_var).grid(row=0, column=1, sticky="ew", padx=4)
        ttk.Button(f, text="选择", command=lambda: self._pick_into(self.inbox_var)).grid(row=0, column=2, padx=2)

        ttk.Label(f, text="归档到:").grid(row=1, column=0, sticky="w", pady=(6, 0))
        self.dest_var = tk.StringVar(value=DEFAULT_DEST)
        ttk.Entry(f, textvariable=self.dest_var).grid(row=1, column=1, sticky="ew", padx=4, pady=(6, 0))
        ttk.Button(f, text="选择", command=lambda: self._pick_into(self.dest_var)).grid(row=1, column=2, padx=2, pady=(6, 0))
        f.columnconfigure(1, weight=1)

        opt = ttk.LabelFrame(root, text="选项")
        opt.pack(fill="x", padx=PAD)
        self.scan_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt, text="扫描子目录", variable=self.scan_var).grid(
            row=0, column=0, sticky="w", padx=6, pady=6)
        self.inbox_move_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt, text="归档后删除解压输出（源压缩包另由下方开关决定）",
                        variable=self.inbox_move_var).grid(row=0, column=1, sticky="w", padx=6, pady=6)
        self.inbox_del_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(opt, text="归档成功后删除源压缩包（建议先确认结果再勾选）",
                        variable=self.inbox_del_var).grid(row=1, column=0, columnspan=2,
                                                          sticky="w", padx=6, pady=(0, 6))
        self.auto_open_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt, text="处理完自动打开刚解压的内容",
                        variable=self.auto_open_var).grid(row=2, column=0, columnspan=2,
                                                          sticky="w", padx=6, pady=(0, 6))

        run = ttk.Frame(root)
        run.pack(fill="x", padx=PAD, pady=PAD)
        self.inbox_btn = ttk.Button(run, text="一键处理", command=self._run_inbox)
        self.inbox_btn.pack(side="left")
        ttk.Button(run, text="预览待处理", command=self._preview_inbox).pack(side="left", padx=6)
        ttk.Button(run, text="查看刚解压的", command=self._open_recent).pack(side="left", padx=(0, 6))
        self.stop_btn = ttk.Button(run, text="停止", command=self._request_stop, state="disabled")
        self.stop_btn.pack(side="left")

        ttk.Label(root,
                  text="一键处理 = 扫描收件目录 → 解压（含套娃）→ 分类归档 → 刷新清单 → "
                       "自动打开刚解压的内容。",
                  foreground="#666", wraplength=940, justify="left").pack(anchor="w", padx=PAD)

    # -- 解压 --------------------------------------------------------------
    def _build_extract(self, root):
        f = ttk.Frame(root)
        f.pack(fill="x", padx=PAD, pady=PAD)

        ttk.Label(f, text="输入文件/文件夹:").grid(row=0, column=0, sticky="w")
        self.src_var = tk.StringVar()
        ttk.Entry(f, textvariable=self.src_var).grid(row=0, column=1, sticky="ew", padx=4)
        ttk.Button(f, text="选择文件", command=self._pick_files).grid(row=0, column=2, padx=2)
        ttk.Button(f, text="选择文件夹", command=self._pick_folder).grid(row=0, column=3, padx=2)

        ttk.Label(f, text="输出目录:").grid(row=1, column=0, sticky="w", pady=(6, 0))
        self.out_var = tk.StringVar(value=os.path.join(DEFAULT_DEST, "_解压输出"))
        ttk.Entry(f, textvariable=self.out_var).grid(row=1, column=1, sticky="ew", padx=4, pady=(6, 0))
        ttk.Button(f, text="选择", command=self._pick_out).grid(row=1, column=2, padx=2, pady=(6, 0))
        f.columnconfigure(1, weight=1)

        opt = ttk.LabelFrame(root, text="选项")
        opt.pack(fill="x", padx=PAD)
        self.recurse_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt, text="自动解内层套娃（分卷 / 压缩包 / 改名包）",
                        variable=self.recurse_var).grid(row=0, column=0, sticky="w", padx=6, pady=6)
        self.subdir_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt, text="扫描子目录", variable=self.subdir_var).grid(
            row=0, column=1, sticky="w", padx=6, pady=6)

        run = ttk.Frame(root)
        run.pack(fill="x", padx=PAD, pady=PAD)
        self.run_btn = ttk.Button(run, text="开始解压", command=self._run_extract)
        self.run_btn.pack(side="left")

        ttk.Label(root, text="密码请到「密码」标签页维护，支持热加载。",
                  foreground="#666").pack(anchor="w", padx=PAD)

    # -- 归档 --------------------------------------------------------------
    def _build_archive(self, root):
        f = ttk.Frame(root)
        f.pack(fill="x", padx=PAD, pady=PAD)

        ttk.Label(f, text="待归档目录:").grid(row=0, column=0, sticky="w")
        self.arc_src = tk.StringVar()
        ttk.Entry(f, textvariable=self.arc_src).grid(row=0, column=1, sticky="ew", padx=4)
        ttk.Button(f, text="选择", command=lambda: self._pick_into(self.arc_src)).grid(row=0, column=2, padx=2)

        ttk.Label(f, text="归档到:").grid(row=1, column=0, sticky="w", pady=(6, 0))
        self.arc_dst = tk.StringVar(value=DEFAULT_DEST)
        ttk.Entry(f, textvariable=self.arc_dst).grid(row=1, column=1, sticky="ew", padx=4, pady=(6, 0))
        ttk.Button(f, text="选择", command=lambda: self._pick_into(self.arc_dst)).grid(row=1, column=2, padx=2, pady=(6, 0))
        f.columnconfigure(1, weight=1)

        opt = ttk.LabelFrame(root, text="规则")
        opt.pack(fill="x", padx=PAD)
        self.move_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt, text="移动（归档后删除源文件；取消则复制保留）",
                        variable=self.move_var).grid(row=0, column=0, sticky="w", padx=6, pady=6)
        ttk.Label(opt, text="图片 → <归档到>\\图片\\   视频 → <归档到>\\视频\\   其他 → <归档到>\\其他\\",
                  foreground="#666").grid(row=1, column=0, sticky="w", padx=6, pady=(0, 6))

        run = ttk.Frame(root)
        run.pack(fill="x", padx=PAD, pady=PAD)
        ttk.Button(run, text="开始归档", command=self._run_archive).pack(side="left")
        ttk.Button(run, text="重建检索清单", command=self._rebuild_index).pack(side="left", padx=6)

    # -- 密码 --------------------------------------------------------------
    def _build_passwords(self, root):
        top = ttk.Frame(root)
        top.pack(fill="x", padx=PAD, pady=PAD)

        ttk.Label(top, text="新增密码:").pack(side="left")
        self.new_pw = tk.StringVar()
        ent = ttk.Entry(top, textvariable=self.new_pw, width=30)
        ent.pack(side="left", padx=6)
        ent.bind("<Return>", lambda e: self._add_pw())
        ttk.Button(top, text="添加", command=self._add_pw).pack(side="left")
        ttk.Button(top, text="删除所选", command=self._del_pw).pack(side="left", padx=6)
        ttk.Button(top, text="从说明文件重新提取", command=self._reload_pw).pack(side="left")

        mid = ttk.Frame(root)
        mid.pack(fill="both", expand=True, padx=PAD)
        self.pw_list = tk.Listbox(mid, height=10, exportselection=False)
        sb = ttk.Scrollbar(mid, command=self.pw_list.yview)
        self.pw_list.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.pw_list.pack(side="left", fill="both", expand=True)

        info = ttk.Frame(root)
        info.pack(fill="x", padx=PAD, pady=PAD)
        ttk.Label(info, text="密码文件:").grid(row=0, column=0, sticky="w")
        self.pw_file_var = tk.StringVar(value=self.pw_store.path)
        ttk.Entry(info, textvariable=self.pw_file_var).grid(row=0, column=1, sticky="ew", padx=4)
        ttk.Button(info, text="选择", command=self._pick_pw_file).grid(row=0, column=2, padx=2)
        info.columnconfigure(1, weight=1)

        note = ("热加载说明：\n"
                "  · 新增的密码会写入密码文件，并立刻对后续压缩包生效（无需重启）。\n"
                "  · 收件目录里任何 .txt 出现「密码:xxx」会被自动提取；\n"
                "    以「密码」开头的目录名也会被识别（例如「解压密码：abc」）。\n"
                "  · 跑批处理时在另一台窗口编辑密码文件，只要保存了也会自动生效。")
        ttk.Label(root, text=note, foreground="#666", justify="left",
                  wraplength=940).pack(anchor="w", padx=PAD, pady=(0, PAD))

    # -- pickers -----------------------------------------------------------
    def _pick_files(self):
        paths = filedialog.askopenfilenames(title="选择要解压的文件")
        if paths:
            self.src_var.set(";".join(paths))

    def _pick_folder(self):
        p = filedialog.askdirectory(title="选择文件夹")
        if p:
            self.src_var.set(p)

    def _pick_out(self):
        p = filedialog.askdirectory(title="选择输出目录")
        if p:
            self.out_var.set(p)

    def _pick_into(self, var: tk.StringVar):
        p = filedialog.askdirectory(title="选择目录")
        if p:
            var.set(p)

    def _pick_pw_file(self):
        p = filedialog.askopenfilename(title="选择密码文件",
                                       filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")])
        if p:
            self.pw_file_var.set(p)
            self.pw_store.path = p
            self.pw_store.reload(force=True)
            self._refresh_pw_list()

    # -- passwords ---------------------------------------------------------
    def _add_pw(self):
        pw = self.new_pw.get().strip()
        if not pw:
            return
        if self.pw_store.add(pw):
            self.new_pw.set("")
            self._refresh_pw_list()
            self.write(f"已添加密码: {pw}")
        else:
            self.write(f"密码已存在: {pw}")

    def _del_pw(self):
        sel = self.pw_list.curselection()
        if not sel:
            return
        pw = self.pw_list.get(sel[0])
        if self.pw_store.remove(pw):
            self._refresh_pw_list()
            self.write(f"已删除密码: {pw}")

    def _reload_pw(self):
        if self.pw_store.reload(force=True):
            self._refresh_pw_list()
            self.write("已从说明文件重新提取密码")
        else:
            self.write("未发现新密码")

    def _refresh_pw_list(self):
        self.pw_list.delete(0, "end")
        for pw in self.pw_store.get():
            self.pw_list.insert("end", pw)

    def _poll_passwords(self):
        """后台轮询密码文件变化 → 真正实现热加载。"""
        try:
            if self.pw_store.reload():
                self._refresh_pw_list()
                self.write(f"密码已更新（当前 {len(self.pw_store.get())} 个）")
        except Exception:
            pass
        self.after(1500, self._poll_passwords)

    # -- logging -----------------------------------------------------------
    def write(self, msg: str):
        self.log.configure(state="normal")
        self.log.insert("end", msg + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _drain(self):
        try:
            while True:
                kind, payload = self.log_q.get_nowait()
                if kind == "log":
                    self.write(str(payload))
                elif kind == "status":
                    self.status.configure(text=str(payload))
                elif kind == "progress":
                    done, total = payload
                    self.pbar.configure(maximum=max(total, 1), value=done)
                elif kind == "done":
                    self.busy = False
                    self.inbox_btn.configure(state="normal")
                    self.run_btn.configure(state="normal")
                    self.stop_btn.configure(state="disabled")
                    self._refresh_pw_list()
        except queue.Empty:
            pass
        self.after(80, self._drain)

    def _request_stop(self):
        self.stop_flag.set()
        self.write("已请求停止，当前包处理完就停。")
        self.stop_btn.configure(state="disabled")

    # -- 收件箱任务 --------------------------------------------------------
    def _open_recent(self):
        """打开最近一次解压的内容（图片优先用看图软件）。"""
        try:
            from . import recent
            msg = recent.open_latest()
        except Exception as exc:
            msg = f"打开失败: {exc}"
        self.write(msg)

    def _preview_inbox(self):
        try:
            import importlib
            inbox_mod = importlib.import_module("收件箱")
            inbox_mod.DEFAULT_INBOX = self.inbox_var.get().strip()
            items = inbox_mod.collect(self.inbox_var.get().strip())
        except Exception as exc:
            messagebox.showerror("错误", f"扫描失败: {exc}")
            return
        if not items:
            self.write("收件箱里没有待处理的压缩包。")
            return
        self.write(f"待处理 {len(items)} 个：")
        for label, path, sources in items:
            n = len(sources)
            extra = f"（{n} 个文件/分卷）" if n > 1 else ""
            self.write(f"   - {label} {extra}")

    def _run_inbox(self):
        if self.busy:
            return
        inbox = self.inbox_var.get().strip()
        dest = self.dest_var.get().strip()
        if not os.path.isdir(inbox):
            messagebox.showwarning("提示", "收件目录不存在")
            return
        if not dest:
            messagebox.showwarning("提示", "请选择归档目标目录")
            return

        self.busy = True
        self.stop_flag.clear()
        self.inbox_btn.configure(state="disabled")
        self.run_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")

        threading.Thread(target=self._worker_inbox,
                         args=(inbox, dest,
                               self.scan_var.get(),
                               self.inbox_move_var.get(),
                               self.inbox_del_var.get()),
                         daemon=True).start()

    def _worker_inbox(self, inbox, dest, scan, move, del_source):
        try:
            import importlib
            inbox_mod = importlib.import_module("收件箱")
            inbox_mod.SKIP_DIRS = set(inbox_mod.SKIP_DIRS)
            items = inbox_mod.collect(inbox)
            if not items:
                self.log_q.put(("log", "收件箱里没有待处理的压缩包。"))
                return

            self.log_q.put(("log", f"收件箱 {inbox}：待处理 {len(items)} 个"))
            staging = os.path.join(inbox_mod.STAGING, "_gui")
            os.makedirs(staging, exist_ok=True)

            pipe = Pipeline(SevenZip(), salvage=True)
            # 传可调用对象 → 每次尝试密码都取最新值（热加载）
            pws = self.pw_store.get

            ok_n = fail_n = 0
            all_works: list[dict] = []
            for i, (label, open_path, sources) in enumerate(items, 1):
                if self.stop_flag.is_set():
                    self.log_q.put(("log", "已停止。"))
                    break
                self.log_q.put(("status", f"处理 {i}/{len(items)}: {label}"))
                self.log_q.put(("log", f"=== [{i}/{len(items)}] {label} ==="))

                outdir = os.path.join(staging, "out")
                workdir = os.path.join(staging, "work")
                shutil.rmtree(outdir, ignore_errors=True)
                shutil.rmtree(workdir, ignore_errors=True)

                res = pipe.process(open_path, workdir, outdir, pws,
                                   log=lambda m: self.log_q.put(("log", "  " + m)),
                                   recurse=True)
                if not res.ok:
                    self.log_q.put(("log", f"  !! 失败: {res.error}"))
                    fail_n += 1
                    continue

                # 安全闸门 1：解压结果必须像样
                src_total = sum(os.path.getsize(s) for s in dict.fromkeys(sources)
                                if os.path.exists(s))
                bad = []
                if res.files == 0:
                    bad.append("没有解出任何文件")
                if res.bytes_ < 1024 * 1024 and src_total > 10 * 1024 * 1024:
                    bad.append(f"解出仅 {res.bytes_} 字节，源包 {_human(src_total)}")
                if src_total and res.bytes_ < src_total * 0.01:
                    bad.append("解出体积不足源包的 1%")
                if bad:
                    self.log_q.put(("log", "  !! 解压结果可疑，保留源文件:"))
                    for b in bad:
                        self.log_q.put(("log", "       - " + b))
                    fail_n += 1
                    continue

                # 归档
                try:
                    works: list[dict] = []
                    moved, mbytes, errors = pipe.archive_by_type(
                        outdir, dest, move=True,
                        log=lambda m: self.log_q.put(("log", "  " + m)),
                        works_out=works)
                except Exception as exc:
                    self.log_q.put(("log", f"  !! 归档异常: {exc}"))
                    fail_n += 1
                    continue

                if errors:
                    self.log_q.put(("log", f"  !! {len(errors)} 个文件未能归档，保留源文件"))
                    for e in errors[:5]:
                        self.log_q.put(("log", "       " + e))
                    fail_n += 1
                    continue

                if del_source:
                    for s in dict.fromkeys(sources):
                        try:
                            os.chmod(s, 0o666)
                        except OSError:
                            pass
                        try:
                            os.remove(s)
                        except OSError:
                            pass
                all_works.extend(works)
                self.log_q.put(("log", f"  -> {res.files} 个文件 / {_human(res.bytes_)}"
                                       + ("  (源包已删除)" if del_source else "  (源包保留)")))
                ok_n += 1

            shutil.rmtree(staging, ignore_errors=True)
            self.log_q.put(("log", f"完成：成功 {ok_n}，失败 {fail_n}"))

            # 记录本次结果，供"查看刚解压的"
            if all_works:
                try:
                    recent.record(dest, all_works)
                except Exception:
                    pass

            # 刷新检索清单
            try:
                idx = importlib.import_module("建索引")
                idx.main_quiet(dest)
            except Exception as exc:
                self.log_q.put(("log", f"清单生成失败（不影响解压）: {exc}"))

            # 一键：处理完直接把刚解压的打开
            if all_works and self.auto_open_var.get():
                self.log_q.put(("log", "正在打开刚解压的内容..."))
                try:
                    self.log_q.put(("log", recent.open_latest()))
                except Exception as exc:
                    self.log_q.put(("log", f"打开失败: {exc}"))
        except Exception as exc:
            self.log_q.put(("log", f"致命错误: {type(exc).__name__}: {exc}"))
        finally:
            self.log_q.put(("status", "完成"))
            self.log_q.put(("done", None))

    # -- 手动解压任务 ------------------------------------------------------
    def _run_extract(self):
        if self.busy:
            return
        src = self.src_var.get().strip()
        if not src:
            messagebox.showwarning("提示", "请先选择要解压的文件或文件夹")
            return
        out = self.out_var.get().strip()
        targets: list[str] = []
        for part in src.split(";"):
            part = part.strip()
            if os.path.isdir(part):
                if self.subdir_var.get():
                    for r, _dirs, fs in os.walk(part):
                        for n in fs:
                            if not n.endswith(".qkdownloading"):
                                targets.append(os.path.join(r, n))
                else:
                    for n in sorted(os.listdir(part)):
                        fp = os.path.join(part, n)
                        if os.path.isfile(fp) and not n.endswith(".qkdownloading"):
                            targets.append(fp)
            elif os.path.isfile(part):
                targets.append(part)
        targets = [t for t in targets if _is_candidate(t)]
        if not targets:
            messagebox.showwarning("提示", "没有找到可处理的文件")
            return

        self.busy = True
        self.stop_flag.clear()
        self.run_btn.configure(state="disabled")
        self.inbox_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        threading.Thread(target=self._worker_extract,
                         args=(targets, out, self.recurse_var.get()), daemon=True).start()

    def _worker_extract(self, targets, out, recurse):
        try:
            pipe = Pipeline(SevenZip())
            workdir = os.path.join(out, "_work")
            pws = self.pw_store.get          # 热加载
            total = len(targets)
            for i, t in enumerate(targets, 1):
                if self.stop_flag.is_set():
                    self.log_q.put(("log", "已停止。"))
                    break
                self.log_q.put(("status", f"处理 {i}/{total}: {os.path.basename(t)}"))
                self.log_q.put(("log", f"=== [{i}/{total}] {t} ==="))
                stem = _stem_name(os.path.basename(t))
                parent = os.path.basename(os.path.dirname(t))
                sub_name = stem if parent in ("", out) else f"{parent}_{stem}"
                sub = os.path.join(out, sub_name)
                res = pipe.process(
                    t, workdir, sub, pws,
                    log=lambda m: self.log_q.put(("log", "  " + m)),
                    progress=lambda d, tt: self.log_q.put(("progress", (d, tt))),
                    recurse=recurse,
                )
                self.log_q.put(("log", f"  -> {'成功' if res.ok else '失败'} {res.error}"))
        except Exception as exc:
            self.log_q.put(("log", f"致命错误: {type(exc).__name__}: {exc}"))
        finally:
            self.log_q.put(("status", "完成"))
            self.log_q.put(("done", None))

    # -- 归档任务 ----------------------------------------------------------
    def _run_archive(self):
        if self.busy:
            return
        src = self.arc_src.get().strip()
        dst = self.arc_dst.get().strip()
        if not src or not os.path.isdir(src):
            messagebox.showwarning("提示", "请选择有效的待归档目录")
            return
        if not dst:
            messagebox.showwarning("提示", "请选择归档目标目录")
            return
        self.busy = True
        self.stop_flag.clear()
        self.inbox_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        threading.Thread(target=self._worker_archive,
                         args=(src, dst, self.move_var.get()), daemon=True).start()

    def _worker_archive(self, src, dst, move):
        try:
            pipe = Pipeline()
            pipe.archive_by_type(
                src, dst,
                log=lambda m: self.log_q.put(("log", m)),
                move=move,
                progress=lambda d, t: self.log_q.put(("progress", (d, t))),
            )
        except Exception as exc:
            self.log_q.put(("log", f"致命错误: {type(exc).__name__}: {exc}"))
        finally:
            self.log_q.put(("status", "完成"))
            self.log_q.put(("done", None))

    def _rebuild_index(self):
        dst = self.arc_dst.get().strip() or self.dest_var.get().strip()
        if not os.path.isdir(dst):
            messagebox.showwarning("提示", "目录不存在")
            return
        try:
            import importlib
            idx = importlib.import_module("建索引")
            idx.main_quiet(dst)
        except Exception as exc:
            self.write(f"清单生成失败: {exc}")


def main():
    App().mainloop()


if __name__ == "__main__":
    main()
