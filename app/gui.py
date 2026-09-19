"""Tkinter GUI for the universal extractor / archiver."""

from __future__ import annotations

import os
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .pipeline import Pipeline
from .sevenzip import SevenZip, find_7za

PAD = 8


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("通用解压归档助手")
        self.geometry("980x680")
        self.minsize(820, 560)

        self.log_q: queue.Queue[tuple[str, object]] = queue.Queue()
        self.busy = False
        self._build()
        self.after(80, self._drain)

    # -- layout ------------------------------------------------------------
    def _build(self):
        style = ttk.Style(self)
        try:
            style.theme_use("vista")
        except tk.TclError:
            pass

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=PAD, pady=PAD)

        self.tab_extract = ttk.Frame(nb)
        self.tab_archive = ttk.Frame(nb)
        nb.add(self.tab_extract, text="解压")
        nb.add(self.tab_archive, text="分类归档")

        self._build_extract(self.tab_extract)
        self._build_archive(self.tab_archive)

        # shared log
        box = ttk.LabelFrame(self, text="日志")
        box.pack(fill="both", expand=False, padx=PAD, pady=(0, PAD))
        self.log = tk.Text(box, height=10, wrap="word", state="disabled")
        sb = ttk.Scrollbar(box, command=self.log.yview)
        self.log.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.log.pack(side="left", fill="both", expand=True)

        self.status = ttk.Label(self, text="就绪", anchor="w")
        self.status.pack(fill="x", padx=PAD, pady=(0, PAD))

        if not find_7za():
            self.write("警告: 未找到 7za.exe，解压功能不可用。请把 7za.exe 放到 bin 目录。")

    def _build_extract(self, root):
        f = ttk.Frame(root)
        f.pack(fill="x", padx=PAD, pady=PAD)

        ttk.Label(f, text="输入文件/文件夹:").grid(row=0, column=0, sticky="w")
        self.src_var = tk.StringVar()
        ttk.Entry(f, textvariable=self.src_var).grid(row=0, column=1, sticky="ew", padx=4)
        ttk.Button(f, text="选择文件", command=self._pick_files).grid(row=0, column=2, padx=2)
        ttk.Button(f, text="选择文件夹", command=self._pick_folder).grid(row=0, column=3, padx=2)

        ttk.Label(f, text="输出目录:").grid(row=1, column=0, sticky="w", pady=(6, 0))
        self.out_var = tk.StringVar(value=os.path.join(os.path.expanduser("~"), "Downloads", "解压输出"))
        ttk.Entry(f, textvariable=self.out_var).grid(row=1, column=1, sticky="ew", padx=4, pady=(6, 0))
        ttk.Button(f, text="选择", command=self._pick_out).grid(row=1, column=2, padx=2, pady=(6, 0))

        f.columnconfigure(1, weight=1)

        opt = ttk.LabelFrame(root, text="选项")
        opt.pack(fill="x", padx=PAD)
        self.pw_var = tk.StringVar()
        ttk.Label(opt, text="密码(每行一个，可留空):").grid(row=0, column=0, sticky="nw", padx=6, pady=6)
        self.pw_text = tk.Text(opt, height=4, width=40)
        self.pw_text.grid(row=0, column=1, sticky="ew", padx=6, pady=6)
        opt.columnconfigure(1, weight=1)

        self.recurse_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt, text="自动处理嵌套分卷 (.001/.z01)", variable=self.recurse_var).grid(
            row=1, column=1, sticky="w", padx=6, pady=(0, 6))

        run = ttk.Frame(root)
        run.pack(fill="x", padx=PAD, pady=PAD)
        self.run_btn = ttk.Button(run, text="开始解压", command=self._run_extract)
        self.run_btn.pack(side="left")
        self.pbar = ttk.Progressbar(run, mode="determinate")
        self.pbar.pack(side="left", fill="x", expand=True, padx=PAD)

        drop = ttk.Label(root, text="提示: 支持伪装包（mp4/jpg 外观）自动还原、分卷、加密。",
                         foreground="#666")
        drop.pack(anchor="w", padx=PAD)

    def _build_archive(self, root):
        f = ttk.Frame(root)
        f.pack(fill="x", padx=PAD, pady=PAD)

        ttk.Label(f, text="待归档目录:").grid(row=0, column=0, sticky="w")
        self.arc_src = tk.StringVar()
        ttk.Entry(f, textvariable=self.arc_src).grid(row=0, column=1, sticky="ew", padx=4)
        ttk.Button(f, text="选择", command=lambda: self._pick_into(self.arc_src)).grid(row=0, column=2, padx=2)

        ttk.Label(f, text="归档到:").grid(row=1, column=0, sticky="w", pady=(6, 0))
        self.arc_dst = tk.StringVar(value="H:\\赏花阁")
        ttk.Entry(f, textvariable=self.arc_dst).grid(row=1, column=1, sticky="ew", padx=4, pady=(6, 0))
        ttk.Button(f, text="选择", command=lambda: self._pick_into(self.arc_dst)).grid(row=1, column=2, padx=2, pady=(6, 0))
        f.columnconfigure(1, weight=1)

        opt = ttk.LabelFrame(root, text="规则")
        opt.pack(fill="x", padx=PAD)
        self.move_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt, text="移动（归档后删除源文件；取消则复制保留）",
                        variable=self.move_var).grid(row=0, column=0, sticky="w", padx=6, pady=6)
        ttk.Label(opt, text="图片 → <归档到>\\图片\\  视频 → <归档到>\\视频\\",
                  foreground="#666").grid(row=1, column=0, sticky="w", padx=6, pady=(0, 6))

        run = ttk.Frame(root)
        run.pack(fill="x", padx=PAD, pady=PAD)
        ttk.Button(run, text="开始归档", command=self._run_archive).pack(side="left")
        self.pbar2 = ttk.Progressbar(run, mode="determinate")
        self.pbar2.pack(side="left", fill="x", expand=True, padx=PAD)

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
                    done, total = payload  # type: ignore[misc]
                    self.pbar.configure(maximum=max(total, 1), value=done)
                    self.pbar2.configure(maximum=max(total, 1), value=done)
                elif kind == "done":
                    self.busy = False
                    self.run_btn.configure(state="normal")
        except queue.Empty:
            pass
        self.after(80, self._drain)

    # -- jobs --------------------------------------------------------------
    def _passwords(self) -> list[str]:
        raw = self.pw_text.get("1.0", "end")
        return [ln.strip() for ln in raw.splitlines() if ln.strip()]

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
                for n in sorted(os.listdir(part)):
                    fp = os.path.join(part, n)
                    if os.path.isfile(fp):
                        targets.append(fp)
            elif os.path.isfile(part):
                targets.append(part)
        if not targets:
            messagebox.showwarning("提示", "没有找到可处理的文件")
            return

        self.busy = True
        self.run_btn.configure(state="disabled")
        pwds = self._passwords()
        recurse = self.recurse_var.get()
        threading.Thread(target=self._worker_extract,
                         args=(targets, out, pwds, recurse), daemon=True).start()

    def _worker_extract(self, targets, out, pwds, recurse):
        try:
            sz = SevenZip()
            pipe = Pipeline(sz)
            workdir = os.path.join(out, "_work")
            total = len(targets)
            for i, t in enumerate(targets, 1):
                self.log_q.put(("status", f"处理 {i}/{total}: {os.path.basename(t)}"))
                self.log_q.put(("log", f"=== [{i}/{total}] {t} ==="))
                stem = os.path.splitext(os.path.basename(t))[0]
                sub = os.path.join(out, stem)
                res = pipe.process(
                    t, workdir, sub, pwds,
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
        self.run_btn.configure(state="disabled")
        move = self.move_var.get()
        threading.Thread(target=self._worker_archive, args=(src, dst, move), daemon=True).start()

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


def main():
    App().mainloop()


if __name__ == "__main__":
    main()
