# -*- coding: utf-8 -*-
"""网页视频嗅探器 —— 图形界面。

只有一条嗅探路径：**浏览器嗅探**。
程序会起一个真实的 Edge/Chrome，像一个真人那样把页面打开、让 JS 跑完、
让视频真的播起来，然后问它到底在播什么。

为什么只留这一条：
    静态看 HTML 对抖音这类站点**根本不可能**抓到 —— 实测那类页面 72 KB 里
    连一条 http 链接都没有，地址是 JS 跑起来之后才拿到的。
    与其留一条"看着能用、在大多数站点上失效"的路，不如只有一条能用的。

下载内容可选：视频+音频 / 仅视频 / 仅音频(.m4a) / 仅音频(.mp3)。
"""
from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
import urllib.parse
from tkinter import messagebox, ttk

import engine
from browser import BrowserError, sniff_with_browser

# 打包成 exe 后 __file__ 指向 PyInstaller 的临时解包目录（退出即删），
# downloads / browser_profile 必须落在 exe 旁边。
APP_DIR = os.path.dirname(os.path.abspath(
    sys.executable if getattr(sys, "frozen", False) else __file__))
DEFAULT_OUT = os.path.join(APP_DIR, "downloads")
BROWSER_PROFILE = os.path.join(APP_DIR, "browser_profile")
MAX_WORKERS = 2
DEFAULT_THREADS = 8          # 单个文件的分段下载线程数

# 下拉框：显示文字 -> (模式, 输出扩展名)
MODES = (
    ("视频 + 音频（MP4）", "both", ".mp4"),
    ("仅视频（无声 MP4）", "video", ".mp4"),
    ("仅音频（.m4a 原样，不重编码）", "audio", ".m4a"),
    ("仅音频（.mp3 转码）", "audio", ".mp3"),
)
MODE_LABELS = [m[0] for m in MODES]

STREAM_EXT = {".m3u8": "HLS", ".mpd": "DASH"}


class Candidate:
    """嗅探结果里的一条，纯展示用。"""

    __slots__ = ("url", "ext", "kind", "source", "size", "user_agent",
                 "audio_url")

    def __init__(self, url, ext, source, size=0, user_agent="", audio_url=""):
        self.url = url
        self.ext = ext or ""
        self.kind = STREAM_EXT.get(self.ext, "视频")
        self.source = source
        self.size = size
        self.user_agent = user_agent
        self.audio_url = audio_url

    @property
    def name(self) -> str:
        try:
            path = urllib.parse.urlsplit(self.url).path
        except ValueError:
            path = self.url
        base = urllib.parse.unquote(path.rsplit("/", 1)[-1])
        return base or "(无文件名)"

    def as_row(self):
        size = engine.human_size(self.size) if self.size else "-"
        return (self.kind, self.ext or "-", size, self.source, self.name[:70],
                self.url)


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.ffmpeg = engine.find_ffmpeg()
        self.ffprobe = engine.find_ffprobe(self.ffmpeg)

        self.ui_q = queue.Queue()
        self.task_q = queue.Queue()
        self.tasks = {}                 # task.id -> Task
        self.results = []               # 当前嗅探结果 Candidate 列表
        self.page_url = ""
        self.sniffing = False

        root.title("网页视频嗅探器")
        root.geometry("1020x780")
        root.minsize(860, 640)

        self._build()
        self._start_workers()
        self._pump()

        self.log("嗅探器已就绪。")
        self.log(f"ffmpeg：{self.ffmpeg or '未找到 —— 无法转 MP4 / 合并音视频，请安装并加入 PATH'}")
        self.log("嗅探方式：浏览器嗅探（模拟真人访问，能对付 JS 渲染的站点）")
        self.log(f"下载目录：{DEFAULT_OUT}")
        if not self.ffmpeg:
            messagebox.showwarning(
                "缺少 ffmpeg",
                "没找到 ffmpeg，无法转 MP4 / 去音轨 / 抽音轨。\n\n"
                "安装：winget install Gyan.FFmpeg\n装完重开本程序。")

    # ------------------------------------------------------------------
    # 界面
    # ------------------------------------------------------------------

    def _build(self):
        try:
            import tkinter.font as tkfont
            tkfont.nametofont("TkDefaultFont").configure(
                family="Microsoft YaHei UI", size=9)
        except Exception:
            pass

        root = self.root
        root.columnconfigure(0, weight=1)
        root.rowconfigure(2, weight=3)          # 嗅探结果
        root.rowconfigure(4, weight=2)          # 任务
        root.rowconfigure(6, weight=2)          # 日志

        # --- 网址 + 嗅探 ---
        top = ttk.Frame(root, padding=(10, 10, 10, 4))
        top.grid(row=0, column=0, sticky="ew")
        top.columnconfigure(1, weight=1)
        ttk.Label(top, text="网页地址").grid(row=0, column=0, padx=(0, 6))
        self.url_var = tk.StringVar()
        ent = ttk.Entry(top, textvariable=self.url_var)
        ent.grid(row=0, column=1, sticky="ew")
        ent.bind("<Return>", lambda _e: self.on_browser_sniff())
        self.browser_btn = ttk.Button(top, text="浏览器嗅探", width=14,
                                      command=self.on_browser_sniff)
        self.browser_btn.grid(row=0, column=2, padx=(6, 0))

        # --- 第二行：下载内容 / 线程 / 选项 ---
        opt = ttk.Frame(top)
        opt.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(6, 0))
        ttk.Label(opt, text="下载内容").grid(row=0, column=0, padx=(0, 4))
        self.mode_var = tk.StringVar(value=MODE_LABELS[0])
        ttk.Combobox(opt, textvariable=self.mode_var, width=26, state="readonly",
                     values=MODE_LABELS).grid(row=0, column=1)
        ttk.Label(opt, text="下载线程").grid(row=0, column=2, padx=(16, 4))
        self.threads_var = tk.StringVar(value=str(DEFAULT_THREADS))
        ttk.Combobox(opt, textvariable=self.threads_var, width=4, state="readonly",
                     values=("1", "2", "4", "8", "16", "32")).grid(row=0, column=3)
        self.show_browser_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(opt, text="嗅探时显示浏览器窗口（需要登录 / 过验证时勾上）",
                        variable=self.show_browser_var).grid(row=0, column=4,
                                                             padx=(16, 0))

        self.status_var = tk.StringVar(value="就绪")
        ttk.Label(root, textvariable=self.status_var, foreground="#555",
                  padding=(12, 0, 10, 4)).grid(row=1, column=0, sticky="w")

        # --- 嗅探结果 ---
        box = ttk.LabelFrame(root, text="嗅探结果（可多选，双击直接下载）", padding=6)
        box.grid(row=2, column=0, sticky="nsew", padx=10, pady=4)
        box.columnconfigure(0, weight=1)
        box.rowconfigure(0, weight=1)
        cols = ("kind", "ext", "size", "source", "name", "url")
        self.tree = ttk.Treeview(box, columns=cols, show="headings",
                                 selectmode="extended")
        for key, text, width, stretch in (
                ("kind", "类型", 60, False), ("ext", "后缀", 60, False),
                ("size", "大小", 80, False), ("source", "来源", 130, False),
                ("name", "文件名", 200, False), ("url", "地址", 420, True)):
            self.tree.heading(key, text=text)
            self.tree.column(key, width=width, stretch=stretch, anchor="w")
        self.tree.grid(row=0, column=0, sticky="nsew")
        self.tree.bind("<Double-1>", lambda _e: self.on_download())
        sb = ttk.Scrollbar(box, orient="vertical", command=self.tree.yview)
        sb.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=sb.set)

        # --- 保存为 + 操作 ---
        mid = ttk.Frame(root, padding=(10, 2, 10, 2))
        mid.grid(row=3, column=0, sticky="ew")
        mid.columnconfigure(1, weight=1)
        ttk.Label(mid, text="保存为").grid(row=0, column=0, padx=(0, 6))
        self.title_var = tk.StringVar()
        ttk.Entry(mid, textvariable=self.title_var).grid(row=0, column=1,
                                                         sticky="ew")
        ttk.Button(mid, text="下载选中", width=12,
                   command=self.on_download).grid(row=0, column=2, padx=6)
        ttk.Button(mid, text="打开下载文件夹", width=14,
                   command=self.open_folder).grid(row=0, column=3)
        ttk.Label(mid, foreground="#777",
                  text="按实际体积排序，第一个通常是主视频；多选会自动加文件名区分。"
                  ).grid(row=1, column=1, columnspan=3, sticky="w")

        # --- 任务 ---
        tbox = ttk.LabelFrame(root, text="任务", padding=6)
        tbox.grid(row=4, column=0, sticky="nsew", padx=10, pady=4)
        tbox.columnconfigure(0, weight=1)
        tbox.rowconfigure(0, weight=1)
        tcols = ("name", "status", "pct", "detail")
        self.ttree = ttk.Treeview(tbox, columns=tcols, show="headings",
                                  selectmode="extended")
        for key, text, width, stretch in (
                ("name", "标题", 300, True), ("status", "状态", 120, False),
                ("pct", "进度", 70, False), ("detail", "详情", 330, True)):
            self.ttree.heading(key, text=text)
            self.ttree.column(key, width=width, stretch=stretch, anchor="w")
        self.ttree.grid(row=0, column=0, sticky="nsew")
        self.ttree.bind("<Double-1>", self._open_task_file)
        tsb = ttk.Scrollbar(tbox, orient="vertical", command=self.ttree.yview)
        tsb.grid(row=0, column=1, sticky="ns")
        self.ttree.configure(yscrollcommand=tsb.set)

        tbtn = ttk.Frame(root, padding=(10, 0, 10, 2))
        tbtn.grid(row=5, column=0, sticky="ew")
        ttk.Button(tbtn, text="取消选中任务", width=14,
                   command=self.on_cancel).grid(row=0, column=0)
        ttk.Button(tbtn, text="清空已完成", width=12,
                   command=self.on_clear_done).grid(row=0, column=1, padx=6)
        self.bar = ttk.Progressbar(tbtn, mode="determinate", maximum=100)
        self.bar.grid(row=0, column=2, sticky="ew", padx=(10, 0))
        tbtn.columnconfigure(2, weight=1)

        # --- 日志 ---
        lbox = ttk.LabelFrame(root, text="日志", padding=6)
        lbox.grid(row=6, column=0, sticky="nsew", padx=10, pady=(4, 10))
        lbox.columnconfigure(0, weight=1)
        lbox.rowconfigure(0, weight=1)
        self.logbox = tk.Text(lbox, height=8, wrap="word", state="disabled",
                              background="#fbfbfb", relief="flat")
        self.logbox.grid(row=0, column=0, sticky="nsew")
        lsb = ttk.Scrollbar(lbox, orient="vertical", command=self.logbox.yview)
        lsb.grid(row=0, column=1, sticky="ns")
        self.logbox.configure(yscrollcommand=lsb.set)

    # ------------------------------------------------------------------
    # 日志
    # ------------------------------------------------------------------

    def log(self, msg: str):
        self.logbox.configure(state="normal")
        self.logbox.insert("end", str(msg) + "\n")
        self.logbox.see("end")
        self.logbox.configure(state="disabled")

    def log_async(self, msg: str):
        self.ui_q.put(("log", msg))

    # ------------------------------------------------------------------
    # 工作线程
    # ------------------------------------------------------------------

    def _start_workers(self):
        for _ in range(MAX_WORKERS):
            threading.Thread(target=self._worker, daemon=True).start()

    def _worker(self):
        while True:
            task = self.task_q.get()
            if task is None:
                return
            try:
                engine.run_task(task, self.ffmpeg, self.ffprobe,
                                log=self.log_async)
            finally:
                self.ui_q.put(("task_done", task))

    # ------------------------------------------------------------------
    # 主线程事件泵：唯一的界面刷新点
    # ------------------------------------------------------------------

    def _pump(self):
        try:
            while True:
                kind, payload = self.ui_q.get_nowait()
                if kind == "log":
                    self.log(payload)
                elif kind == "browser_ok":
                    self._show_results(payload)
                elif kind == "browser_err":
                    self._sniff_failed(str(payload))
                elif kind in ("task", "task_done"):
                    self._refresh_task(payload)
                    self._update_bar()
        except queue.Empty:
            pass
        self.root.after(120, self._pump)

    # ------------------------------------------------------------------
    # 浏览器嗅探
    # ------------------------------------------------------------------

    def on_browser_sniff(self):
        if self.sniffing:
            return
        url = self.url_var.get().strip()
        if not url:
            messagebox.showinfo("提示", "请先填网页地址")
            return
        self.sniffing = True
        self.browser_btn.configure(state="disabled")
        self.status_var.set("正在用浏览器打开页面…")
        self.tree.delete(*self.tree.get_children())
        self.results = []
        self.log(f"→ 浏览器嗅探 {url}")
        self.log("  （会临时开一个浏览器把页面跑起来，最长等 30 秒）")
        # 必须在主线程读这个 Tk 变量：子线程碰 Tk 会抛
        # "main thread is not in main loop"
        headless = not self.show_browser_var.get()
        threading.Thread(target=self._browser_worker, args=(url, headless),
                         daemon=True).start()

    def _browser_worker(self, url: str, headless: bool):
        try:
            res = sniff_with_browser(url, BROWSER_PROFILE,
                                     headless=headless, on_log=self.log_async)
        except BrowserError as e:
            self.ui_q.put(("browser_err", str(e)))
        except Exception as e:                       # 兜底，别让线程静默死掉
            self.ui_q.put(("browser_err", f"{type(e).__name__}: {e}"))
        else:
            self.ui_q.put(("browser_ok", res))

    def _sniff_failed(self, msg: str):
        self.sniffing = False
        self.browser_btn.configure(state="normal")
        self.status_var.set("嗅探失败")
        self.log(f"✗ 嗅探失败：{msg}")
        messagebox.showerror("嗅探失败", msg)

    def _show_results(self, res: dict):
        self.sniffing = False
        self.browser_btn.configure(state="normal")
        title = (res.get("title") or "").strip()
        ua = res.get("user_agent") or ""
        items = res.get("urls") or []
        self.page_url = res.get("page_url", "") or self.page_url
        if title:
            self.title_var.set(engine.sanitize(engine.strip_media_ext(title)))

        self.results = [
            Candidate(it["url"], it.get("ext", ""), it.get("source", "浏览器"),
                      size=it.get("bytes", 0), user_agent=ua,
                      audio_url=it.get("audio_url", ""))
            for it in items
        ]
        for c in self.results:
            self.tree.insert("", "end", values=c.as_row())
        kids = self.tree.get_children()
        if kids:
            self.tree.selection_set(kids[0])         # 只选第一个（体积最大的主视频）

        self.status_var.set(f"抓到 {len(self.results)} 个地址")
        if title:
            self.log(f"✓ 页面标题：{title}")
        for c in self.results:
            size = engine.human_size(c.size) if c.size else "?"
            self.log(f"  · [{c.kind}] {size:>9}  {c.name[:56]}  ← {c.source}")
        if not self.results:
            self.log("  ✗ 没抓到任何媒体地址。可勾上「嗅探时显示浏览器窗口」"
                     "看看页面是不是要求登录或过验证码。")
        elif any(c.audio_url for c in self.results):
            self.log("  ⓘ 画面和声音是分开的两条流："
                     "选「视频+音频」会自动补下声音轨再合并")

    # ------------------------------------------------------------------
    # 下载
    # ------------------------------------------------------------------

    def _mode(self):
        try:
            return MODES[MODE_LABELS.index(self.mode_var.get())]
        except (ValueError, IndexError):
            return MODES[0]

    def _new_task(self, url: str, title: str, kind: str, user_agent="",
                  audio_url="", mode="both", audio_ext=".m4a") -> engine.Task:
        try:
            threads = max(1, int(self.threads_var.get()))
        except (TypeError, ValueError):
            threads = DEFAULT_THREADS
        task = engine.Task(url, title, DEFAULT_OUT, kind=kind,
                           referer=self.page_url, threads=threads,
                           user_agent=user_agent, audio_url=audio_url,
                           mode=mode, audio_ext=audio_ext)
        task.notify = lambda t: self.ui_q.put(("task", t))
        self.tasks[task.id] = task
        self.ttree.insert("", "end", iid=task.id,
                          values=(task.title, task.status, "0%", ""))
        return task

    def on_download(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("提示", "先在上面选一个视频")
            return
        label, mode, audio_ext = self._mode()
        base = self.title_var.get().strip() or "video"
        multi = len(sel) > 1
        for iid in sel:
            idx = self.tree.index(iid)
            cand = self.results[idx]
            title = base
            if multi:
                stem = os.path.splitext(cand.name)[0] or f"视频{idx + 1}"
                title = f"{base} - {stem}"
            # 配套声音轨只跟主视频（第一条）绑在一起
            audio = cand.audio_url if idx == 0 else ""
            task = self._new_task(cand.url, title, cand.kind,
                                  user_agent=cand.user_agent, audio_url=audio,
                                  mode=mode, audio_ext=audio_ext)
            self.task_q.put(task)
            self.log(f"+ 加入队列：{task.title}  [{label}]")
        self.status_var.set(f"已加入 {len(sel)} 个任务")

    # ------------------------------------------------------------------
    # 任务显示
    # ------------------------------------------------------------------

    def _refresh_task(self, task: engine.Task):
        if not self.ttree.exists(task.id):
            return
        self.ttree.item(task.id, values=(
            task.title, task.status, f"{task.progress * 100:.0f}%",
            task.error or task.detail))
        self._update_bar()

    def _update_bar(self):
        if not self.tasks:
            self.bar.configure(value=0)
            return
        total = 0.0
        for t in self.tasks.values():
            total += 1.0 if t.status in ("完成", "完成(未转MP4)") else t.progress
        self.bar.configure(value=total / len(self.tasks) * 100)

    def on_cancel(self):
        n = 0
        for iid in self.ttree.selection():
            t = self.tasks.get(iid)
            if t and t.status not in ("完成", "失败", "已取消", "完成(未转MP4)"):
                t.cancel.set()
                n += 1
        if n:
            self.log(f"已请求取消 {n} 个任务")

    def on_clear_done(self):
        for tid, t in list(self.tasks.items()):
            if t.status in ("完成", "失败", "已取消", "完成(未转MP4)"):
                if self.ttree.exists(tid):
                    self.ttree.delete(tid)
                del self.tasks[tid]
        self._update_bar()

    def _open_task_file(self, _event=None):
        sel = self.ttree.selection()
        if not sel:
            return
        t = self.tasks.get(sel[0])
        if t and t.out_path and os.path.isfile(t.out_path):
            self._reveal(t.out_path)

    # ------------------------------------------------------------------
    # 杂项
    # ------------------------------------------------------------------

    def open_folder(self):
        os.makedirs(DEFAULT_OUT, exist_ok=True)
        self._reveal(DEFAULT_OUT)

    @staticmethod
    def _reveal(path: str):
        try:
            if os.path.isdir(path):
                os.startfile(path)                       # noqa: S606
            else:
                subprocess.Popen(["explorer", "/select,", os.path.normpath(path)])
        except Exception as e:
            messagebox.showerror("打不开", str(e))


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    sys.exit(main())
