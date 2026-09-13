# -*- coding: utf-8 -*-
"""
网页视频嗅探下载器 —— 图形界面。

用发：
  1. 上面填网页地址，点「嗅探」
  2. 下面列出嗅探到的视频，选一个或多个
  3. 填好「保存为」（默认就是网页标题），点「下载选中」
  4. 下完自动转成 MP4，落在 downloads/ 里

抓不到的站点（YouTube / B 站这类 JS 渲染的）点「yt-dlp 下载」。
"""
from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import messagebox, ttk

import engine
import sniffer
from browser import BrowserError, sniff_with_browser

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUT = os.path.join(APP_DIR, "downloads")
BROWSER_PROFILE = os.path.join(APP_DIR, "browser_profile")
MAX_WORKERS = 2
DEFAULT_THREADS = 8          # 单个文件的分段下载线程数


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.ffmpeg = engine.find_ffmpeg()
        self.ffprobe = engine.find_ffprobe(self.ffmpeg)
        self.ytdlp = engine.find_ytdlp()

        self.ui_q = queue.Queue()
        self.task_q = queue.Queue()
        self.tasks = {}                 # task.id -> Task
        self.results = []               # 当前嗅探结果 Candidate 列表
        self.page_url = ""              # 用作 Referer
        self.browser_audio = ""         # 浏览器嗅探发现音视频分流时的声音轨地址
        self.active = 0

        root.title("网页视频嗅探器")
        root.geometry("980x760")
        root.minsize(820, 620)

        self._build()
        self._start_workers()
        self._pump()

        self.log("嗅探器已就绪。")
        self.log(f"ffmpeg：{self.ffmpeg or '未找到 —— 无法转 MP4，请安装 ffmpeg 并加入 PATH'}")
        self.log(f"yt-dlp：{self.ytdlp or '未找到 —— 大站兜底不可用（安装：winget install yt-dlp.yt-dlp）'}")
        self.log(f"下载线程：{DEFAULT_THREADS}（单个文件分段并发，可在界面上改）")
        self.log(f"下载目录：{DEFAULT_OUT}")
        if not self.ffmpeg:
            messagebox.showwarning(
                "缺少 ffmpeg",
                "没找到 ffmpeg，下载后无法转成 MP4（会保留原格式）。\n\n"
                "安装：winget install Gyan.FFmpeg\n装完重开本程序。")

    # ------------------------------------------------------------------
    # 界面
    # ------------------------------------------------------------------

    def _build(self):
        try:
            import tkinter.font as tkfont
            f = tkfont.nametofont("TkDefaultFont")
            f.configure(family="Microsoft YaHei UI", size=9)
        except Exception:
            pass

        root = self.root
        root.columnconfigure(0, weight=1)
        root.rowconfigure(2, weight=3)          # 嗅探结果
        root.rowconfigure(4, weight=2)          # 任务
        root.rowconfigure(6, weight=2)          # 日志

        # --- 网址输入 ---
        top = ttk.Frame(root, padding=(10, 10, 10, 4))
        top.grid(row=0, column=0, sticky="ew")
        top.columnconfigure(1, weight=1)
        ttk.Label(top, text="网页地址").grid(row=0, column=0, padx=(0, 6))
        self.url_var = tk.StringVar()
        ent = ttk.Entry(top, textvariable=self.url_var)
        ent.grid(row=0, column=1, sticky="ew")
        ent.bind("<Return>", lambda _e: self.on_sniff())
        self.sniff_btn = ttk.Button(top, text="嗅探", width=8, command=self.on_sniff)
        self.sniff_btn.grid(row=0, column=2, padx=(6, 4))
        self.browser_btn = ttk.Button(top, text="浏览器嗅探", width=13,
                                      command=self.on_browser_sniff)
        self.browser_btn.grid(row=0, column=3, padx=4)
        self.ytdlp_top_btn = ttk.Button(top, text="yt-dlp 下载", width=13,
                                        command=self.on_ytdlp)
        self.ytdlp_top_btn.grid(row=0, column=4, padx=(4, 0))

        # 第二行：Cookie 与浏览器选项
        ttk.Label(top, text="Cookie").grid(row=1, column=0, sticky="w", pady=(6, 0))
        self.cookie_var = tk.StringVar(value="不使用")
        ttk.Combobox(top, textvariable=self.cookie_var, width=9, state="readonly",
                     values=("不使用", "edge", "chrome", "firefox", "brave")).grid(
            row=1, column=1, sticky="w", pady=(6, 0))
        self.cookie_file = ""
        self.cookie_btn = ttk.Button(top, text="Cookie 文件…", width=13,
                                     command=self.on_cookie_btn)
        self.cookie_btn.grid(row=1, column=2, padx=(6, 4), pady=(6, 0))
        self.show_browser_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="浏览器嗅探时显示窗口（需要登录/过验证时勾上）",
                        variable=self.show_browser_var).grid(
            row=1, column=3, columnspan=2, sticky="w", padx=4, pady=(6, 0))

        self.status_var = tk.StringVar(value="就绪")
        ttk.Label(root, textvariable=self.status_var, foreground="#555",
                  padding=(12, 0, 10, 4)).grid(row=1, column=0, sticky="w")

        # --- 嗅探结果 ---
        box = ttk.LabelFrame(root, text="嗅探结果（可多选，双击直接下载）", padding=6)
        box.grid(row=2, column=0, sticky="nsew", padx=10, pady=4)
        box.columnconfigure(0, weight=1)
        box.rowconfigure(0, weight=1)

        cols = ("kind", "ext", "source", "name", "url")
        self.tree = ttk.Treeview(box, columns=cols, show="headings",
                                 selectmode="extended")
        for key, text, width, stretch in (
                ("kind", "类型", 70, False), ("ext", "后缀", 60, False),
                ("source", "来源", 110, False), ("name", "文件名", 220, False),
                ("url", "地址", 460, True)):
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
        ttk.Entry(mid, textvariable=self.title_var).grid(row=0, column=1, sticky="ew")
        self.dl_btn = ttk.Button(mid, text="下载选中", width=12,
                                 command=self.on_download)
        self.dl_btn.grid(row=0, column=2, padx=6)
        ttk.Button(mid, text="打开下载文件夹", width=14,
                   command=self.open_folder).grid(row=0, column=3)
        ttk.Label(mid, text="下载线程").grid(row=1, column=0, sticky="w", pady=(4, 0))
        self.threads_var = tk.StringVar(value=str(DEFAULT_THREADS))
        ttk.Combobox(mid, textvariable=self.threads_var, width=4, state="readonly",
                     values=("1", "2", "4", "8", "16", "32")).grid(
            row=1, column=1, sticky="w", pady=(4, 0))
        ttk.Label(mid, foreground="#777",
                  text="多线程分段下载（服务器不支持 Range 时自动退回单线程）；"
                       "多选下载会自动加文件名区分。").grid(
            row=1, column=2, columnspan=2, sticky="w", pady=(4, 0))

        # --- 任务 ---
        tbox = ttk.LabelFrame(root, text="任务", padding=6)
        tbox.grid(row=4, column=0, sticky="nsew", padx=10, pady=4)
        tbox.columnconfigure(0, weight=1)
        tbox.rowconfigure(0, weight=1)
        tcols = ("name", "status", "pct", "detail")
        self.ttree = ttk.Treeview(tbox, columns=tcols, show="headings",
                                  selectmode="extended")
        for key, text, width, stretch in (
                ("name", "标题", 300, True), ("status", "状态", 110, False),
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
    # 日志 / 状态
    # ------------------------------------------------------------------

    def log(self, msg: str):
        self.logbox.configure(state="normal")
        self.logbox.insert("end", msg + "\n")
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
                engine.run_task(task, self.ffmpeg, self.ffprobe, self.ytdlp,
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
                elif kind == "sniff_ok":
                    self._show_results(payload)
                elif kind == "browser_ok":
                    self._show_browser_results(payload)
                elif kind == "browser_err":
                    self.browser_btn.configure(state="normal")
                    self.sniff_btn.configure(state="normal")
                    self.status_var.set("浏览器嗅探失败")
                    self.log(f"✗ 浏览器嗅探失败：{payload}")
                    messagebox.showerror("浏览器嗅探失败", str(payload))
                elif kind == "sniff_err":
                    self.sniff_btn.configure(state="normal")
                    self.status_var.set("嗅探失败")
                    self.log(f"✗ 嗅探失败：{payload}")
                    messagebox.showerror("嗅探失败", payload)
                elif kind == "task":
                    self._refresh_task(payload)
                elif kind == "task_done":
                    self._refresh_task(payload)
                    self._update_bar()
        except queue.Empty:
            pass
        self.root.after(120, self._pump)

    # ------------------------------------------------------------------
    # 嗅探
    # ------------------------------------------------------------------

    def on_sniff(self):
        url = self.url_var.get().strip()
        if not url:
            messagebox.showinfo("提示", "请先填网页地址")
            return
        self.sniff_btn.configure(state="disabled")
        self.status_var.set("嗅探中…")
        self.tree.delete(*self.tree.get_children())
        self.results = []
        self.log(f"→ 嗅探 {url}")
        threading.Thread(target=self._sniff_worker, args=(url,), daemon=True).start()

    def _sniff_worker(self, url: str):
        try:
            res = sniffer.sniff(url)
        except sniffer.SniffError as e:
            self.ui_q.put(("sniff_err", str(e)))
        except Exception as e:                       # 兜底，别让线程静默死掉
            self.ui_q.put(("sniff_err", f"{type(e).__name__}: {e}"))
        else:
            self.ui_q.put(("sniff_ok", res))

    def _show_results(self, res: sniffer.SniffResult):
        self.sniff_btn.configure(state="normal")
        self.results = res.candidates
        self.page_url = res.final_url
        self.browser_audio = ""      # 静态嗅探的结果没有配套声音轨，清掉上一次的
        self.title_var.set(engine.sanitize(engine.strip_media_ext(res.title)))
        for c in res.candidates:
            self.tree.insert("", "end", values=c.as_row())
        kids = self.tree.get_children()
        if kids:
            self.tree.selection_set(kids)            # 默认全选，省一次点击
        self.status_var.set(f"嗅探到 {len(res.candidates)} 个视频")
        self.log(f"✓ 页面标题：{res.title}")
        if res.note:
            self.log(f"  {res.note}")
        for c in res.candidates:
            self.log(f"  · [{c.kind}] {c.name}  ← {c.source}")

    # ------------------------------------------------------------------
    # 浏览器嗅探（模拟真人）
    # ------------------------------------------------------------------

    def on_browser_sniff(self):
        """用真实浏览器把页面跑起来，问它到底在播什么。

        静态嗅探对 JS 站点（抖音等）注定抓不到 —— HTML 里根本没有地址。
        """
        url = self.url_var.get().strip()
        if not url:
            messagebox.showinfo("提示", "请先填网页地址")
            return
        self.browser_btn.configure(state="disabled")
        self.sniff_btn.configure(state="disabled")
        self.status_var.set("正在用浏览器打开页面…")
        self.tree.delete(*self.tree.get_children())
        self.results = []
        self.log(f"→ 浏览器嗅探 {url}")
        self.log("  （会临时开一个浏览器窗口把页面跑起来，最长等 30 秒）")
        threading.Thread(target=self._browser_worker, args=(url,),
                         daemon=True).start()

    def _browser_worker(self, url: str):
        try:
            res = sniff_with_browser(
                url, BROWSER_PROFILE,
                headless=not self.show_browser_var.get(),
                on_log=self.log_async)
        except BrowserError as e:
            self.ui_q.put(("browser_err", str(e)))
        except Exception as e:                       # 兜底，别让线程静默死掉
            self.ui_q.put(("browser_err", f"{type(e).__name__}: {e}"))
        else:
            self.ui_q.put(("browser_ok", res))

    def _show_browser_results(self, res: dict):
        self.browser_btn.configure(state="normal")
        self.sniff_btn.configure(state="normal")
        title = res.get("title") or ""
        ua = res.get("user_agent") or ""
        urls = res.get("urls") or []
        self.page_url = res.get("page_url", "") or self.page_url
        if title:
            self.title_var.set(engine.sanitize(engine.strip_media_ext(title)))
        self.results = [
            sniffer.Candidate(item["url"], sniffer.guess_ext(item["url"]),
                              item["source"], user_agent=ua,
                              size=item.get("bytes", 0))
            for item in urls
        ]
        # 主视频只有画面（DASH 拆流）时，把配套的声音地址记上，下载时一起合
        self.browser_audio = ""
        for item in urls:
            if item.get("audio_url"):
                self.browser_audio = item["audio_url"]
                self.log("  ⓘ 这是分开的音视频流，下载时会自动补下声音轨再合并")
                break
        for c in self.results:
            self.tree.insert("", "end", values=c.as_row())
        kids = self.tree.get_children()
        if kids:
            self.tree.selection_set(kids[:1])        # 只选第一个（正在播的那个）
        self.status_var.set(f"浏览器抓到 {len(self.results)} 个地址")
        if title:
            self.log(f"✓ 页面标题：{title}")
        for c in self.results:
            mark = f"  {engine.human_size(c.size)}" if c.size else ""
            self.log(f"  · [{c.kind}] {c.name[:60]}{mark}  ← {c.source}")
        if not self.results:
            self.log("  ✗ 页面里没抓到任何媒体地址。"
                     "可以勾上「显示浏览器窗口」看看页面是不是要求登录/过验证码。")
        else:
            self.log("  （按实际传输量排序，第一个通常就是主视频；"
                     "选中哪一个就下哪一个）")

    # ------------------------------------------------------------------
    # 下载
    # ------------------------------------------------------------------

    def _refresh_tools(self):
        """工具可能是程序启动之后才装上的，用之前再找一次。"""
        self.ffmpeg = engine.find_ffmpeg()
        self.ffprobe = engine.find_ffprobe(self.ffmpeg)
        self.ytdlp = engine.find_ytdlp()

    def _cookies(self) -> str:
        v = self.cookie_var.get()
        return "" if v == "不使用" else v

    def on_cookie_btn(self):
        """一个按钮两用：没选文件时选文件，选了就变成清除。"""
        if self.cookie_file:
            self.cookie_file = ""
            self.cookie_btn.configure(text="Cookie 文件…")
            self.log("已清除 Cookie 文件")
        else:
            self.on_pick_cookie_file()

    def on_pick_cookie_file(self):
        """选一个手动导出的 cookies.txt。

        浏览器 Cookie 库在 Chrome/Edge 127+ 之后加了应用绑定加密，
        yt-dlp 直接读会报 "Failed to decrypt with DPAPI"。
        手动导出的 Netscape 格式文件是明文，绕开这个问题。
        """
        from tkinter import filedialog
        path = filedialog.askopenfilename(
            title="选择 cookies.txt（Netscape 格式）",
            filetypes=[("Cookie 文件", "*.txt"), ("所有文件", "*.*")])
        if not path:
            return
        self.cookie_file = path
        self.cookie_btn.configure(text="清除 Cookie")
        self.log(f"已选择 Cookie 文件：{path}")
        self.log("  （比右上角的下拉框优先使用）")

    def _new_task(self, url: str, title: str, kind: str, use_ytdlp=False,
                  keep_source_title=False, user_agent="", cookie="",
                  audio_url="") -> engine.Task:
        try:
            threads = max(1, int(self.threads_var.get()))
        except (TypeError, ValueError):
            threads = DEFAULT_THREADS
        task = engine.Task(url, title, DEFAULT_OUT, kind=kind,
                           referer=self.page_url, use_ytdlp=use_ytdlp,
                           keep_source_title=keep_source_title, threads=threads,
                           cookies_from=self._cookies() if use_ytdlp else "",
                           cookies_file=self.cookie_file if use_ytdlp else "",
                           user_agent=user_agent, cookie=cookie,
                           audio_url=audio_url)
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
        self._refresh_tools()
        base = self.title_var.get().strip() or "video"
        multi = len(sel) > 1
        for iid in sel:
            idx = self.tree.index(iid)
            cand = self.results[idx]
            title = base
            if multi:
                stem = os.path.splitext(cand.name)[0] or f"视频{idx + 1}"
                title = f"{base} - {stem}"
            # 只有主视频（第一个）才需要补声音轨
            audio = self.browser_audio if idx == 0 else ""
            task = self._new_task(cand.url, title, cand.kind,
                                  user_agent=cand.user_agent,
                                  cookie=cand.cookie, audio_url=audio)
            self.task_q.put(task)
            self.log(f"+ 加入队列：{task.title}  [{cand.kind}]")
        self.status_var.set(f"已加入 {len(sel)} 个任务")

    def on_ytdlp(self):
        """用 yt-dlp 处理当前网址（或结果里选中的那一条）。"""
        self._refresh_tools()
        url = self.url_var.get().strip()
        title = self.title_var.get().strip() or "video"
        sel = self.tree.selection()
        if sel:
            cand = self.results[self.tree.index(sel[0])]
            url = cand.url
        if not url:
            messagebox.showinfo("提示", "请先填网页地址")
            return
        if not self.ytdlp:
            messagebox.showwarning(
                "没找到 yt-dlp",
                "yt-dlp 兜底需要先安装，任选一条命令：\n\n"
                "  pip install -U yt-dlp\n"
                "  winget install yt-dlp.yt-dlp\n\n"
                "装完重开本程序。\n"
                "（注意：winget 装的可能不在 PATH 里，pip 更稳）")
            return
        ck = self._cookies()
        task = self._new_task(url, title, "yt-dlp", use_ytdlp=True,
                              keep_source_title=True)
        self.task_q.put(task)
        src = ""
        if self.cookie_file:
            src = f"（用 Cookie 文件 {os.path.basename(self.cookie_file)}）"
        elif ck:
            src = f"（用 {ck} 的 Cookie）"
        self.log(f"+ 交给 yt-dlp：{url}{src}")

    # ------------------------------------------------------------------
    # 任务显示
    # ------------------------------------------------------------------

    def _refresh_task(self, task: engine.Task):
        if not self.ttree.exists(task.id):
            return
        pct = f"{task.progress * 100:.0f}%"
        detail = task.error or task.detail
        self.ttree.item(task.id, values=(task.title, task.status, pct, detail))
        self._update_bar()

    def _update_bar(self):
        running = [t for t in self.tasks.values()
                   if t.status not in ("完成", "失败", "已取消", "完成(未转MP4)")]
        if running:
            done = sum(t.progress for t in self.tasks.values()
                       if t.status in ("完成", "完成(未转MP4)"))
            total = len(self.tasks)
            self.bar.configure(value=(done + sum(t.progress for t in running)) /
                                     max(1, total) * 100)
        else:
            finished = [t for t in self.tasks.values() if t.status.startswith("完成")]
            self.bar.configure(value=100 if finished and
                               len(finished) == len(self.tasks) else 0)

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
