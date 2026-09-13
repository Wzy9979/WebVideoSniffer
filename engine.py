# -*- coding: utf-8 -*-
"""
下载引擎：直链下载 / HLS 拉流 → ffmpeg 转 MP4 → yt-dlp 兜底。

只依赖标准库 + 外部程序 ffmpeg / yt-dlp。
所有外部进程都用 CREATE_NO_WINDOW 启动，不会闪黑框。
"""
from __future__ import annotations

from typing import NamedTuple

import json
import os
import re
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import sniffer

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")

CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0

MANIFEST_EXTS = {".m3u8", ".mpd", ".ism"}
MEDIA_EXTS = {
    ".mp4", ".m4v", ".mkv", ".webm", ".flv", ".mov", ".avi", ".wmv",
    ".mpg", ".mpeg", ".3gp", ".f4v", ".ogv", ".rmvb", ".rm", ".asf",
    ".vob", ".amv", ".divx", ".mts", ".m2ts", ".ts", ".m4s",
}

# 能被 MP4 容器"正常播放"的编码。
# 关键：ffmpeg 能把几乎任何编码塞进 MP4（PCM、DTS 都写得进去），但播放器放不出来。
# 所以能不能 -c copy，取决于编码在不在这个白名单里，而不是 ffmpeg 成不成功。
MP4_SAFE_VIDEO = {"h264", "hevc", "av1", "mpeg4", "vp9"}
MP4_SAFE_AUDIO = {"aac", "mp3", "ac3", "eac3", "alac"}


class Canceled(Exception):
    """用户取消。"""


class EngineError(Exception):
    """下载 / 转码过程中的可预期失败。"""


class _NoRangeSupport(Exception):
    """服务器嘴上支持分段，实际返回整份内容 —— 内部信号，退回单线程。"""


# 分片下载参数
CHUNK = 256 * 1024
SEGMENT_MIN_BYTES = 1024 * 1024            # 单个分片小于这个就不值得再切
SEGMENT_MIN_TOTAL = 2 * 1024 * 1024        # 整个文件小于这个直接单线程


# --------------------------------------------------------------------------
# 外部程序定位
# --------------------------------------------------------------------------

def find_ffmpeg() -> str:
    for name in ("ffmpeg", "ffmpeg.exe"):
        p = shutil.which(name)
        if p:
            return p
    return ""


def find_ffprobe(ffmpeg_path: str = "") -> str:
    p = shutil.which("ffprobe") or shutil.which("ffprobe.exe")
    if p:
        return p
    if ffmpeg_path:                                  # 同目录下的 ffprobe
        cand = os.path.join(os.path.dirname(ffmpeg_path), "ffprobe.exe")
        if os.path.isfile(cand):
            return cand
    return ""


def find_ytdlp() -> str:
    for name in ("yt-dlp", "yt-dlp.exe", "youtube-dl", "youtube-dl.exe"):
        p = shutil.which(name)
        if p:
            return p
    return ""


def find_node() -> str:
    """yt-dlp 解 YouTube 的 JS 挑战需要一个 JS 运行时。

    它默认只认 deno，但机器上通常已经有 node —— 直接拿来用，不必再装 deno。
    """
    for name in ("node", "node.exe"):
        p = shutil.which(name)
        if p:
            return p
    return ""


# --------------------------------------------------------------------------
# 小工具
# --------------------------------------------------------------------------

_ILLEGAL_RX = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
_RESERVED = {"CON", "PRN", "AUX", "NUL"} | {f"COM{i}" for i in range(1, 10)} | \
            {f"LPT{i}" for i in range(1, 10)}


def sanitize(name: str, max_len: int = 120) -> str:
    """清洗成 Windows 上能安全落盘的文件名（不含目录、不含扩展名）。"""
    name = _ILLEGAL_RX.sub(" ", name or "")
    name = re.sub(r"\s+", " ", name).strip(" .")
    if len(name) > max_len:
        name = name[:max_len].rstrip(" .") + "…"
    if not name:
        name = "video"
    if name.split(".")[0].upper() in _RESERVED:
        name = "_" + name
    return name


def strip_media_ext(title: str) -> str:
    """标题自带扩展名时去掉，免得存成 xxx.mp4.mp4。"""
    low = title.lower()
    for ext in sorted(MEDIA_EXTS, key=len, reverse=True):
        if low.endswith(ext) and len(title) > len(ext) + 1:
            return title[:-len(ext)].rstrip(" .")
    return title


def unique_path(path: str) -> str:
    """目标已存在则追加 (2)、(3)……"""
    if not os.path.exists(path):
        return path
    root, ext = os.path.splitext(path)
    i = 2
    while os.path.exists(f"{root} ({i}){ext}"):
        i += 1
    return f"{root} ({i}){ext}"


def ext_of(url: str) -> str:
    try:
        path = urllib.parse.urlsplit(url).path
    except ValueError:
        return ""
    m = re.search(r"\.([A-Za-z0-9]{2,5})$", path)
    return "." + m.group(1).lower() if m else ""


def human_size(n) -> str:
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "?"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{int(n)} B" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return "?"


class FetchOpts(NamedTuple):
    """一次取数要带的请求头。referer/UA/Cookie 三者要一起传，所以打成一包。"""

    referer: str = ""
    user_agent: str = ""
    cookie: str = ""


def _headers_block(referer: str, user_agent: str = "",
                   cookie: str = "") -> str:
    """ffmpeg 的 -headers 需要一整块 \\r\\n 分隔的文本。"""
    lines = [f"User-Agent: {user_agent or UA}"]
    if referer:
        lines.append(f"Referer: {referer}")
    if cookie:
        lines.append(f"Cookie: {cookie}")
    return "".join(line + "\r\n" for line in lines)


def _request(url: str, opts=None):
    """opts 见 FetchOpts。带上真实浏览器的 UA 很重要：
    有些 CDN 的签名地址是跟 UA 绑定的，UA 不对会 403。"""
    o = opts or FetchOpts()
    req = urllib.request.Request(url, headers={
        "User-Agent": o.user_agent or UA,
        "Accept": "*/*",
        "Accept-Encoding": "identity",               # 视频已是压缩数据，别再折腾
    })
    if o.referer:
        req.add_header("Referer", o.referer)
    if o.cookie:
        req.add_header("Cookie", o.cookie)
    return req


# --------------------------------------------------------------------------
# 跑外部进程（带进度与取消）
# --------------------------------------------------------------------------

class _ProcRunner:
    """启动一个进程，边读 stdout 边看取消标志，stderr 由后台线程收走防死锁。"""

    def __init__(self, cmd, on_line=None, cancel: threading.Event | None = None,
                 on_stderr=None):
        self.cmd = cmd
        self.on_line = on_line
        self.cancel = cancel
        self.on_stderr = on_stderr
        self.stderr_tail = []
        self.proc = None

    def run(self) -> int:
        try:
            self.proc = subprocess.Popen(
                self.cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                creationflags=CREATE_NO_WINDOW,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
        except FileNotFoundError as e:
            raise EngineError(f"启动失败：找不到 {self.cmd[0]}") from e
        except OSError as e:
            raise EngineError(f"启动失败：{e}") from e

        drain = threading.Thread(target=self._drain, daemon=True)
        drain.start()

        try:
            for line in self.proc.stdout:
                if self.cancel is not None and self.cancel.is_set():
                    self._kill()
                    raise Canceled()
                if self.on_line:
                    self.on_line(line.strip())
        finally:
            try:
                self.proc.stdout.close()
            except Exception:
                pass
            drain.join(timeout=5)

        rc = self.proc.wait()
        if self.cancel is not None and self.cancel.is_set():
            self._kill()
            raise Canceled()
        return rc

    def _drain(self):
        try:
            for line in self.proc.stderr:
                line = line.rstrip()
                self.stderr_tail.append(line)
                if len(self.stderr_tail) > 40:        # 只留最后 40 行够报错了
                    del self.stderr_tail[:20]
                # 把真正的报错实时透出去，别让用户对着"下载失败"干瞪眼
                if self.on_stderr and ("ERROR" in line or "WARNING" in line):
                    self.on_stderr(line.strip())
        except Exception:
            pass

    def _kill(self):
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.kill()
            except Exception:
                pass

    def error_text(self) -> str:
        return " / ".join(self.stderr_tail[-3:]) or "未知错误"


def _probe_duration(ffprobe: str, target: str, referer: str = "") -> float:
    """秒数；拿不到返回 0（进度条退化成不确定状态）。"""
    if not ffprobe:
        return 0.0
    cmd = [ffprobe, "-v", "error", "-show_entries", "format=duration",
           "-of", "default=nw=1:nk=1"]
    if referer:
        cmd += ["-headers", _headers_block(referer)]
    cmd.append(target)
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=60,
                             creationflags=CREATE_NO_WINDOW)
        return max(0.0, float((out.stdout or "").strip() or 0))
    except (ValueError, OSError, subprocess.SubprocessError):
        return 0.0


def probe_codecs(ffprobe: str, target: str, referer: str = "") -> tuple:
    """取第一个视频流和第一个音频流的编码名；取不到返回空串。"""
    if not ffprobe:
        return "", ""
    cmd = [ffprobe, "-v", "error", "-show_entries", "stream=codec_type,codec_name",
           "-of", "json"]
    if referer:
        cmd += ["-headers", _headers_block(referer)]
    cmd.append(target)
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=60,
                             creationflags=CREATE_NO_WINDOW)
        streams = json.loads(out.stdout or "{}").get("streams", [])
    except (ValueError, OSError, subprocess.SubprocessError):
        return "", ""
    video = audio = ""
    for s in streams:
        kind = s.get("codec_type")
        name = (s.get("codec_name") or "").lower()
        if kind == "video" and not video:
            video = name
        elif kind == "audio" and not audio:
            audio = name
    return video, audio


def _mp4_playable(video: str, audio: str) -> bool:
    """未知编码（探测失败）时放行，免得探针坏了就什么都不给转。"""
    if video and video not in MP4_SAFE_VIDEO:
        return False
    if audio and audio not in MP4_SAFE_AUDIO:
        return False
    return True


# --------------------------------------------------------------------------
# 直链下载
# --------------------------------------------------------------------------

def _download_single(url: str, dest: str, opts=None,
                     on_progress=None, cancel: threading.Event | None = None) -> str:
    """一路连接顺序下完（不支持分段、或文件太小时走这里）。"""
    tmp = dest + ".part"
    with urllib.request.urlopen(_request(url, opts), timeout=30) as resp:
        ctype = (resp.headers.get("Content-Type") or "").lower()
        if ctype.startswith("text/html"):
            raise EngineError(
                "服务器返回的是网页而不是视频，可能需要登录或防盗链 "
                "（试试 yt-dlp 下载）")
        total = int(resp.headers.get("Content-Length") or 0)
        got = 0
        with open(tmp, "wb") as f:
            while True:
                if cancel is not None and cancel.is_set():
                    raise Canceled()
                chunk = resp.read(CHUNK)
                if not chunk:
                    break
                f.write(chunk)
                got += len(chunk)
                if on_progress:
                    on_progress((got / total) if total else 0.0, got, total)
    if got == 0:
        raise EngineError("下载到 0 字节，服务器可能拒绝了请求")
    os.replace(tmp, dest)
    return dest


def probe_size_and_range(url: str, opts=None, timeout: int = 20):
    """探测文件总大小与是否支持 Range。返回 (total, supports_range)。

    用 `Range: bytes=0-0` 而不是 HEAD：有些服务器直接拒绝 HEAD（405）。
    返回 206 说明支持分段，返回 200 说明服务器把整份内容塞回来了。
    """
    try:
        req = _request(url, opts)
        req.add_header("Range", "bytes=0-0")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            if r.status == 206:
                m = re.search(r"/(\d+)\s*$", r.headers.get("Content-Range") or "")
                total = int(m.group(1)) if m else 0
                return total, total > 0
            return int(r.headers.get("Content-Length") or 0), False
    except (urllib.error.URLError, OSError, ValueError):
        return 0, False


def plan_segments(total: int, threads: int):
    """把 [0, total) 切成若干段。返回空列表表示"别分段"。"""
    count = min(threads, total // SEGMENT_MIN_BYTES)
    if count <= 1:
        return []
    step = -(-total // count)                    # 向上取整，保证覆盖整个文件
    segments = []
    start = 0
    while start < total:
        end = min(total - 1, start + step - 1)
        segments.append((start, end))
        start = end + 1
    return segments


def _fetch_segment(url: str, opts, path: str, start: int, end: int,
                   counter, lock, on_progress, total: int,
                   cancel, stop: threading.Event):
    """下 [start, end] 这一段，直接写到文件对应偏移上。"""
    req = _request(url, opts)
    req.add_header("Range", f"bytes={start}-{end}")
    with urllib.request.urlopen(req, timeout=30) as r:
        if r.status != 206:
            raise _NoRangeSupport()              # 服务器无视了 Range，整份返回
        with open(path, "r+b") as f:             # 每个线程自己的句柄，各写各的偏移
            f.seek(start)
            pos = start
            while pos <= end:
                if (cancel is not None and cancel.is_set()) or stop.is_set():
                    raise Canceled()
                chunk = r.read(min(CHUNK, end - pos + 1))
                if not chunk:
                    break
                f.write(chunk)
                pos += len(chunk)
                with lock:
                    counter[0] += len(chunk)
                    got = counter[0]
                if on_progress:
                    on_progress((got / total) if total else 0.0, got, total)
    if pos != end + 1:
        raise EngineError(f"分片 {start}-{end} 没下完（只到 {pos}）")


def _download_segmented(url: str, dest: str, opts, total: int, segments,
                        on_progress, cancel) -> str:
    """多线程分段下载：预分配文件，每个线程按偏移各写各的。"""
    part = dest + ".part"
    _silent_remove(part)
    with open(part, "wb") as f:
        f.truncate(total)                        # 先占好位置，各线程直接 seek 写入

    lock = threading.Lock()
    counter = [0]
    stop = threading.Event()                     # 某一段挂了就让其它段别白下
    errors = []

    def work(segment):
        try:
            _fetch_segment(url, opts, part, segment[0], segment[1],
                           counter, lock, on_progress, total, cancel, stop)
        except BaseException as e:               # noqa: BLE001 - 收集到主线程再抛
            errors.append(e)
            stop.set()

    workers = [threading.Thread(target=work, args=(s,), daemon=True)
               for s in segments]
    for t in workers:
        t.start()
    for t in workers:
        t.join()

    if cancel is not None and cancel.is_set():
        _silent_remove(part)
        raise Canceled()
    real = [e for e in errors if not isinstance(e, Canceled)]
    if real:
        _silent_remove(part)
        raise real[0]
    if errors:                                   # 只剩 Canceled，说明是被 stop 带停的
        _silent_remove(part)
        raise EngineError("分段下载被中断")

    size = os.path.getsize(part)
    if size != total:                            # 少一个字节都不能当成功
        _silent_remove(part)
        raise EngineError(f"分段下载大小对不上：得到 {size}，期望 {total}")
    os.replace(part, dest)
    return dest


def download_direct(url: str, dest: str, opts=None,
                    on_progress=None, cancel: threading.Event | None = None,
                    retries: int = 2, threads: int = 1) -> str:
    """下载到 dest。threads > 1 时用多线程分段下载（服务器支持 Range 才行）。

    opts 见 FetchOpts（Referer / User-Agent / Cookie）。
    分段不可用时自动退回单线程；失败重试（从头开始，不做断点续传）。
    """
    parent = os.path.dirname(os.path.abspath(dest))
    if parent:
        os.makedirs(parent, exist_ok=True)       # 别把"目录不存在"当成网络错误去重试
    last = None
    for attempt in range(retries + 1):
        if cancel is not None and cancel.is_set():
            raise Canceled()
        try:
            if threads > 1:
                total, ranged = probe_size_and_range(url, opts)
                segments = (plan_segments(total, threads)
                            if ranged and total >= SEGMENT_MIN_TOTAL else [])
                if segments:
                    return _download_segmented(url, dest, opts, total,
                                               segments, on_progress, cancel)
            return _download_single(url, dest, opts, on_progress, cancel)
        except Canceled:
            _silent_remove(dest + ".part")
            raise
        except _NoRangeSupport:
            # 探测说有、真下时又整份返回：退回单线程，这不叫失败
            return _download_single(url, dest, opts, on_progress, cancel)
        except EngineError:
            _silent_remove(dest + ".part")
            raise
        except (urllib.error.URLError, OSError, ValueError) as e:
            _silent_remove(dest + ".part")
            last = e
            if attempt < retries:
                time.sleep(1.5)
    raise EngineError(f"下载失败：{last}")


# --------------------------------------------------------------------------
# ffmpeg 转 MP4
# --------------------------------------------------------------------------

def _ffmpeg_progress(on_progress, duration):
    """解析 ffmpeg -progress pipe:1 的输出。"""
    def handle(line: str):
        if not on_progress:
            return
        m = re.match(r"out_time_us=(\d+)", line)
        if m and duration > 0:
            on_progress(min(1.0, int(m.group(1)) / 1_000_000 / duration), 0, 0)
    return handle


def _run_ffmpeg(ffmpeg: str, args, duration: float, on_progress, cancel):
    cmd = [ffmpeg, "-hide_banner", "-nostdin", "-y",
           "-progress", "pipe:1", "-nostats"] + args
    runner = _ProcRunner(cmd, _ffmpeg_progress(on_progress, duration), cancel)
    rc = runner.run()
    return rc, runner.error_text()


_REENCODE = ["-c:v", "libx264", "-crf", "20", "-preset", "veryfast",
             "-pix_fmt", "yuv420p", "-c:a", "aac", "-b:a", "192k"]


def convert_to_mp4(ffmpeg: str, src: str, out: str, ffprobe: str = "",
                   on_progress=None, cancel: threading.Event | None = None) -> str:
    """把任意容器转成 MP4，并保证产出的编码是播放器真能放的。

    按源编码挑起点，再从快到慢降级：
      1. -c copy              无损重封装（MKV(H.264+AAC) 秒转）
      2. -c:v copy -c:a aac   只转音频（MKV+DTS/FLAC/PCM 这类几秒搞定）
      3. libx264 + aac        整体重编码（最后的兜底）
    """
    duration = _probe_duration(ffprobe, src)
    vcodec, acodec = probe_codecs(ffprobe, src)

    stages = []
    if _mp4_playable(vcodec, acodec):
        stages.append(("重封装", ["-c", "copy"]))
    elif vcodec in MP4_SAFE_VIDEO or not vcodec:
        stages.append(("音频转 AAC", ["-c:v", "copy", "-c:a", "aac", "-b:a", "192k"]))
    stages.append(("重编码", list(_REENCODE)))       # 兜底，永远在最后

    bases = ["-i", src, "-map", "0:v:0", "-map", "0:a:0?"]
    moves = ["-movflags", "+faststart", out]
    last_err = ""
    for label, extra in stages:
        if cancel is not None and cancel.is_set():
            raise Canceled()
        if on_progress:
            on_progress(0.0, 0, 0)
        rc, err = _run_ffmpeg(ffmpeg, bases + extra + moves, duration, on_progress, cancel)
        if rc == 0 and os.path.isfile(out) and os.path.getsize(out) > 0:
            ov, oa = probe_codecs(ffprobe, out)
            if _mp4_playable(ov, oa):
                return out
            # ffmpeg 说自己成功了，但塞进去的编码播放器放不了 —— 不能就这么交付
            last_err = f"{label} 产出 {ov or '?'}/{oa or '?'}，播放器放不了"
        else:
            last_err = err
        _silent_remove(out)
    raise EngineError(f"转 MP4 失败（已试过重封装/音频转码/重编码）：{last_err}")


def mux_tracks(ffmpeg: str, video: str, audio: str, out: str, ffprobe: str = "",
               on_progress=None, cancel: threading.Event | None = None) -> str:
    """把分开的画面流和声音流合成一个 MP4。

    DASH 站点（抖音等）不给你一个完整文件，而是画面、声音两条流分开下，
    再由播放器实时合起来。所以要下两条再合 —— 这就是"把切片合并"。
    """
    duration = _probe_duration(ffprobe, video)
    bases = ["-i", video, "-i", audio, "-map", "0:v:0", "-map", "1:a:0"]
    moves = ["-movflags", "+faststart", out]
    stages = [
        ("直接封装", ["-c", "copy"]),
        ("音频转 AAC", ["-c:v", "copy", "-c:a", "aac", "-b:a", "192k"]),
    ]
    last_err = ""
    for label, extra in stages:
        if cancel is not None and cancel.is_set():
            raise Canceled()
        if on_progress:
            on_progress(0.0, 0, 0)
        rc, err = _run_ffmpeg(ffmpeg, bases + extra + moves, duration,
                              on_progress, cancel)
        if rc == 0 and os.path.isfile(out) and os.path.getsize(out) > 0:
            ov, oa = probe_codecs(ffprobe, out)
            if _mp4_playable(ov, oa) and oa:
                return out
            last_err = f"{label} 产出 {ov or '?'}/{oa or '?'}"
        else:
            last_err = err
        _silent_remove(out)
    raise EngineError(f"画面和声音合并失败：{last_err}")


def stream_to_mp4(ffmpeg: str, url: str, out: str, referer: str = "",
                  ffprobe: str = "", on_progress=None,
                  cancel: threading.Event | None = None) -> str:
    """把 m3u8 / mpd 直接交给 ffmpeg 边拉边转成 MP4。"""
    duration = _probe_duration(ffprobe, url, referer)
    head = ["-headers", _headers_block(referer), "-i", url,
            "-map", "0:v:0", "-map", "0:a:0?"]
    moves = ["-movflags", "+faststart", out]
    stages = [
        ("拉流重封装", ["-c", "copy"]),
        ("拉流重编码", list(_REENCODE)),
    ]
    last_err = ""
    for label, extra in stages:
        if cancel is not None and cancel.is_set():
            raise Canceled()
        if on_progress:
            on_progress(0.0, 0, 0)
        rc, err = _run_ffmpeg(ffmpeg, head + extra + moves, duration, on_progress, cancel)
        if rc == 0 and os.path.isfile(out) and os.path.getsize(out) > 0:
            ov, oa = probe_codecs(ffprobe, out)
            if _mp4_playable(ov, oa):
                return out
            last_err = f"{label} 产出 {ov or '?'}/{oa or '?'}，播放器放不了"
        else:
            last_err = err
        _silent_remove(out)
    raise EngineError(f"拉流转 MP4 失败：{last_err}")


# --------------------------------------------------------------------------
# yt-dlp 兜底
# --------------------------------------------------------------------------

_DL_PCT_RX = re.compile(r"\[download\]\s+([\d.]+)%")


def _ytdlp_reason(lines) -> str:
    """从 yt-dlp 的 stderr 里挑出真正有信息量的那一行。

    以前这里直接吞掉，只回一句"下载失败"，用户和我们都无从下手。
    """
    for line in reversed(lines):
        if "ERROR" in line:
            return line.split("ERROR:", 1)[-1].strip() or line.strip()
    for line in reversed(lines):
        if line.strip():
            return line.strip()
    return "没有输出（yt-dlp 可能被系统或网络中断）"


def ytdlp_download(ytdlp: str, url: str, workdir: str, referer: str = "",
                   on_progress=None, on_log=None,
                   cancel: threading.Event | None = None,
                   threads: int = 1, cookies_from: str = "",
                   cookies_file: str = "") -> str:
    """用 yt-dlp 下载，标题保持原视频标题。返回产出的文件路径。"""
    os.makedirs(workdir, exist_ok=True)
    before = set(os.listdir(workdir))

    def handle(line: str):
        m = _DL_PCT_RX.search(line)
        if m and on_progress:
            on_progress(float(m.group(1)) / 100.0, 0, 0)

    cmd = [
        ytdlp, "--no-playlist", "--no-color", "--newline",
        "--windows-filenames",          # 文件名按 Windows 规则清洗，标题尽量原样保留
        "--no-mtime",
        "-f", "bv*[ext=mp4]+ba[ext=m4a]/b[ext=mp4]/bv*+ba/b",
        "--merge-output-format", "mp4",
        "-o", os.path.join(workdir, "%(title)s.%(ext)s"),
    ]
    if threads > 1:
        # HLS/DASH 分片并发拉取 —— yt-dlp 自己的多线程下载
        cmd += ["--concurrent-fragments", str(threads)]
    if find_node():
        # 不指定的话 yt-dlp 只认 deno，YouTube 会退化成"部分格式缺失"甚至抓不到
        cmd += ["--js-runtimes", "node"]
    if cookies_file:
        # 手动导出的 cookies.txt —— 绕开浏览器 Cookie 解密，最可靠的一条路
        cmd += ["--cookies", cookies_file]
    elif cookies_from:
        # 需要登录 / 被要求"确认你不是机器人"的站点，靠浏览器 Cookie 过
        cmd += ["--cookies-from-browser", cookies_from]
    if referer:
        cmd += ["--referer", referer]
    cmd.append(url)

    runner = _ProcRunner(cmd, handle, cancel, on_stderr=on_log)
    rc = runner.run()
    if rc != 0:
        raise EngineError(f"yt-dlp 失败：{_ytdlp_reason(runner.stderr_tail)}")

    new = [f for f in os.listdir(workdir) if f not in before]
    if not new:
        raise EngineError("yt-dlp 没产出文件")
    # 可能有 .part 等中间产物，挑最大的那个
    new.sort(key=lambda f: os.path.getsize(os.path.join(workdir, f)), reverse=True)
    return os.path.join(workdir, new[0])


def _silent_remove(path: str):
    try:
        os.remove(path)
    except OSError:
        pass


# --------------------------------------------------------------------------
# HLS 清晰度选择
# --------------------------------------------------------------------------

_ATTR_RX = re.compile(r'([A-Za-z0-9-]+)=("[^"]*"|[^,]*)')


def resolve_hls(url: str, referer: str = "") -> tuple:
    """HLS 主播放列表 → 清晰度最高的那个变体地址。

    ffmpeg 拿到主列表时**只取第一个变体**，而主列表往往把低清排在前面，
    结果就是明明有 1080p 却只下到 720p。这里自己挑最高的那个。

    带独立音频轨（#EXT-X-MEDIA:TYPE=AUDIO）的主列表不动，原样交给 ffmpeg ——
    那种情况下单挑一个视频变体会把音轨丢掉，宁可让 ffmpeg 自己处理。

    返回 (交给 ffmpeg 的地址, 日志说明)。
    """
    if not url.lower().split("?")[0].endswith(".m3u8"):
        return url, ""
    try:
        _, _, text = sniffer.fetch(url, referer)
    except sniffer.SniffError:
        return url, ""                               # 拿不到就原样交给 ffmpeg
    if "#EXT-X-STREAM-INF" not in text.upper():
        return url, ""                               # 本来就是媒体列表
    if re.search(r"#EXT-X-MEDIA:[^\r\n]*TYPE=AUDIO", text, re.I):
        return url, "主列表含独立音频轨，交给 ffmpeg 自选"

    lines = text.splitlines()
    best = None
    for i, line in enumerate(lines):
        if not line.strip().upper().startswith("#EXT-X-STREAM-INF:"):
            continue
        attrs = {m.group(1).upper(): m.group(2).strip('"')
                 for m in _ATTR_RX.finditer(line.split(":", 1)[1])}
        uri = ""
        for nxt in lines[i + 1:]:
            if nxt.strip() and not nxt.lstrip().startswith("#"):
                uri = nxt.strip()
                break
        if not uri:
            continue
        try:
            bw = int(attrs.get("BANDWIDTH") or 0)
        except ValueError:
            bw = 0
        if best is None or bw > best[0]:
            best = (bw, attrs.get("RESOLUTION", ""), uri)
    if best is None:
        return url, ""
    label = best[1] or (f"{best[0] // 1000} kbps" if best[0] else "未知清晰度")
    return urllib.parse.urljoin(url, best[2]), f"已挑最高清晰度 {label}"


# --------------------------------------------------------------------------
# 单个任务：串起整条流水线
# --------------------------------------------------------------------------

class Task:
    """一个下载任务。字段由 GUI 轮询显示。"""

    _seq = 0
    _seq_lock = threading.Lock()

    def __init__(self, url: str, title: str, out_dir: str, kind: str = "视频",
                 referer: str = "", use_ytdlp: bool = False,
                 keep_source_title: bool = False, threads: int = 8,
                 cookies_from: str = "", cookies_file: str = "",
                 user_agent: str = "", cookie: str = "",
                 audio_url: str = ""):
        with Task._seq_lock:
            Task._seq += 1
            self.id = f"t{Task._seq}"
        self.url = url
        self.title = sanitize(strip_media_ext(title)) or "video"
        self.out_dir = out_dir
        self.kind = kind
        self.referer = referer
        self.use_ytdlp = use_ytdlp
        self.keep_source_title = keep_source_title
        self.threads = max(1, int(threads))
        self.cookies_from = cookies_from
        self.cookies_file = cookies_file
        self.user_agent = user_agent
        self.cookie = cookie
        self.audio_url = audio_url        # 画面和声音分开时，补一条声音流
        self.status = "排队中"
        self.progress = 0.0
        self.detail = ""
        self.out_path = ""
        self.error = ""
        self.cancel = threading.Event()
        self.notify = None          # 由 GUI 注入

    @property
    def fetch_opts(self) -> FetchOpts:
        """下载这个任务时该带的请求头（浏览器嗅探来的 UA/Cookie 会在这里生效）。"""
        return FetchOpts(referer=self.referer, user_agent=self.user_agent,
                         cookie=self.cookie)

    def emit(self):
        if self.notify:
            self.notify(self)

    def set(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)
        self.emit()


_place_lock = threading.Lock()


def _place(staged: str, out_dir: str, stem: str, ext: str = ".mp4") -> str:
    """把成品挪到 out_dir 下、按标题命名。

    取名和落盘必须在同一把锁里：两个并发任务会同时算出「标题.mp4」，
    后落盘的那个直接覆盖前一个。os.replace 是同卷原子操作，不复制数据。
    """
    with _place_lock:
        final = unique_path(os.path.join(out_dir, stem + ext))
        os.replace(staged, final)
    return final


def _prune_tmp_parent(out_dir: str):
    """任务目录清空后顺手删掉 .tmp —— 非空时 rmdir 会失败，正好不用判断。"""
    try:
        os.rmdir(os.path.join(out_dir, ".tmp"))
    except OSError:
        pass


def run_task(task: Task, ffmpeg: str, ffprobe: str, ytdlp: str, log=print):
    """执行一个任务：下载（必要时转码）→ 落盘为「标题.mp4」。

    中间文件全部待在 .tmp/<任务id>/ 里 —— 每个任务一个目录。
    共用一个 .tmp 的话，先结束的任务会把还在下载的任务的目录一起删掉。
    """
    os.makedirs(task.out_dir, exist_ok=True)
    tmp_dir = os.path.join(task.out_dir, ".tmp", task.id)
    os.makedirs(tmp_dir, exist_ok=True)

    def prog(pct, got, total):
        task.progress = pct
        if total:
            task.detail = f"{human_size(got)} / {human_size(total)}"
        task.emit()

    try:
        src_path = ""

        if task.use_ytdlp:
            if not ytdlp:
                raise EngineError(
                    "没找到 yt-dlp。安装：winget install yt-dlp.yt-dlp")
            task.set(status="yt-dlp 下载中", progress=0.0)
            log(f"[{task.title}] 交给 yt-dlp…")
            src_path = ytdlp_download(ytdlp, task.url, tmp_dir, task.referer,
                                      prog, log, task.cancel, task.threads,
                                      task.cookies_from, task.cookies_file)
            if task.keep_source_title:
                # yt-dlp 按 %(title)s 命名，那就是最原汁原味的视频标题
                stem = os.path.splitext(os.path.basename(src_path))[0]
                real = sanitize(strip_media_ext(stem))
                if real:
                    task.title = real
                    task.emit()
        elif task.kind in ("HLS", "DASH", "SmoothStreaming"):
            if not ffmpeg:
                raise EngineError("拉流需要 ffmpeg，请先安装并确保在 PATH 中")
            task.set(status="拉流中", progress=0.0)
            target, note = resolve_hls(task.url, task.referer)
            if note:
                log(f"[{task.title}] {note}")
            log(f"[{task.title}] ffmpeg 拉流并转 MP4…")
            staged = os.path.join(tmp_dir, "out.mp4")
            stream_to_mp4(ffmpeg, target, staged, task.referer, ffprobe,
                          prog, task.cancel)
            task.set(status="完成", progress=1.0,
                     out_path=_place(staged, task.out_dir, task.title))
            log(f"[{task.title}] ✓ 完成 → {os.path.basename(task.out_path)}")
            return
        else:
            task.set(status="下载中", progress=0.0)
            log(f"[{task.title}] 直链下载（{task.threads} 线程）…")
            src_path = os.path.join(tmp_dir, "src" + (ext_of(task.url) or ".bin"))
            download_direct(task.url, src_path, task.fetch_opts, prog, task.cancel,
                            threads=task.threads)

        # 画面和声音是分开的两条流（DASH 站点）→ 两条都下，再合成一个
        if task.audio_url and ffmpeg:
            task.set(status="下载声音轨", progress=0.0)
            log(f"[{task.title}] 画面和声音是分开的两条流，再下一条声音轨…")
            audio_path = os.path.join(
                tmp_dir, "audio" + (ext_of(task.audio_url) or ".m4a"))
            download_direct(task.audio_url, audio_path, task.fetch_opts, None,
                            task.cancel, threads=1)
            task.set(status="合并音视频", progress=0.0)
            log(f"[{task.title}] 合并画面与声音…")
            staged = os.path.join(tmp_dir, "out.mp4")
            mux_tracks(ffmpeg, src_path, audio_path, staged, ffprobe,
                       prog, task.cancel)
            task.set(status="完成", progress=1.0,
                     out_path=_place(staged, task.out_dir, task.title))
            log(f"[{task.title}] ✓ 完成 → {os.path.basename(task.out_path)}")
            return

        # 到这里手上是一个本地文件，统一处理成 MP4
        if src_path.lower().endswith(".mp4"):
            task.set(status="完成", progress=1.0,
                     out_path=_place(src_path, task.out_dir, task.title))
            log(f"[{task.title}] ✓ 完成 → {os.path.basename(task.out_path)}")
            return

        if not ffmpeg:
            # 没 ffmpeg 就保留原格式，别把文件丢了
            ext = os.path.splitext(src_path)[1] or ".bin"
            task.set(status="完成(未转MP4)", progress=1.0,
                     out_path=_place(src_path, task.out_dir, task.title, ext))
            log(f"[{task.title}] ! 没找到 ffmpeg，保留原格式 → "
                f"{os.path.basename(task.out_path)}")
            return

        task.set(status="转 MP4 中", progress=0.0, detail="")
        log(f"[{task.title}] 转 MP4…")
        staged = os.path.join(tmp_dir, "out.mp4")
        convert_to_mp4(ffmpeg, src_path, staged, ffprobe, prog, task.cancel)
        task.set(status="完成", progress=1.0,
                 out_path=_place(staged, task.out_dir, task.title))
        log(f"[{task.title}] ✓ 完成 → {os.path.basename(task.out_path)}")
    except Canceled:
        task.set(status="已取消", detail="")
        log(f"[{task.title}] 已取消")
    except EngineError as e:
        task.set(status="失败", error=str(e), detail="")
        log(f"[{task.title}] ✗ {e}")
    except Exception as e:                            # 兜底，别让线程静默死掉
        task.set(status="失败", error=f"{type(e).__name__}: {e}", detail="")
        log(f"[{task.title}] ✗ 意外错误 {type(e).__name__}: {e}")
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        _prune_tmp_parent(task.out_dir)
