# -*- coding: utf-8 -*-
"""用真实浏览器访问网页，抓出它真正在播的视频。

为什么需要这个：
    静态嗅探只能看服务器返回的 HTML。抖音这类站点的 HTML 里**一个视频地址都没有**
    （实测 72 KB 页面里连一条 http 链接都没有），地址是 JS 跑起来之后才拿到的。

    这里启动一个**真实的浏览器**（Edge/Chrome），像一个真人那样把页面打开、让 JS 跑完、
    让视频真的播起来，然后：

      · 问 DOM「你现在在播什么」→ `<video>.currentSrc`，那就是真正的视频地址
      · 取 `document.title` → 视频标题
      · 顺带把网络请求里出现的媒体地址也收着，作为备选

    拿到地址之后**下载还是我们自己下**（引擎里那套多线程 + 转 MP4），
    所以不需要碰任何 Cookie 解密 —— 实测抖音连 Cookie 都不用带。

只用标准库：CDP 走 WebSocket，这里手写了一个够用就行的 RFC6455 客户端。
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import socket
import struct
import subprocess
import threading
import time
import urllib.parse
import urllib.request

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0

# 探测体积时的兜底 UA（正常情况下用页面里读到的真实 UA）
_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")

# 常见安装位置；也查 PATH
_BROWSER_PATHS = (
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Users\%USERNAME%\AppData\Local\Google\Chrome\Application\chrome.exe",
)

_MEDIA_URL_RX = re.compile(
    r"\.(m3u8|mpd|mp4|m4s|ts|flv|mkv|webm)(\?|$)"
    r"|/aweme/v1/play/|video_id=|mime_type=video",
    re.I)
_MEDIA_MIME_RX = re.compile(
    r"^(video/|audio/|application/(x-mpegurl|vnd\.apple\.mpegurl|dash\+xml))",
    re.I)


def _probe_size(url: str, user_agent: str = "", timeout: int = 10) -> int:
    """用一次 1 字节的 Range 请求问出资源真实大小。

    为什么不靠 CDP 抓的响应头：视频是边播边缓冲的，浏览器只取开头一小段，
    而且这类请求常常不带 Content-Range，据此估出来的"大小"会差几十倍。
    直接问服务器最准。
    """
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": user_agent or _UA,
            "Range": "bytes=0-0",
            "Accept": "*/*",
            "Accept-Encoding": "identity",
        })
        with urllib.request.urlopen(req, timeout=timeout) as r:
            cr = r.headers.get("Content-Range") or ""
            if "/" in cr:
                try:
                    return int(cr.rsplit("/", 1)[1])
                except ValueError:
                    pass
            return int(r.headers.get("Content-Length") or 0)
    except Exception:
        return 0


class BrowserError(Exception):
    """浏览器嗅探过程中的可预期失败。"""


def _ext_of(url: str) -> str:
    try:
        path = urllib.parse.urlsplit(url).path
    except ValueError:
        return ""
    m = re.search(r"\.([A-Za-z0-9]{2,5})$", path)
    return "." + m.group(1).lower() if m else ""


def find_browser() -> str:
    """找一个可用的 Edge / Chrome。"""
    for name in ("msedge", "msedge.exe", "chrome", "chrome.exe"):
        p = _which(name)
        if p:
            return p
    for p in _BROWSER_PATHS:
        p = os.path.expandvars(p)
        if os.path.isfile(p):
            return p
    return ""


def _which(name: str) -> str:
    from shutil import which
    return which(name) or ""


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# --------------------------------------------------------------------------
# 最小 WebSocket 客户端（只够 CDP 用）
# --------------------------------------------------------------------------

class MiniWS:
    """RFC6455 客户端：握手 + 收发文本帧，自动处理分片和 ping/pong。"""

    def __init__(self, url: str, timeout: int = 30):
        p = urllib.parse.urlsplit(url)
        if p.scheme != "ws":
            raise BrowserError(f"只支持 ws://，收到 {p.scheme}")
        host, port = p.hostname, p.port or 80
        path = p.path + (("?" + p.query) if p.query else "")
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self._buf = b""
        key = base64.b64encode(os.urandom(16)).decode()
        self.sock.sendall((
            f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
            "Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        ).encode())
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise BrowserError("WebSocket 握手时连接被关闭")
            head += chunk
        if b" 101 " not in head.split(b"\r\n")[0]:
            raise BrowserError("WebSocket 握手失败："
                               + head.split(b"\r\n")[0].decode("latin1"))
        want = base64.b64encode(
            hashlib.sha1((key + GUID).encode()).digest()).decode()
        if want.encode() not in head:
            raise BrowserError("WebSocket 握手校验失败")
        self._buf = head.split(b"\r\n\r\n", 1)[1]

    def _read(self, n: int) -> bytes:
        while len(self._buf) < n:
            chunk = self.sock.recv(max(4096, n - len(self._buf)))
            if not chunk:
                raise BrowserError("WebSocket 连接被关闭")
            self._buf += chunk
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def send(self, text: str):
        data = text.encode()
        header = bytearray([0x81])                   # FIN + 文本帧
        n = len(data)
        if n < 126:
            header.append(0x80 | n)
        elif n < 65536:
            header.append(0x80 | 126)
            header += struct.pack(">H", n)
        else:
            header.append(0x80 | 127)
            header += struct.pack(">Q", n)
        mask = os.urandom(4)
        header += mask
        self.sock.sendall(bytes(header) + bytes(
            b ^ mask[i % 4] for i, b in enumerate(data)))

    def recv(self) -> str:
        payload = b""
        while True:
            b0, b1 = self._read(2)
            fin, opcode = b0 & 0x80, b0 & 0x0F
            length = b1 & 0x7F
            if length == 126:
                length = struct.unpack(">H", self._read(2))[0]
            elif length == 127:
                length = struct.unpack(">Q", self._read(8))[0]
            mask = self._read(4) if (b1 & 0x80) else None
            data = self._read(length) if length else b""
            if mask:
                data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
            if opcode == 0x9:                        # ping
                self.sock.sendall(b"\x8a\x80" + os.urandom(4))
                continue
            if opcode == 0xA:                        # pong
                continue
            if opcode == 0x8:
                raise BrowserError("浏览器主动断开了调试连接")
            payload += data
            if fin:
                return payload.decode("utf-8", "replace")

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


# --------------------------------------------------------------------------
# 浏览器会话
# --------------------------------------------------------------------------

def _track_of(url: str, mime: str = "") -> str:
    """判断一个地址是「只有画面」「只有声音」还是「音视频都在」。

    DASH 站点（抖音等）会把画面和声音拆成两条流分别下，页面上再用播放器合起来。
    只下画面那条，出来的 MP4 就是哑的 —— 所以这里要分清楚。
    """
    low = (url or "").lower()
    if "media-audio" in low or "audio-only" in low or \
            (mime or "").lower().startswith("audio/"):
        return "audio"
    if "media-video" in low or "video-only" in low:
        return "video"
    return "muxed"          # 没有单独轨道的标记，按"完整"看待


class BrowserSession:
    """启动一个真实浏览器，连上 CDP，驱动它访问页面并取回结果。"""

    def __init__(self, exe: str, profile_dir: str, headless: bool = True,
                 on_log=None, timeout: int = 40):
        self.exe = exe
        self.profile_dir = profile_dir
        self.headless = headless
        self.on_log = on_log or (lambda _m: None)
        self.timeout = timeout
        self.proc = None
        self.ws = None
        self._events = []
        self._replies = {}
        self._lock = threading.Lock()
        self._mid = 0
        self._reader_err = []
        self._req_url = {}          # requestId -> url
        self._req_bytes = {}        # requestId -> 实际传输字节数
        self._req_size = {}         # requestId -> 资源真实大小（从响应头推）

    # -- 生命周期 --------------------------------------------------------

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()
        return False

    def start(self):
        os.makedirs(self.profile_dir, exist_ok=True)
        self.port = _free_port()
        args = [
            self.exe,
            f"--remote-debugging-port={self.port}",
            f"--user-data-dir={self.profile_dir}",
            "--no-first-run", "--no-default-browser-check",
            "--disable-extensions", "--disable-background-networking",
            "--mute-audio",
            # 让视频不用用户手势就能播
            "--autoplay-policy=no-user-gesture-required",
            "--window-size=1280,860",
        ]
        if self.headless:
            args.append("--headless=new")
        args.append("about:blank")
        try:
            self.proc = subprocess.Popen(
                args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=CREATE_NO_WINDOW)
        except OSError as e:
            raise BrowserError(f"启动浏览器失败：{e}") from e

        ws_url = ""
        deadline = time.time() + 30
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise BrowserError("浏览器启动后立刻退出了")
            try:
                ver = json.loads(urllib.request.urlopen(
                    f"http://127.0.0.1:{self.port}/json/version",
                    timeout=1).read())
                ws_url = ver.get("webSocketDebuggerUrl", "")
                if ws_url:
                    break
            except (OSError, ValueError):
                time.sleep(0.4)
        if not ws_url:
            raise BrowserError("浏览器的调试端口没起来（可能被安全软件拦了）")

        # 连到已有的页面标签页（/json/new 在新版里要求 PUT，绕开它）
        pages = []
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                tabs = json.loads(urllib.request.urlopen(
                    f"http://127.0.0.1:{self.port}/json/list", timeout=2).read())
                pages = [t for t in tabs if t.get("type") == "page"]
                if pages:
                    break
            except (OSError, ValueError):
                pass
            time.sleep(0.3)
        if not pages:
            raise BrowserError("找不到可用的浏览器标签页")

        self.ws = MiniWS(pages[0]["webSocketDebuggerUrl"],
                         timeout=max(60, self.timeout))
        threading.Thread(target=self._reader, daemon=True).start()
        self.call("Network.enable")
        self.call("Page.enable")
        self.call("Runtime.enable")

    def stop(self):
        if self.ws:
            self.ws.close()
            self.ws = None
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=8)
            except (OSError, subprocess.SubprocessError):
                try:
                    self.proc.kill()
                except OSError:
                    pass

    # -- CDP 收发 --------------------------------------------------------

    @staticmethod
    def _note_size(rid, headers):
        """从响应头里抠出资源真实大小。

        浏览器放视频只缓冲开头一小段，所以"实际传输了多少"远小于文件本身
        （实测 35 MB 的视频只传了约 700 KB）。但分段请求会带
        `Content-Range: bytes 0-…/总长`，这里面就有**真实大小**，用它排序才靠谱。
        """
        if rid is None or not isinstance(headers, dict):
            return
        try:
            low = {str(k).lower(): str(v) for k, v in headers.items()}
        except Exception:
            return
        size = 0
        cr = low.get("content-range", "")
        if "/" in cr:
            try:
                size = int(cr.rsplit("/", 1)[1])
            except ValueError:
                size = 0
        if not size:
            try:
                size = int(low.get("content-length", "0"))
            except ValueError:
                size = 0
        if size:
            self._req_size[rid] = size

    def _reader(self):
        """CDP 消息循环。**这里绝对不能因为单条消息有问题就退出** ——
        读取线程一死，后面所有命令都收不到回复，表现就是"标题空、地址空、等待超时"。"""
        try:
            while True:
                msg = json.loads(self.ws.recv())
                try:
                    self._dispatch(msg)
                except Exception:
                    continue                         # 单条消息处理失败，跳过就好
        except Exception as e:                       # 连接结束是正常路径
            self._reader_err.append(f"{type(e).__name__}: {e}")

    def _dispatch(self, msg):
        if "method" not in msg:
            if "id" in msg:
                self._replies[msg["id"]] = msg
            return
        self._events.append(msg)
        m, p = msg["method"], msg.get("params") or {}
        if m == "Network.requestWillBeSent":
            self._req_url[p.get("requestId")] = \
                (p.get("request") or {}).get("url", "")
        elif m == "Network.loadingFinished":
            rid = p.get("requestId")
            if rid is not None:
                self._req_bytes[rid] = p.get("encodedDataLength", 0)
        elif m == "Network.responseReceived":
            self._note_size(p.get("requestId"),
                            (p.get("response") or {}).get("headers"))
        elif m == "Network.responseReceivedExtraInfo":
            # 完整原始响应头在这里 —— Content-Range 常常只在 ExtraInfo 里有，
            # responseReceived 里那份是阉割过的。
            self._note_size(p.get("requestId"), p.get("headers"))

    def call(self, method: str, params=None, timeout: float = 20):
        """发一条 CDP 命令并等回复。"""
        if self.ws is None:
            raise BrowserError("浏览器会话已关闭")
        with self._lock:
            self._mid += 1
            mid = self._mid
        self.ws.send(json.dumps({"id": mid, "method": method,
                                 "params": params or {}}))
        deadline = time.time() + timeout
        while time.time() < deadline:
            if mid in self._replies:
                return self._replies.pop(mid)
            time.sleep(0.05)
        return None

    def evaluate(self, expression: str, timeout: float = 20):
        """在页面里跑一段 JS，返回它的值。"""
        r = self.call("Runtime.evaluate",
                      {"expression": expression, "returnByValue": True},
                      timeout)
        try:
            return r["result"]["result"].get("value")
        except (TypeError, KeyError):
            return None

    # -- 嗅探 ------------------------------------------------------------

    def sniff(self, url: str, wait: float = 30) -> dict:
        """打开页面、等视频跑起来，返回找到的候选地址。"""
        self.on_log(f"浏览器打开：{url}")
        self.call("Page.navigate", {"url": url})

        # 轮询等 <video> 出现并拿到 currentSrc —— 比死等固定秒数快得多
        deadline = time.time() + wait
        played = False
        while time.time() < deadline:
            time.sleep(1.5)
            n = self.evaluate(
                "document.querySelectorAll('video').length") or 0
            if n and not played:
                self.evaluate(
                    "(()=>{for(const v of document.querySelectorAll('video'))"
                    "{v.muted=true;try{v.play()}catch(e){}}return 1})()")
                played = True
            cur = self.evaluate(
                "(()=>{const v=document.querySelector('video');"
                "return v?(v.currentSrc||v.src||''):''})()") or ""
            if cur:
                self.on_log("视频已开始播放，取回地址")
                break
        else:
            self.on_log("等待超时，仍把已抓到的结果带回去")

        # 再给网络一点时间把媒体请求发全
        time.sleep(2)

        dom = {}
        raw = self.evaluate(
            "JSON.stringify({t:document.title,"
            "v:[...document.querySelectorAll('video')].map(v=>({"
            " s:v.currentSrc||v.src||'', d:v.duration||0, p:v.paused,"
            " a:(v.clientWidth||0)*(v.clientHeight||0)})),"
            "src:[...document.querySelectorAll('video source')]"
            ".map(s=>s.src||''),"
            "ua:navigator.userAgent})")
        if raw:
            try:
                dom = json.loads(raw)
            except (ValueError, TypeError):
                pass

        # 每个地址到底多大：
        #   优先用响应头里的真实大小（Content-Range/Content-Length），
        #   拿不到再退回到"浏览器实际传了多少"。
        # 这是区分「真视频」和「UI 小素材」最可靠的信号 ——
        # 抖音页面上有个 195 KB 的装饰性视频，真正的视频有 35 MB。
        byte_of, size_of = {}, {}
        for rid, u in self._req_url.items():
            n = self._req_bytes.get(rid, 0)
            if n:
                byte_of[u] = byte_of.get(u, 0) + n
            s = self._req_size.get(rid, 0)
            if s > size_of.get(u, 0):
                size_of[u] = s
        weight_of = {u: max(size_of.get(u, 0), byte_of.get(u, 0))
                     for u in set(byte_of) | set(size_of)}

        found = []          # (url, 来源, 字节数, 是否正在播, mime)

        def add(u, source, playing=False, mime=""):
            if not u or u.startswith(("blob:", "data:")):
                return
            if u.startswith("//"):
                u = "https:" + u
            if not u.startswith("http"):
                return
            if any(f[0] == u for f in found):
                return
            found.append((u, source, weight_of.get(u, 0), playing, mime))

        for v in dom.get("v", []):
            add(v.get("s", ""), "浏览器视频元素",
                playing=(not v.get("p")) and (v.get("d") or 0) > 0)
        for u in dom.get("src", []):
            add(u, "浏览器 <source>")
        for e in list(self._events):
            if e.get("method") != "Network.responseReceived":
                continue
            r = e["params"]["response"]
            u, mime = r.get("url", ""), r.get("mimeType", "")
            if _MEDIA_MIME_RX.match(mime) or _MEDIA_URL_RX.search(u):
                add(u, f"浏览器请求 {mime or '?'}", mime=mime)

        # 用真实大小排序：CDP 里那些数字只是"浏览器缓冲了多少"，差着几十倍。
        # 挨个问服务器一次（只取 1 字节），拿到准确体积再排。
        ua_for_probe = dom.get("ua") or ""
        for i, item in enumerate(found[:8]):
            real = _probe_size(item[0], ua_for_probe)
            if real > item[2]:
                found[i] = (item[0], item[1], real, item[3], item[4])

        def score(item):
            u, _src, weight, playing, _mime = item
            # 播放列表本身很小，但它是交给 ffmpeg 的入口，必须排最前
            manifest = 10 ** 12 if _ext_of(u) in (".m3u8", ".mpd") else 0
            return manifest + weight + (1000 if playing else 0)

        found.sort(key=score, reverse=True)

        # 挑主视频：先按体积选，但如果选中的只有画面，就找找有没有更好的
        primary_audio = ""
        if found:
            top = found[0]
            if _track_of(top[0], top[4]) == "video":
                muxed = [f for f in found if _track_of(f[0], f[4]) == "muxed"]
                # 体积相当的"完整"流优先。下限同时卡比例和绝对值 ——
                # 只卡比例的话，站点里那种一两百 KB 的装饰性小视频会被误当成主视频。
                floor = max(1024 * 1024, 0.2 * top[2])
                if muxed and muxed[0][2] >= floor:
                    found.remove(muxed[0])
                    found.insert(0, muxed[0])
                else:
                    # 没有完整流，就把声音那条记下来，下载后合起来
                    audios = [f for f in found if _track_of(f[0], f[4]) == "audio"]
                    if audios:
                        primary_audio = audios[0][0]

        urls = [{"url": u, "source": src, "bytes": n, "playing": playing,
                 "track": _track_of(u, mime),
                 "audio_url": primary_audio if i == 0 else ""}
                for i, (u, src, n, playing, mime) in enumerate(found)]

        title = (dom.get("t") or "").strip()
        return {
            "urls": urls,
            "title": title,
            "user_agent": dom.get("ua") or "",
            "page_url": url,
        }


def sniff_with_browser(url: str, profile_dir: str, *, headless: bool = True,
                       wait: float = 30, browser: str = "", on_log=None):
    """打开一个浏览器、嗅探、关掉。返回 dict(urls, title, user_agent, ...)。"""
    exe = browser or find_browser()
    if not exe:
        raise BrowserError("找不到 Edge 或 Chrome，浏览器嗅探需要其中一个")
    with BrowserSession(exe, profile_dir, headless=headless,
                        on_log=on_log) as s:
        return s.sniff(url, wait=wait)
