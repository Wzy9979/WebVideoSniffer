# -*- coding: utf-8 -*-
"""
网页视频嗅探：拉取页面，提取视频 / 流媒体候选地址与标题。

只做「静态嗅探」——直接分析服务器返回的 HTML / JSON，**不执行 JavaScript**。
所以 JS 渲染出来的视频（YouTube、B 站等）抓不到，那种站点走 yt-dlp 兜底。

对外只有一个入口： sniff(url) -> SniffResult
"""
from __future__ import annotations

import gzip
import html
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
import zlib
from html.parser import HTMLParser

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")

# 能独立下载、能转成 MP4 的视频容器
VIDEO_EXTS = {
    ".mp4", ".m4v", ".mkv", ".webm", ".flv", ".mov", ".avi", ".wmv",
    ".mpg", ".mpeg", ".3gp", ".f4v", ".ogv", ".rmvb", ".rm", ".asf",
    ".vob", ".amv", ".divx", ".mts", ".m2ts",
}
# 流媒体清单：不直接下载，交给 ffmpeg 边下边转
STREAM_EXTS = {".m3u8", ".mpd", ".ism"}
# 分片格式：单独抓一个分片没有意义，只在 <video>/<source> 明确给出时才收
SEGMENT_EXTS = {".ts", ".m4s"}
# 正文正则扫描的扩展名集合（刻意不含 .ts/.m4s，否则会把 TypeScript 文件当成视频）
LOOSE_EXTS = VIDEO_EXTS | STREAM_EXTS

KIND_BY_EXT = {".m3u8": "HLS", ".mpd": "DASH", ".ism": "SmoothStreaming"}
for _e in SEGMENT_EXTS:
    KIND_BY_EXT[_e] = "分片"

MAX_HTML_BYTES = 8 * 1024 * 1024
DEFAULT_TIMEOUT = 20

_EXT_ALT = "|".join(
    sorted((re.escape(e[1:]) for e in LOOSE_EXTS), key=len, reverse=True)
)
# 正文里扫 URL：协议可有可无，扩展名后必须是边界，避免 .mp4x 之类的误判
_MEDIA_RX = re.compile(
    r"(?:https?:)?//[^\s\"'<>\\(){}\[\]]+?\.(?:" + _EXT_ALT + r")(?![0-9A-Za-z])"
    r"(?:\?[^\s\"'<>\\()\[\]]*)?",
    re.IGNORECASE,
)
# <meta> 里可能藏视频地址的键
_META_VIDEO_KEYS = (
    "og:video", "og:video:url", "og:video:secure_url", "og:video:iframe",
    "twitter:player:stream", "twitter:player", "video:url", "contenturl",
)


class SniffError(Exception):
    """嗅探过程中的可预期失败（网络、编码、非网页内容）。"""


class Candidate:
    """一个候选视频地址。

    user_agent / cookie 只在「浏览器嗅探」来的候选上有值 ——
    签名地址常常跟 UA 绑定，下载时要原样带上。
    """

    __slots__ = ("url", "ext", "kind", "source", "user_agent", "cookie", "size")

    def __init__(self, url: str, ext: str, source: str,
                 user_agent: str = "", cookie: str = "", size: int = 0):
        self.url = url
        self.ext = ext
        self.kind = KIND_BY_EXT.get(ext, "视频")
        self.source = source
        self.user_agent = user_agent
        self.cookie = cookie
        self.size = size

    @property
    def name(self) -> str:
        """URL 里的文件名，用作标题兜底。"""
        try:
            path = urllib.parse.urlsplit(self.url).path
        except ValueError:
            path = self.url
        base = urllib.parse.unquote(path.rsplit("/", 1)[-1])
        return base or "(无文件名)"

    def as_row(self):
        return (self.kind, self.ext or "-", self.source, self.name, self.url)


# --------------------------------------------------------------------------
# 取页面
# --------------------------------------------------------------------------

def _decompress(raw: bytes, encoding: str) -> bytes:
    enc = (encoding or "").lower()
    try:
        if "gzip" in enc:
            return gzip.decompress(raw)
        if "deflate" in enc:
            try:
                return zlib.decompress(raw)
            except zlib.error:                      # 裸 deflate（无 zlib 头）
                return zlib.decompress(raw, -zlib.MAX_WBITS)
    except (OSError, zlib.error):
        return raw                                  # 解压失败就用原始字节，好过直接报错
    return raw


def _decode(raw: bytes, content_type: str) -> str:
    """尽量正确地解码：先看响应头，再看 <meta>，最后按中文站的常见编码猜。"""
    m = re.search(r"charset=([\w-]+)", content_type or "", re.I)
    candidates = [m.group(1)] if m else []
    head = raw[:4096].decode("ascii", "ignore")
    m = re.search(r"""charset\s*=\s*["']?([\w-]+)""", head, re.I)
    if m:
        candidates.append(m.group(1))
    candidates += ["utf-8", "gb18030", "big5", "latin-1"]
    for enc in candidates:
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", "replace")


def _open(url: str, referer: str = "", timeout: int = DEFAULT_TIMEOUT):
    req = urllib.request.Request(url, headers={
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
                  "application/vnd.apple.mpegurl,video/*;q=0.8,*/*;q=0.7",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        # 刻意不要 br：标准库解不了 brotli
        "Accept-Encoding": "gzip, deflate",
    })
    if referer:
        req.add_header("Referer", referer)
    ctx = ssl.create_default_context()
    return urllib.request.urlopen(req, timeout=timeout, context=ctx)


def fetch(url: str, referer: str = "", timeout: int = DEFAULT_TIMEOUT):
    """GET 一个 URL，返回 (最终URL, Content-Type, 文本)。"""
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url.lstrip("/")
    try:
        with _open(url, referer, timeout) as resp:
            raw = resp.read(MAX_HTML_BYTES)
            ctype = resp.headers.get("Content-Type", "")
            final = resp.geturl()
            raw = _decompress(raw, resp.headers.get("Content-Encoding", ""))
    except urllib.error.HTTPError as e:
        raise SniffError(f"HTTP {e.code} {e.reason}") from e
    except urllib.error.URLError as e:
        raise SniffError(f"连接失败：{e.reason}") from e
    except (OSError, ValueError) as e:
        raise SniffError(f"请求出错：{e}") from e
    return final, ctype, _decode(raw, ctype)


# --------------------------------------------------------------------------
# 解析页面
# --------------------------------------------------------------------------

class _PageParser(HTMLParser):
    """收集标题、<base>、媒体标签、可能藏视频地址的 meta 和 JSON-LD。"""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.base = ""
        self.title = ""
        self.og_title = ""
        self.tag_urls = []          # (url, 来源说明)
        self.meta_urls = []
        self.jsonld = []
        self._capture = None
        self._buf = []

    def _start(self, tag):
        self._capture = tag
        self._buf = []

    def _finish(self):
        text = "".join(self._buf).strip()
        if self._capture == "title" and text:
            self.title = text
        elif self._capture == "jsonld" and text:
            self.jsonld.append(text)
        self._capture = None
        self._buf = []

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "base" and a.get("href"):
            self.base = a["href"].strip()
        elif tag in ("title", "script"):
            if tag == "script":
                if "ld+json" in a.get("type", "").lower():
                    self._start("jsonld")
            else:
                self._start("title")
        elif tag in ("video", "audio"):
            for key in ("src", "data-src", "data-url"):
                if a.get(key):
                    self.tag_urls.append((a[key], f"<{tag}> 标签"))
        elif tag == "source":
            if a.get("src"):
                self.tag_urls.append((a["src"], "<source> 标签"))
        elif tag == "a" and a.get("href"):
            self.tag_urls.append((a["href"], "页面链接"))
        elif tag in ("embed", "iframe") and a.get("src"):
            self.tag_urls.append((a["src"], f"<{tag}> 标签"))
        elif tag == "meta":
            key = (a.get("property") or a.get("name") or "").lower()
            content = a.get("content", "").strip()
            if not content:
                return
            if key == "og:title" and not self.og_title:
                self.og_title = content
            elif key in ("twitter:title",) and not self.og_title:
                self.og_title = content
            elif key in _META_VIDEO_KEYS:
                self.meta_urls.append((content, f"meta {key}"))

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_data(self, data):
        if self._capture:
            self._buf.append(data)

    def handle_endtag(self, tag):
        if self._capture and (tag == self._capture or
                              (self._capture == "jsonld" and tag == "script")):
            self._finish()


def _ext_of(url: str) -> str:
    try:
        path = urllib.parse.urlsplit(url).path
    except ValueError:
        return ""
    m = re.search(r"\.([A-Za-z0-9]{2,5})$", path)
    return "." + m.group(1).lower() if m else ""


def normalize(raw: str, base: str):
    """把页面里抽出来的原始地址整理成绝对 URL；不是 http(s) 就返回 None。"""
    u = html.unescape(raw).replace("\\/", "/").strip().strip("\"'")
    u = u.rstrip(",;")
    if not u or u.startswith(("data:", "blob:", "javascript:", "#")):
        return None
    if u.startswith("//"):
        u = urllib.parse.urlsplit(base).scheme + ":" + u
    try:
        u = urllib.parse.urljoin(base, u)
        p = urllib.parse.urlsplit(u)
    except ValueError:
        return None
    if p.scheme not in ("http", "https") or not p.netloc:
        return None
    return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path, p.query, ""))


def guess_ext(url: str) -> str:
    """猜扩展名，连 query 里的 mime_type 提示也算上。

    浏览器嗅探出来的地址经常没有后缀（抖音那种 `.../video/tos/cn/xxx/?mime_type=video_mp4`），
    只看路径会误判成"未知格式"，进而在下载后白白多跑一次转码。
    """
    ext = _ext_of(url)
    if ext:
        return ext
    try:
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
    except ValueError:
        return ""
    mt = (q.get("mime_type") or [""])[0].lower()
    if not mt:
        return ""
    if "mp4" in mt or "m4v" in mt:
        return ".mp4"
    if "mpegurl" in mt or "m3u8" in mt:
        return ".m3u8"
    if "webm" in mt:
        return ".webm"
    if "matroska" in mt:
        return ".mkv"
    return ""


def _collect_jsonld_urls(texts):
    """从 JSON-LD / 内联 JSON 里挖 contentUrl、url 之类的媒体地址。"""
    found = []
    for text in texts:
        try:
            data = json.loads(text)
        except (ValueError, TypeError):
            continue
        stack = [data]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                for k, v in node.items():
                    if isinstance(v, str) and k.lower() in (
                            "contenturl", "url", "videourl", "embedurl"):
                        found.append(v)
                    elif isinstance(v, (dict, list)):
                        stack.append(v)
            elif isinstance(node, list):
                stack.extend(node)
    return found


def extract(html_text: str, base: str):
    """从页面文本里提取候选地址，按可信度从高到低去重。"""
    p = _PageParser()
    try:
        p.feed(html_text)
    except Exception:                               # 畸形 HTML 不该让整次嗅探失败
        pass
    try:
        p.close()
    except Exception:
        pass

    if p.base:
        base = urllib.parse.urljoin(base, p.base)

    seen = {}
    order = []

    def add(raw, source, allow_segment=False):
        url = normalize(raw, base)
        if not url:
            return
        ext = _ext_of(url)
        if ext in SEGMENT_EXTS and not allow_segment:
            return
        if ext not in LOOSE_EXTS and ext not in SEGMENT_EXTS:
            return
        if url in seen:
            return
        seen[url] = Candidate(url, ext, source)
        order.append(url)

    # 1) 标签直接声明的源 —— 最可信
    for raw, source in p.tag_urls:
        add(raw, source, allow_segment=True)
    # 2) meta 声明
    for raw, source in p.meta_urls:
        add(raw, source)
    # 3) JSON-LD / 内联 JSON
    for raw in _collect_jsonld_urls(p.jsonld):
        add(raw, "JSON-LD")
    # 4) 正文全文扫描（含 转义过的 \/ 形式）
    for text in (html_text, html_text.replace("\\/", "/")):
        for m in _MEDIA_RX.finditer(text):
            add(m.group(0), "页面正文")

    return [seen[u] for u in order], (p.og_title or p.title).strip()


# --------------------------------------------------------------------------
# 对外入口
# --------------------------------------------------------------------------

class SniffResult:
    __slots__ = ("final_url", "title", "candidates", "is_media", "note")

    def __init__(self, final_url, title, candidates, is_media=False, note=""):
        self.final_url = final_url
        self.title = title
        self.candidates = candidates
        self.is_media = is_media
        self.note = note


def _is_media_response(url: str, ctype: str) -> bool:
    ct = (ctype or "").split(";")[0].strip().lower()
    if ct.startswith(("video/", "audio/")) or ct in (
            "application/vnd.apple.mpegurl", "application/x-mpegurl",
            "application/dash+xml", "application/octet-stream"):
        return True
    return _ext_of(url) in (LOOSE_EXTS | SEGMENT_EXTS)


def sniff(url: str, referer: str = "", timeout: int = DEFAULT_TIMEOUT) -> SniffResult:
    """嗅探一个网址。

    网址本身就是媒体文件时直接返回它；否则抓页面、解析出所有候选。
    """
    url = url.strip()
    if not url:
        raise SniffError("网址是空的")
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url.lstrip("/")

    # 网址后缀直接就是媒体 → 不用抓页面了
    ext = _ext_of(url)
    if ext in LOOSE_EXTS:
        name = urllib.parse.unquote(urllib.parse.urlsplit(url).path.rsplit("/", 1)[-1])
        return SniffResult(url, name, [Candidate(url, ext, "输入网址本身")],
                           is_media=True, note="网址本身就是媒体文件")

    final, ctype, text = fetch(url, referer, timeout)

    if _is_media_response(final, ctype):
        ext = _ext_of(final) or ".mp4"
        name = urllib.parse.unquote(urllib.parse.urlsplit(final).path.rsplit("/", 1)[-1])
        return SniffResult(final, name or "video",
                           [Candidate(final, ext, "响应内容")],
                           is_media=True, note=f"服务器直接返回媒体（{ctype.split(';')[0]}）")

    cands, title = extract(text, final)
    if not title:
        title = urllib.parse.urlsplit(final).netloc
    note = ""
    if not cands:
        note = ("页面里没找到静态视频地址。若是 YouTube / B 站这类 JS 渲染站点，"
                "请用「yt-dlp 下载」按钮。")
    return SniffResult(final, title, cands, note=note)


# --------------------------------------------------------------------------
# 自检：不联网，用内嵌页面验证解析逻辑
# --------------------------------------------------------------------------

_SELFTEST_HTML = """
<html><head>
  <base href="https://cdn.example.com/media/">
  <meta property="og:title" content="示例影片 第一集">
  <meta property="og:video" content="/media/promo.mkv">
  <title>被 og:title 覆盖的标题</title>
  <script type="application/ld+json">
  {"@type":"VideoObject","contentUrl":"https:\\/\\/cdn.example.com\\/media\\/ep1.webm"}
  </script>
</head><body>
  <video src="movie.mp4" poster="a.jpg"></video>
  <video><source src="https://cdn.example.com/media/clip.mkv" type="video/x-matroska"></video>
  <a href="extra/more.flv">下载</a>
  <a href="/other/notes.txt">文本，不该被收</a>
  <script>var s = "https://cdn.example.com/hls/index.m3u8?token=abc&x=1";</script>
  <p>裸地址 https://cdn.example.com/media/raw.mp4 和 TS 分片 https://cdn.example.com/seg/1.ts</p>
</body></html>
"""


def _selftest():
    base = "https://www.example.com/page/index.html"
    cands, title = extract(_SELFTEST_HTML, base)
    urls = {c.url: c for c in cands}

    assert title == "示例影片 第一集", f"标题取错了: {title!r}"

    expected = {
        "https://cdn.example.com/media/promo.mkv",      # meta，相对 <base> 解析
        "https://cdn.example.com/media/ep1.webm",       # JSON-LD，转义 \/ 还原
        "https://cdn.example.com/media/movie.mp4",      # <video src>，相对 <base>
        "https://cdn.example.com/media/clip.mkv",       # <source src>
        "https://cdn.example.com/media/extra/more.flv",  # <a href>，相对 <base>
        "https://cdn.example.com/hls/index.m3u8?token=abc&x=1",  # 脚本里的 m3u8
        "https://cdn.example.com/media/raw.mp4",        # 正文裸地址
    }
    missing = expected - set(urls)
    assert not missing, f"漏掉了: {missing}"

    assert "https://cdn.example.com/other/notes.txt" not in urls, "把 txt 当成视频了"
    assert not any(u.endswith(".ts") for u in urls), "正文扫描不该收 .ts 分片"
    assert urls["https://cdn.example.com/hls/index.m3u8?token=abc&x=1"].kind == "HLS"

    # 网址本身就是媒体 → 不该发起网络请求
    res = sniff("https://x.test/a/b/影片 名.MKV")
    assert res.is_media and res.candidates[0].ext == ".mkv"
    assert res.title == "影片 名.MKV", res.title

    # 去重：同一地址在标签和正文里都出现，只能留一条
    assert len(urls) == len(cands), "有重复候选没去掉"

    # normalize 边界
    assert normalize("javascript:void(0)", base) is None
    assert normalize("data:video/mp4;base64,AAAA", base) is None
    assert normalize("//cdn.x/y.mp4", base) == "https://cdn.x/y.mp4"
    print(f"selftest OK - {len(cands)} 个候选，标题 {title!r}")


if __name__ == "__main__":
    _selftest()
