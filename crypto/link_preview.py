"""
SHROUD privately-fetched link previews.

The problem
-----------
Most messengers (Signal included) generate link previews on the
*recipient's* side: when you receive a message with a URL, your client
opens that URL to fetch the page title, description, og:image. The
server doesn't see it, but every recipient leaks "I opened this link"
to the URL's host. If 100 people receive a viral link, the link's host
sees 100 distinct request IPs correlated by time. Combined with anyone
who happens to see your IP (your ISP, a passive observer on the same
subnet), this trivially identifies recipients.

The fix
-------
Generate the preview on the **sender's** side, embed it in the
encrypted payload, and never let the URL touch the recipient's
network. The recipient renders entirely from cached metadata.

This module provides the sender-side fetcher. It:

  1. Detects URLs in outbound message text.
  2. For each URL, fetches the target page over a separate connection
     (preferably over Tor / SOCKS5 if the user has that enabled).
  3. Parses Open Graph + Twitter Card + standard <title> / <meta name=
     description> tags.
  4. Optionally fetches and re-encodes the og:image at a small size,
     stripping all metadata via crypto.strip_metadata.
  5. Returns a self-contained ``LinkPreview`` blob ready to be embedded
     into the sealed envelope's payload.

Rule compliance
---------------
  - Rule 1: irrelevant — preview is inside the payload, server sees
    only ciphertext.
  - Rule 2: irrelevant — preview rides the same routing tag as the
    message.
  - Rule 3: the og:image bytes pass through strip_metadata before
    being included, so EXIF/XMP/IPTC don't leak from the original
    asset.
  - Rule 0: stateless — no server involvement.
"""
from __future__ import annotations

import io
import re
import socket
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict
from html.parser import HTMLParser
from typing import List, Optional

from .strip_metadata import strip, UnsupportedMimeError, MalformedMediaError


# ── Public types ─────────────────────────────────────────────────────


@dataclass
class LinkPreview:
    """A self-contained preview blob ready to be embedded inside a
    sealed envelope. The recipient renders from this alone; no network
    activity required."""
    url: str
    title: Optional[str] = None
    description: Optional[str] = None
    site_name: Optional[str] = None
    image_mime: Optional[str] = None
    image_bytes: Optional[bytes] = None
    # SHA-256 of image_bytes for integrity if image is detached, can be
    # used by the recipient to verify content-addressed cache hits.
    image_hash: Optional[str] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        # image_bytes encodes as raw bytes which JSON can't carry; the
        # caller must base64 it explicitly. Keep this method honest by
        # not silently doing it for them.
        if self.image_bytes is not None:
            d["image_bytes_len"] = len(self.image_bytes)
        return d


# ── URL detection ────────────────────────────────────────────────────


URL_RE = re.compile(
    r"""
    \bhttps?://                # scheme — only http(s) considered, no mailto etc
    [^\s<>"']+                # rest of the URL up to whitespace or quote
    """,
    re.VERBOSE,
)


def extract_urls(text: str, max_urls: int = 4) -> List[str]:
    """Return up to ``max_urls`` URLs found in ``text``. Order preserved,
    duplicates collapsed."""
    seen = set()
    out = []
    for match in URL_RE.finditer(text or ""):
        url = match.group(0).rstrip(".,!?:;)>\"'")
        if url in seen:
            continue
        seen.add(url)
        out.append(url)
        if len(out) >= max_urls:
            break
    return out


# ── HTML parsing — pull <title>, og:*, twitter:*, meta description ──


class _MetaParser(HTMLParser):
    """Minimal HTML parser. We don't depend on BeautifulSoup so this
    runs without extra deps in low-spec clients."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title: Optional[str] = None
        self._in_title = False
        self.meta: dict = {}

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if tag == "title":
            self._in_title = True
        elif tag == "meta":
            a = dict(attrs)
            key = a.get("property") or a.get("name")
            val = a.get("content")
            if key and val:
                self.meta[key.lower()] = val

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            if self.title is None:
                self.title = ""
            self.title += data


# ── Fetcher ──────────────────────────────────────────────────────────


_FETCH_TIMEOUT_SECONDS = 10
_MAX_HTML_BYTES = 256 * 1024     # 256 KB cap on fetched HTML
_MAX_IMAGE_BYTES = 512 * 1024    # 512 KB cap on og:image
_FETCH_USER_AGENT = "Mozilla/5.0 (compatible; Shroud-LinkPreview/1.0)"

# Hosts we refuse to query because they reveal private network topology.
# Caller can extend if running a captive portal or LAN-internal preview.
_BLOCK_HOSTS = {
    "localhost", "127.0.0.1", "::1",
    "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
    "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.",
    "169.254.",  # link-local — also AWS metadata
}


def _is_safe_url(url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False
    host = (parsed.hostname or "").lower()
    if not host:
        return False
    for blocked in _BLOCK_HOSTS:
        if host == blocked or host.startswith(blocked):
            return False
    return True


def _http_get(url: str, max_bytes: int, *, proxy: Optional[str] = None) -> tuple[bytes, str]:
    """Fetch up to ``max_bytes`` from ``url``. Optionally route via a
    SOCKS5 proxy ("socks5h://host:port") for Tor users.

    Returns (body_bytes, content_type).
    """
    if not _is_safe_url(url):
        raise ValueError(f"refused to fetch URL: {url}")

    if proxy:
        # urllib doesn't natively support SOCKS — caller must install
        # PySocks and wire a custom opener. We surface a clear error
        # if asked to use a proxy without that support.
        raise NotImplementedError(
            "SOCKS proxy support requires PySocks; wire via socks.set_default_proxy() "
            "before calling fetch_preview()."
        )

    req = urllib.request.Request(url, headers={
        "User-Agent": _FETCH_USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,image/*;q=0.8,*/*;q=0.5",
    })
    with urllib.request.urlopen(req, timeout=_FETCH_TIMEOUT_SECONDS) as resp:
        ctype = (resp.headers.get_content_type() or "application/octet-stream").lower()
        body = resp.read(max_bytes + 1)
        if len(body) > max_bytes:
            raise ValueError(f"resource too large (> {max_bytes} bytes)")
    return body, ctype


def fetch_preview(url: str, *, fetch_image: bool = True,
                  proxy: Optional[str] = None) -> Optional[LinkPreview]:
    """Fetch a link preview for ``url``. Returns None if the URL is
    unreachable, returns content unsuitable for previewing, or fails
    safe-URL checks.

    Args:
        url: HTTPS or HTTP URL.
        fetch_image: if True, also fetch and metadata-strip og:image.
        proxy: optional SOCKS5 proxy ("socks5h://127.0.0.1:9050") for
               Tor users. Requires PySocks installed.
    """
    try:
        html, ctype = _http_get(url, _MAX_HTML_BYTES, proxy=proxy)
    except Exception:
        return None
    if "html" not in ctype:
        return None

    parser = _MetaParser()
    try:
        parser.feed(html.decode("utf-8", errors="replace"))
    except Exception:
        return None

    meta = parser.meta
    preview = LinkPreview(
        url=url,
        title=meta.get("og:title") or meta.get("twitter:title") or parser.title,
        description=meta.get("og:description") or meta.get("twitter:description") or meta.get("description"),
        site_name=meta.get("og:site_name") or meta.get("twitter:site"),
    )

    if fetch_image:
        img_url = meta.get("og:image") or meta.get("twitter:image")
        if img_url:
            img_url = urllib.parse.urljoin(url, img_url)
            try:
                img_bytes, img_ctype = _http_get(img_url, _MAX_IMAGE_BYTES, proxy=proxy)
                # Strip every byte of metadata before embedding (Rule 3).
                clean = strip(img_bytes, img_ctype)
                preview.image_mime = img_ctype.split(";")[0].strip()
                preview.image_bytes = clean.cleaned
                import hashlib
                preview.image_hash = hashlib.sha256(clean.cleaned).hexdigest()
            except (ValueError, UnsupportedMimeError, MalformedMediaError, Exception):
                # Couldn't fetch or couldn't safely strip. Drop image
                # silently — the title+description preview still ships.
                pass

    # Title/description optional but if BOTH are missing the preview
    # adds no value; skip it.
    if not preview.title and not preview.description:
        return None
    return preview


# ── Self-test ───────────────────────────────────────────────────────


def _self_test() -> None:
    # URL detection
    text = (
        "Check out https://example.com/foo, "
        "also see http://www.test.org/abc?x=1 and https://example.com/foo (dup)."
    )
    urls = extract_urls(text)
    assert urls == ["https://example.com/foo", "http://www.test.org/abc?x=1"], urls

    # Safe-URL filter
    assert not _is_safe_url("http://127.0.0.1/")
    assert not _is_safe_url("http://192.168.1.5/")
    assert not _is_safe_url("ftp://example.com/")
    assert _is_safe_url("https://example.com/foo")

    # HTML parsing
    sample = (
        '<html><head>'
        '<title>Foo</title>'
        '<meta property="og:title" content="Foo OG">'
        '<meta property="og:description" content="A page">'
        '<meta property="og:image" content="https://example.com/img.png">'
        '<meta name="description" content="fallback desc">'
        '</head><body>...</body></html>'
    )
    p = _MetaParser()
    p.feed(sample)
    assert p.title == "Foo"
    assert p.meta.get("og:title") == "Foo OG"
    assert p.meta.get("og:image") == "https://example.com/img.png"

    print("link_preview self-tests passed.")


if __name__ == "__main__":
    _self_test()
