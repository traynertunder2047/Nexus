"""Stage 1: reverse-image search (reuses Locus's providers - the API
keys are shared) plus page fetching with og:image / title / author
extraction that feeds the identity-context stage."""

import re
from typing import Optional

import requests

from ..locus.config import PipelineConfig
from ..locus.contracts import StageResult
from ..locus.reverse_search import stage1_reverse_search as _locus_reverse
from .config import DoppelConfig

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
AUTHOR_RE = re.compile(
    r'<meta[^>]+name=["\'](?:author|article:author|twitter:creator)["\'][^>]+'
    r'content=["\']([^"\']+)["\']', re.I)
OG_TITLE_RE = (
    re.compile(r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\']([^"\']+)["\']', re.I),
    re.compile(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+property=["\']og:title["\']', re.I),
)
OG_IMAGE_RE = (
    re.compile(r'<meta[^>]+property=["\']og:image["\'][^>]+content=["\']([^"\']+)["\']', re.I),
    re.compile(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+property=["\']og:image["\']', re.I),
)


def stage1_reverse(image_path: str, cfg: DoppelConfig) -> StageResult:
    """Reverse-image search via Locus providers (keys shared via .env)."""
    locus_cfg = PipelineConfig(keys=cfg.keys, nominatim_ua=cfg.nominatim_ua,
                               probe_timeout=cfg.probe_timeout,
                               max_reverse_matches=cfg.max_matches)
    return _locus_reverse(image_path, locus_cfg)


def _fetch_page(url: str, cfg: DoppelConfig) -> Optional[str]:
    """Fetch a page's HTML text; None on failure or non-HTML content."""
    try:
        resp = requests.get(url, headers={"User-Agent": cfg.nominatim_ua},
                            timeout=cfg.probe_timeout, allow_redirects=True)
        if resp.status_code != 200:
            return None
        ctype = resp.headers.get("Content-Type", "")
        if "html" not in ctype and not resp.text.strip().startswith(("<", "<!DOCTYPE")):
            return None
        return resp.text[:200_000]
    except requests.RequestException:
        return None


def _og_image(html: str) -> Optional[str]:
    """First og:image URL in the page."""
    for pattern in OG_IMAGE_RE:
        m = pattern.search(html)
        if m:
            return m.group(1)
    return None


def _page_info(html: str) -> dict:
    """Title, author and og:title/og:image of a page."""
    title, author, og_title = "", "", ""
    m = TITLE_RE.search(html)
    if m:
        title = re.sub(r"\s+", " ", m.group(1)).strip()[:200]
    m = AUTHOR_RE.search(html)
    if m:
        author = m.group(1).strip()[:200]
    for pattern in OG_TITLE_RE:
        m = pattern.search(html)
        if m:
            og_title = m.group(1).strip()[:200]
            break
    return {"title": title, "author": author, "og_title": og_title,
            "og_image": _og_image(html)}