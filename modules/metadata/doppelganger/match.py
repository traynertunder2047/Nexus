"""Stage 2: compare the source face against every image found by the
reverse search and against the avatars of optional handle hints.

Each candidate gets:
  - a face verdict (strong / lbph / weak) when a face is detected and
    matched - the identity proof;
  - the whole-image hash distance (same-image flag) - the account-
    correlation signal (same avatar reused across platforms).

Pages that fail to open as images are re-read as HTML and their og:image
is examined instead, so "the photo on this page" is compared even when
the page itself is not a direct image link."""

import io
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

import requests
from PIL import Image

from ..locus.contracts import StageResult
from ..locus.sherlock import (_avatar_url_from_response, _compute_phash,
                              _fetch_bytes, _hamming, SHERLOCK_SCHEMAS)
from .config import DoppelConfig
from .face import face_verdict, largest_face
from .reverse import _og_image


def _platform(url: str) -> str:
    """Best-effort platform guess from the URL host."""
    host = url.split("/")[2].lower() if "://" in url else (url.split("/")[0] or "").lower()
    for frag, name in (
        ("githubusercontent", "github"), ("github.com", "github"),
        ("t.me", "telegram"), ("reddit.com", "reddit"),
        ("steamcommunity", "steam"), ("steamstatic", "steam"),
        ("tiktok.com", "tiktok"), ("youtube.com", "youtube"), ("ytimg", "youtube"),
        ("instagram.com", "instagram"), ("cdninstagram", "instagram"),
        ("x.com", "x"), ("twitter.com", "x"), ("twimg", "x"),
        ("facebook.com", "facebook"), ("fbcdn", "facebook"), ("scontent", "facebook"),
        ("linkedin.com", "linkedin"), ("gravatar.com", "gravatar"),
        ("pinterest", "pinterest"), ("twitch.tv", "twitch"), ("discord", "discord"),
        ("discordapp", "discord"), ("tumblr", "tumblr"), ("vk.com", "vk"),
        ("weibo", "weibo"),
    ):
        if frag in host:
            return name
    return host or url[:40]


def _examine_image(data: Optional[bytes], src_face: Image.Image, src_img: Image.Image,
                   src_hash: str, url: str, source: str,
                   cfg: DoppelConfig) -> Optional[dict]:
    """Detect+compare face and whole-image hash of one fetched image."""
    if not data or len(data) < 100:
        return None
    try:
        cand = Image.open(io.BytesIO(data))
        cand.load()
    except Exception:
        return None
    entry = {"url": url, "source": source, "platform": _platform(url)}
    cand_face = largest_face(cand)
    if cand_face is not None:
        verdict = face_verdict(src_face, cand_face, cfg)
        if verdict:
            entry["face"] = verdict
    entry["image_distance"] = _hamming(src_hash, _compute_phash(cand))
    entry["same_image"] = entry["image_distance"] <= 10
    if "face" in entry or entry["same_image"]:
        return entry
    return None


def _examine_url(url: str, src_face: Image.Image, src_img: Image.Image,
                 src_hash: str, source: str, cfg: DoppelConfig) -> Optional[dict]:
    """Examine a URL as image; if that fails, treat it as an HTML page and
    examine its og:image instead."""
    entry = _examine_image(_fetch_bytes(url, cfg), src_face, src_img, src_hash,
                           url, source, cfg)
    if entry is not None:
        return entry
    html = _fetch_page_text(url, cfg)
    if not html:
        return None
    og = _og_image(html)
    if not og:
        return None
    e2 = _examine_image(_fetch_bytes(og, cfg), src_face, src_img, src_hash,
                        og, source + ":page", cfg)
    if e2 is not None:
        e2["page_url"] = url
    return e2


def _fetch_page_text(url: str, cfg: DoppelConfig) -> Optional[str]:
    """HTML text of a page; None unless it looks like HTML."""
    data = _fetch_bytes(url, cfg)
    if not data:
        return None
    text = data.decode("utf-8", errors="ignore")[:200_000]
    if not text.lstrip().startswith(("<", "<!DOCTYPE")):
        return None
    return text


def _probe_handle(handle: str, src_face: Image.Image, src_img: Image.Image,
                  src_hash: str, cfg: DoppelConfig) -> list:
    """Fetch the handle's avatar from every platform schema and compare."""
    out = []
    for platform, schema in SHERLOCK_SCHEMAS.items():
        try:
            url = schema["url"].format(handle=handle)
        except (KeyError, IndexError):
            continue
        try:
            resp = requests.get(url, headers={"User-Agent": cfg.nominatim_ua},
                                timeout=cfg.probe_timeout, allow_redirects=True)
        except requests.RequestException:
            continue
        if resp.status_code != 200:
            continue
        avatar_url, data = url, resp.content
        if schema.get("kind") != "img":
            avatar_url = _avatar_url_from_response(schema, resp)
            if not avatar_url:
                continue
            data = _fetch_bytes(avatar_url, cfg)
        entry = _examine_image(data, src_face, src_img, src_hash, avatar_url,
                               f"avatar:{platform}", cfg)
        if entry:
            entry["handle"] = handle
            out.append(entry)
    return out


def stage2_match(src_face: Image.Image, src_img: Image.Image, image_urls: list,
                 handles: list, cfg: DoppelConfig) -> StageResult:
    """Face-compare the source against reverse-search images + avatars."""
    started = time.time()
    if not image_urls and not handles:
        return StageResult("match", "no_data", 0.0, {"matches": []},
                           "no candidate images or handles to compare",
                           time.time() - started)
    src_hash = _compute_phash(src_img)
    entries = []
    with ThreadPoolExecutor(max_workers=cfg.max_probe_workers) as pool:
        futures = [pool.submit(_examine_url, u, src_face, src_img, src_hash,
                               "reverse_search", cfg) for u in image_urls]
        for h in handles:
            futures.append(pool.submit(_probe_handle, h, src_face, src_img,
                                       src_hash, cfg))
        for future in futures:
            result = future.result()
            if isinstance(result, list):
                entries.extend(result)
            elif result:
                entries.append(result)
    if not entries:
        return StageResult("match", "no_data", 0.0, {"matches": []},
                           "no candidate images matched", time.time() - started)

    def _key(e):
        fc = e.get("face", {}).get("confidence", 0.0) if "face" in e else 0.0
        return (fc, 1 if e.get("same_image") else 0)

    entries.sort(key=_key, reverse=True)
    faces = sum(1 for e in entries if "face" in e)
    note = f"{len(entries)} candidate link(s), {faces} face match(es)"
    return StageResult("match", "ok", 0.5, {"matches": entries},
                       note, time.time() - started)