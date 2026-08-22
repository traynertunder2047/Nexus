"""Stage 2 Sherlock: probe platform avatar/endpoint schemas for OCR'd
handles plus reverse-search match images, then apply a two-tier visual
gate (strong <= gate, weak <= gate re-checked with ORB when opencv is
available). Built-in average-hash fallback when imagehash is absent."""

import io
import re
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

import requests
from PIL import Image

from .config import PipelineConfig
from .contracts import Candidate, StageResult

try:
    import imagehash
except ImportError:
    imagehash = None

try:
    import cv2
except ImportError:
    cv2 = None


def _avg_hash(img: Image.Image, hash_size: int = 8) -> str:
    """Dependency-free average hash (PIL only); weaker than pHash but
    lets the visual gate work without the imagehash package."""
    small = img.convert("L").resize((hash_size, hash_size), Image.LANCZOS)
    px = list(small.getdata())
    avg = sum(px) / len(px)
    bits = "".join("1" if v > avg else "0" for v in px)
    return "%016x" % int(bits, 2)


def _hamming(hex_a: str, hex_b: str) -> int:
    """Hamming distance between two hex hash strings."""
    return bin(int(hex_a, 16) ^ int(hex_b, 16)).count("1")


def _compute_phash(img: Image.Image) -> str:
    """Perceptual hash: imagehash.phash when available, built-in avhash else."""
    if imagehash is not None:
        return str(imagehash.phash(img))
    return _avg_hash(img)


def _orb_verify(src: Image.Image, cand: Image.Image) -> float:
    """ORB keypoint match ratio; >= 0.15 -> plausible same image/scene."""
    try:
        import numpy as np
    except ImportError:
        return 0.0
    if cv2 is None:
        return 0.0
    s = cv2.cvtColor(np.array(src.convert("RGB")), cv2.COLOR_RGB2GRAY)
    c = cv2.cvtColor(np.array(cand.convert("RGB")), cv2.COLOR_RGB2GRAY)
    orb = cv2.ORB_create(500)
    k1, d1 = orb.detectAndCompute(s, None)
    k2, d2 = orb.detectAndCompute(c, None)
    if d1 is None or d2 is None or len(d1) < 10 or len(d2) < 10:
        return 0.0
    bf = cv2.BFMatcher(cv2.NORM_HAMMING)
    matches = bf.knnMatch(d1, d2, k=2)
    good = [m for m, n in matches if m.distance < 0.75 * n.distance]
    return len(good) / min(len(k1), len(k2))


def _is_uniform(img: Image.Image, threshold: float = 6.0) -> bool:
    """True when the image has near-zero luminance variance.

    Uniform images are degenerate for any average/pHash (all-zeros hash,
    distance 0 vs any other flat image) - they must not enter the visual
    gate or they produce false strong matches.
    """
    gray = img.convert("L").resize((64, 64))
    px = list(gray.getdata())
    if len(px) < 2:
        return True
    mean = sum(px) / len(px)
    variance = sum((p - mean) ** 2 for p in px) / len(px)
    return variance ** 0.5 < threshold


def _match_verdict(distance: int, cand_img: Image.Image, src_img: Image.Image,
                   cfg: PipelineConfig) -> Optional[dict]:
    """Two-tier gate: strong <= strong_phash_gate; weak <= weak_phash_gate
    re-checked with ORB when opencv is available."""
    if distance <= cfg.strong_phash_gate:
        return {"tier": "strong", "confidence": 0.6}
    if distance <= cfg.weak_phash_gate:
        if cv2 is not None:
            ratio = _orb_verify(src_img, cand_img)
            if ratio >= 0.15:
                return {"tier": "weak+orb", "confidence": 0.4, "ratio": round(ratio, 2)}
            return None
        return {"tier": "weak (no opencv verification)", "confidence": 0.3}
    return None


SHERLOCK_SCHEMAS = {
    "github":    {"kind": "json", "url": "https://api.github.com/users/{handle}",
                  "avatar": "avatar_url"},
    "telegram":  {"kind": "html", "url": "https://t.me/{handle}"},
    "reddit":    {"kind": "json", "url": "https://old.reddit.com/user/{handle}/about.json",
                  "avatar": "icon_img"},
    "steam":     {"kind": "xml", "url": "https://steamcommunity.com/id/{handle}?xml=1",
                  "avatar": "avatarMedium"},
    "tiktok":    {"kind": "json", "url": "https://www.tiktok.com/oembed?url=https://www.tiktok.com/@{handle}",
                  "avatar": "thumbnail_url"},
    "youtube":   {"kind": "html", "url": "https://www.youtube.com/@{handle}"},
    "instagram": {"kind": "html", "url": "https://www.instagram.com/{handle}/"},
    "x":         {"kind": "img",
                  "url": "https://api.twitter.com/i/users/profile_image?screen_name={handle}&size=original"},
}

HTML_OG_IMAGE_RE = (
    re.compile(r'<meta[^>]+property=["\']og:image["\'][^>]+content=["\']([^"\']+)["\']', re.I),
    re.compile(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+property=["\']og:image["\']', re.I),
)


def _avatar_url_from_response(schema: dict, resp: requests.Response) -> Optional[str]:
    """Extract the avatar/profile-image URL from a schema-specific response."""
    kind = schema.get("kind")
    try:
        if kind == "json":
            data = resp.json()
            key = schema.get("avatar")
            value = data.get(key) if isinstance(data, dict) else None
            return value or None
        if kind == "xml":
            m = re.search(rf"<{schema['avatar']}[^>]*>([^<]+)</{schema['avatar']}>", resp.text)
            return m.group(1) if m else None
        if kind == "html":
            for pattern in HTML_OG_IMAGE_RE:
                m = pattern.search(resp.text)
                if m:
                    return m.group(1)
    except Exception:
        pass
    return None


def _fetch_bytes(url: str, cfg: PipelineConfig) -> Optional[bytes]:
    """Fetch raw bytes with politeness headers; None on any failure."""
    try:
        resp = requests.get(url, headers={"User-Agent": cfg.nominatim_ua},
                            timeout=cfg.probe_timeout, allow_redirects=True)
        if resp.status_code != 200:
            return None
        return resp.content
    except requests.RequestException:
        return None


def _probe_one(platform: str, schema: dict, handle: str, src_hash: str, src_img: Image.Image,
               cfg: PipelineConfig) -> Optional[dict]:
    """Probe one platform schema for the handle's avatar and gate it visually."""
    try:
        url = schema["url"].format(handle=handle)
    except (KeyError, IndexError):
        return None
    try:
        resp = requests.get(url, headers={"User-Agent": cfg.nominatim_ua},
                            timeout=cfg.probe_timeout, allow_redirects=True)
    except requests.RequestException:
        return None
    if resp.status_code != 200:
        return None
    avatar_bytes = None
    avatar_url = url
    if schema.get("kind") == "img":
        avatar_bytes = resp.content
    else:
        avatar_url = _avatar_url_from_response(schema, resp)
        if not avatar_url:
            return None
        avatar_bytes = _fetch_bytes(avatar_url, cfg)
    if not avatar_bytes or len(avatar_bytes) < 100:
        return None
    try:
        cand_img = Image.open(io.BytesIO(avatar_bytes))
        cand_img.load()
    except Exception:
        return None
    if _is_uniform(cand_img):
        return None
    distance = _hamming(src_hash, _compute_phash(cand_img))
    verdict = _match_verdict(distance, cand_img, src_img, cfg)
    if not verdict:
        return None
    return {"platform": platform, "handle": handle, "url": avatar_url,
            "distance": distance, **verdict}


def stage2_sherlock(handles: list, image_urls: list, image_path: str,
                    cfg: PipelineConfig) -> StageResult:
    """Probe platform/avatar endpoints for handles + reverse-search match
    images; two-tier visual gate vs the source photo.

    strong (<= strong_phash_gate) -> high confidence Candidate; weak
    (<= weak_phash_gate) -> ORB re-check when opencv available, else kept
    at reduced confidence; beyond -> discarded with trace entry.
    """
    started = time.time()
    if not handles and not image_urls:
        return StageResult("sherlock", "no_data", 0.0, {"candidates": []},
                           "no handles or match URLs to probe", time.time() - started)
    try:
        src_img = Image.open(image_path).convert("RGB")
        src_img.load()
    except Exception as exc:
        return StageResult("sherlock", "error", 0.0, {"candidates": []},
                           str(exc), time.time() - started)
    if _is_uniform(src_img):
        return StageResult("sherlock", "no_data", 0.0, {"candidates": []},
                           "source image too uniform for visual matching",
                           time.time() - started)
    src_hash = _compute_phash(src_img)

    found = []
    jobs = [(platform, schema, handle)
            for handle in handles
            for platform, schema in SHERLOCK_SCHEMAS.items()]
    with ThreadPoolExecutor(max_workers=cfg.max_probe_workers) as pool:
        futures = [pool.submit(_probe_one, platform, schema, handle, src_hash, src_img, cfg)
                   for platform, schema, handle in jobs]
        for future in futures:
            result = future.result()
            if result:
                found.append(result)

    for url in image_urls:
        data = _fetch_bytes(url, cfg)
        if not data or len(data) < 100:
            continue
        try:
            cand_img = Image.open(io.BytesIO(data))
            cand_img.load()
        except Exception:
            continue
        if _is_uniform(cand_img):
            continue
        distance = _hamming(src_hash, _compute_phash(cand_img))
        verdict = _match_verdict(distance, cand_img, src_img, cfg)
        if verdict:
            found.append({"platform": "reverse_search", "handle": url[:80],
                          "url": url, "distance": distance, **verdict})

    if not found:
        return StageResult("sherlock", "no_data", 0.0, {"candidates": []},
                           f"{len(jobs)} probes, no visual matches", time.time() - started)

    candidates = [
        Candidate(
            lat=None, lon=None,
            source=f"sherlock:{hit['platform']}",
            confidence=hit["confidence"],
            url=hit["url"],
            reason=f"avatar of @{hit['handle']} matches photo (hamming {hit['distance']}, {hit['tier']})",
        ) for hit in found]
    note = f"{len(candidates)} visual match(es) from {len(jobs)} probes"
    return StageResult("sherlock", "ok", 0.5, {"candidates": candidates, "matches": found},
                       note, time.time() - started)