"""Stage 1 reverse-image search: Google Vision / SerpApi / TinEye /
SauceNAO. Provider failures are isolated - one error never aborts the
others, and stages without configured keys report "skipped"."""

import base64
import hashlib
import os
import time

import requests

from .config import PipelineConfig
from .contracts import StageResult


def _parse_vision(data: dict) -> list:
    """Parse Google Vision webDetection response into match dicts."""
    matches = []
    det = (data.get("responses") or [{}])[0].get("webDetection") or {}
    for item in det.get("fullMatchingImages", []) + det.get("partialMatchingImages", []):
        if item.get("url"):
            matches.append({"url": item["url"], "source": "google_vision"})
    for page in det.get("pagesWithMatchingImages", []):
        if page.get("url"):
            matches.append({"url": page["url"], "source": "google_vision",
                            "title": page.get("pageTitle", "")})
    return matches


def _vision_search(image_path: str, key: str, cfg: PipelineConfig) -> list:
    """Google Cloud Vision webDetection; base64 upload, no public URL needed."""
    with open(image_path, "rb") as f:
        payload = {"requests": [{
            "image": {"content": base64.b64encode(f.read()).decode()},
            "features": [{"type": "WEB_DETECTION"}],
        }]}
    resp = requests.post("https://vision.googleapis.com/v1/images:annotate",
                         params={"key": key}, json=payload, timeout=cfg.probe_timeout)
    resp.raise_for_status()
    return _parse_vision(resp.json())


def _parse_serpapi(data: dict, limit: int) -> list:
    """Parse SerpApi google_images response into match dicts."""
    matches = []
    for item in data.get("images_results", [])[:limit]:
        url = item.get("original") or item.get("link")
        if url:
            matches.append({"url": url, "source": "serpapi",
                            "title": item.get("title", ""),
                            "thumb": item.get("thumbnail", "")})
    return matches


def _serpapi_search(image_url: str, key: str, cfg: PipelineConfig) -> list:
    """SerpApi Google Images; requires a publicly reachable image URL."""
    resp = requests.get("https://serpapi.com/search.json",
                        params={"engine": "google_images", "image_url": image_url,
                                "api_key": key},
                        timeout=cfg.probe_timeout)
    resp.raise_for_status()
    return _parse_serpapi(resp.json(), cfg.max_reverse_matches)


def _tineye_sign(params: dict, private_key: str) -> str:
    """TinEye signature: md5 of sorted key=value pairs + private key."""
    text = "".join(f"{k}{params[k]}" for k in sorted(params))
    return hashlib.md5((text + private_key).encode()).hexdigest()


def _parse_tineye(data: dict) -> list:
    """Parse TinEye search response into match dicts."""
    matches = []
    for hit in (data.get("results") or [])[:10]:
        url = hit.get("image_url") or hit.get("backlink")
        if url:
            matches.append({"url": url, "source": "tineye",
                            "title": hit.get("backlink", "")})
    return matches


def _tineye_search(image_path: str, pub: str, priv: str, cfg: PipelineConfig) -> list:
    """TinEye REST search with the image uploaded as multipart file."""
    params = {"method": "search", "public_key": pub}
    params["api_key"] = _tineye_sign(params, priv)
    with open(image_path, "rb") as f:
        resp = requests.post("https://api.tineye.com/rest/", params=params,
                             files={"file": (os.path.basename(image_path), f)},
                             timeout=cfg.probe_timeout)
    resp.raise_for_status()
    return _parse_tineye(resp.json())


def _parse_saucenao(data: dict) -> list:
    """Parse SauceNAO response into match dicts."""
    matches = []
    for item in (data.get("results") or [])[:10]:
        header = item.get("header", {})
        urls = (item.get("data") or {}).get("ext_urls", [])
        url = urls[0] if urls else header.get("thumbnail", "")
        if url:
            matches.append({"url": url, "source": "saucenao",
                            "title": header.get("index_name", ""),
                            "thumb": header.get("thumbnail", "")})
    return matches


def _saucenao_search(image_path: str, key: str, cfg: PipelineConfig) -> list:
    """SauceNAO search with the image uploaded as multipart file."""
    with open(image_path, "rb") as f:
        resp = requests.post("https://saucenao.com/search.php",
                             data={"api_key": key, "output_type": "2"},
                             files={"file": (os.path.basename(image_path), f)},
                             timeout=cfg.probe_timeout)
    resp.raise_for_status()
    return _parse_saucenao(resp.json())


def stage1_reverse_search(image_path: str, cfg: PipelineConfig) -> StageResult:
    """Reverse-image search via configured providers; skipped without keys.

    Google Vision accepts local files (base64). SerpApi needs a public URL,
    so with a local file it is skipped with a note. TinEye/SauceNAO upload
    the file directly. Provider failures are isolated: one error never
    aborts the others.
    """
    started = time.time()
    if not any(cfg.keys.values()):
        return StageResult("reverse_search", "skipped", 0.0, {},
                           "no API keys configured (GOOGLE_VISION_API_KEY / SERPAPI_API_KEY / ...)")
    matches, providers, errors = [], [], []
    k = cfg.keys

    if k.get("google_vision"):
        providers.append("google_vision")
        try:
            matches += _vision_search(image_path, k["google_vision"], cfg)
        except Exception as exc:
            errors.append(f"google_vision: {exc}")
    if k.get("serpapi"):
        if image_path.startswith(("http://", "https://")):
            providers.append("serpapi")
            try:
                matches += _serpapi_search(image_path, k["serpapi"], cfg)
            except Exception as exc:
                errors.append(f"serpapi: {exc}")
        else:
            providers.append("serpapi (skipped: local file needs public URL)")
    if k.get("tineye_public") and k.get("tineye_private"):
        providers.append("tineye")
        try:
            matches += _tineye_search(image_path, k["tineye_public"], k["tineye_private"], cfg)
        except Exception as exc:
            errors.append(f"tineye: {exc}")
    if k.get("saucenao"):
        providers.append("saucenao")
        try:
            matches += _saucenao_search(image_path, k["saucenao"], cfg)
        except Exception as exc:
            errors.append(f"saucenao: {exc}")

    matches = matches[:cfg.max_reverse_matches]
    if matches:
        status, conf, note = "ok", 0.5, f"{len(matches)} matches from {len(providers)} provider(s)"
    elif errors and not providers:
        status, conf, note = "error", 0.0, "; ".join(errors)
    elif errors:
        status, conf, note = "no_data", 0.0, "; ".join(errors) + " - no matches"
    else:
        status, conf, note = "no_data", 0.0, "providers queried, no matches"
    return StageResult("reverse_search", status, conf,
                       {"matches": matches, "providers": providers, "errors": errors},
                       note, time.time() - started)