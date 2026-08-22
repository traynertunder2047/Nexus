"""Stage 2 Overpass: spatial queries for OCR-extracted POI names, bounded
to a GeoCLIP bounding box when available. Politeness: minimum 2s between
queries, one 5s-delayed retry on 429/504, three mirrors tried on failure."""

import re
import time
from typing import Optional

import requests

from .config import PipelineConfig
from .contracts import Candidate, StageResult
from .ocr import _extract_place_names
from .ratelimit import wait_overpass

OVERPASS_ENDPOINTS = (
    "https://overpass-api.de/api/interpreter",
    "https://overpass.kumi.systems/api/interpreter",
    "https://overpass.private.coffee/api/interpreter",
)

#test is needed
CITY_SUFFIX_WORDS = {
    "roma", "milano", "napoli", "torino", "firenze", "venezia", "bologna",
    "genova", "bari", "palermo", "catania", "verona", "paris", "london",
    "berlin", "madrid", "barcellona", "barcelona", "lisbona", "atene",
    "vienna", "praga", "varsavia", "budapest", "italia", "italy",
}

GENERIC_FIRST_WORDS = {
    "ristorante", "trattoria", "pizzeria", "hotel", "bar", "caffe", "cafè",
    "via", "piazza", "viale", "corso", "chiuso", "aperto", "osteria",
}


def _sanitize_name(name: str) -> str:
    """Strip punctuation for safe Overpass regex use; collapse whitespace."""
    return re.sub(r"\s+", " ", re.sub(r"[^\w\s]", " ", name)).strip()


def _name_variants(name: str) -> list:
    """Progressive query variants: full name, minus city suffix, first word.

    Variants shorter than 4 chars are dropped: regex substring matching
    would otherwise hit noise ("Via" matches "Ferrovia...").
    """
    words = name.split()
    variants = [name]
    if len(words) >= 2 and words[-1].lower() in CITY_SUFFIX_WORDS:
        variants.append(" ".join(words[:-1]))
    if len(words) >= 2 and words[0].lower() not in GENERIC_FIRST_WORDS:
        variants.append(words[0])
    return [v for v in dict.fromkeys(variants) if len(v) >= 4]


def _overpass_query(names: list, bbox: Optional[list], cfg: PipelineConfig) -> list:
    """POST bounded Overpass name queries; returns raw element dicts.

    Politeness: minimum 2s between queries (public mirrors throttle
    bursts), one 5s-delayed retry on 429/504, mirrors tried on failure.
    """
    results = []
    seen = set()
    headers = {"User-Agent": cfg.nominatim_ua, "Accept": "application/json"}
    for name in names[:3]:
        for variant in _name_variants(name):
            wait_overpass()
            q = f'[out:json][timeout:{cfg.overpass_timeout}];'
            b = ",".join(str(round(x, 4)) for x in bbox) if bbox else None
            target = f'["name"~"{variant}",i]({b})' if b else f'["name"~"{variant}",i]'
            q += "(" + "".join(f"{t}{target};" for t in ("node", "way", "rel")) + ");"
            q += "out center 15;"
            resp = None
            for attempt in range(2):
                for endpoint in OVERPASS_ENDPOINTS:
                    try:
                        wait_overpass()
                        resp = requests.post(endpoint, data={"data": q}, headers=headers,
                                             timeout=cfg.overpass_timeout + 10)
                        if resp.status_code == 200:
                            break
                    except requests.RequestException:
                        continue
                if resp is not None and resp.status_code == 200:
                    break
                time.sleep(5.0)
            if resp is None:
                raise RuntimeError("all Overpass mirrors unreachable")
            if resp.status_code != 200:
                raise RuntimeError(f"Overpass HTTP {resp.status_code} on all mirrors")
            for element in resp.json().get("elements", []):
                lat = element.get("lat") or (element.get("center") or {}).get("lat")
                lon = element.get("lon") or (element.get("center") or {}).get("lon")
                tags = element.get("tags", {})
                if lat is None or lon is None:
                    continue
                key = (round(lat, 5), round(lon, 5), element.get("id"))
                if key in seen:
                    continue
                seen.add(key)
                kind = (tags.get("amenity") or tags.get("shop") or tags.get("leisure")
                        or tags.get("tourism") or element.get("type"))
                results.append({
                    "lat": lat, "lon": lon,
                    "name": tags.get("name") or variant,
                    "kind": kind,
                    "url": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=17/{lat}/{lon}",
                })
            if results:
                break
    return results


def stage2_overpass(ocr_text: str, bbox: Optional[list], cfg: PipelineConfig) -> StageResult:
    """Query Overpass with OCR-extracted POI names + GeoCLIP bounding box."""
    started = time.time()
    if not ocr_text:
        return StageResult("overpass", "no_data", 0.0, {"candidates": [], "names": []},
                           "no OCR text to query", time.time() - started)
    names = [_sanitize_name(n) for n in _extract_place_names(ocr_text)]
    if not names:
        return StageResult("overpass", "no_data", 0.0, {"candidates": [], "names": []},
                           "no POI-like names in OCR text", time.time() - started)
    try:
        found = _overpass_query(names, bbox, cfg)
    except Exception as exc:
        return StageResult("overpass", "error", 0.0, {"candidates": [], "names": names},
                           str(exc), time.time() - started)
    if not found:
        return StageResult("overpass", "no_data", 0.0, {"candidates": [], "names": names},
                           "no OSM matches", time.time() - started)
    candidates = [
        Candidate(lat=hit["lat"], lon=hit["lon"], source="overpass", confidence=0.45,
                  url=hit["url"],
                  reason=f"{hit['name']} ({hit['kind'] or 'place'}) in OSM")
        for hit in found]
    note = f"{len(candidates)} OSM match(es) for {len(names)} name(s)"
    return StageResult("overpass", "ok", 0.45, {"candidates": candidates, "names": names},
                       note, time.time() - started)