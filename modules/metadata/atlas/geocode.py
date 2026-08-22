"""Stage 1: forward geocoding of each extracted candidate.

Providers: Nominatim search (primary, free, UA required, 1 req/s),
Photon (fallback, free, no key), Google Geocoding (optional third
provider, only when GOOGLE_GEOCODING_API_KEY is set). Provider failures
are isolated - one error never aborts the others."""

import re
import time

import requests

from ..locus.contracts import StageResult
from ..locus.overpass import CITY_SUFFIX_WORDS
from ..locus.ratelimit import wait_nominatim
from .config import AtlasConfig


def _nominatim_search(query: str, cfg: AtlasConfig) -> list:
    """Forward geocode via Nominatim search; 1 req/s enforced (shared
    limiter: also covers Locus's reverse-geocode stage in this process)."""
    wait_nominatim()
    resp = requests.get(
        "https://nominatim.openstreetmap.org/search",
        params={"q": query, "format": "jsonv2", "addressdetails": 1,
                "limit": cfg.geocode_limit},
        headers={"User-Agent": cfg.nominatim_ua},
        timeout=cfg.probe_timeout,
    )
    if resp.status_code == 429:
        return []
    resp.raise_for_status()
    hits = []
    for item in resp.json():
        if item.get("lat") is None or item.get("lon") is None:
            continue
        addr = item.get("address") or {}
        hits.append({
            "lat": float(item["lat"]), "lon": float(item["lon"]),
            "display_name": item.get("display_name", ""),
            "type": item.get("type") or item.get("class", ""),
            "importance": float(item.get("importance") or 0.0),
            "country": addr.get("country", ""),
            "provider": "nominatim",
        })
    return hits


def _photon_search(query: str, cfg: AtlasConfig) -> list:
    """Fallback forward geocode via Photon (free, no key)."""
    resp = requests.get("https://photon.komoot.io/api/",
                        params={"q": query, "limit": cfg.geocode_limit},
                        timeout=cfg.probe_timeout)
    resp.raise_for_status()
    hits = []
    for feat in (resp.json().get("features") or []):
        props = feat.get("properties") or {}
        geom = feat.get("geometry") or {}
        coords = geom.get("coordinates")
        if not coords:
            continue
        lon, lat = coords[0], coords[1]
        name = (props.get("name") or props.get("city") or props.get("street") or "")
        hits.append({
            "lat": float(lat), "lon": float(lon),
            "display_name": name,
            "type": props.get("type", ""),
            "importance": 0.4,
            "country": props.get("country", ""),
            "provider": "photon",
        })
    return hits


def _google_search(query: str, cfg: AtlasConfig) -> list:
    """Optional third provider: Google Geocoding (keyed)."""
    resp = requests.get("https://maps.googleapis.com/maps/api/geocode/json",
                        params={"address": query, "key": cfg.keys["google_geocoding"]},
                        timeout=cfg.probe_timeout)
    resp.raise_for_status()
    hits = []
    for item in (resp.json().get("results") or [])[:cfg.geocode_limit]:
        loc = (item.get("geometry") or {}).get("location") or {}
        if loc.get("lat") is None or loc.get("lng") is None:
            continue
        country = ""
        for comp in item.get("address_components", []):
            if "country" in comp.get("types", []):
                country = comp.get("long_name", "")
        hits.append({
            "lat": float(loc["lat"]), "lon": float(loc["lng"]),
            "display_name": item.get("formatted_address", ""),
            "type": (item.get("types") or [""])[0],
            "importance": 0.5,
            "country": country,
            "provider": "google",
        })
    return hits


def _geocode_one(query: str, cfg: AtlasConfig) -> tuple:
    """All providers for one query -> (hits, errors)."""
    hits, errors = [], []
    try:
        hits += _nominatim_search(query, cfg)
    except Exception as exc:
        errors.append(f"nominatim: {exc}")
    if not hits:
        try:
            hits += _photon_search(query, cfg)
        except Exception as exc:
            errors.append(f"photon: {exc}")
    if cfg.keys.get("google_geocoding"):
        try:
            hits += _google_search(query, cfg)
        except Exception as exc:
            errors.append(f"google: {exc}")
    return hits, errors


def stage1_geocode(candidates: list, cfg: AtlasConfig) -> StageResult:
    """Geocode every extracted candidate; street/POI names are queried
    together with the city candidate when one was extracted ("Via Roma,
    Milano" instead of bare "Via Roma" - city context disambiguates)."""
    started = time.time()
    if not candidates:
        return StageResult("geocode", "no_data", 0.0, {"results": []},
                           "no candidates to geocode", time.time() - started)
    cities = [c["name"] for c in candidates if c["name"].lower() in CITY_SUFFIX_WORDS]
    results, errors = [], []
    for cand in candidates[:cfg.max_candidates]:
        name = cand["name"]
        query = name
        if name.lower() not in CITY_SUFFIX_WORDS and cities:
            query = f"{name}, {cities[0]}"
        hits, errs = _geocode_one(query, cfg)
        errors.extend(errs)
        if hits:
            results.append({"candidate": name, "query": query, "kind": cand["kind"],
                            "context": cand.get("context", ""), "hits": hits})
    if not results:
        status = "error" if errors else "no_data"
        note = "; ".join(errors) if errors else "providers returned no hits"
        return StageResult("geocode", status, 0.0, {"results": []},
                           note, time.time() - started)
    return StageResult("geocode", "ok", 0.5, {"results": results},
                       f"{len(results)}/{len(candidates)} candidates resolved",
                       time.time() - started)