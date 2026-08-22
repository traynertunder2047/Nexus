"""Stage 2: Overpass "what is at this place" - nearest named POIs around
the resolved coordinate, reusing Locus's mirror list and politeness
pattern (2s spacing, retry, mirrors)."""

import time

import requests

from ..locus.contracts import StageResult
from ..locus.overpass import OVERPASS_ENDPOINTS
from ..locus.ratelimit import wait_overpass
from .config import AtlasConfig


def _overpass_nearby(lat: float, lon: float, radius_m: int, cfg: AtlasConfig) -> list:
    """Named elements (node/way/rel) within radius of the coordinate."""
    headers = {"User-Agent": cfg.nominatim_ua, "Accept": "application/json"}
    q = (f"[out:json][timeout:{cfg.overpass_timeout}];"
         f"(node(around:{radius_m},{lat},{lon})[\"name\"];"
         f"way(around:{radius_m},{lat},{lon})[\"name\"];"
         f"rel(around:{radius_m},{lat},{lon})[\"name\"];);out center 20;")
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
    if resp is None or resp.status_code != 200:
        raise RuntimeError("all Overpass mirrors unreachable")
    nearby = []
    for element in resp.json().get("elements", []):
        tags = element.get("tags", {})
        name = tags.get("name")
        if not name:
            continue
        kind = (tags.get("amenity") or tags.get("shop") or tags.get("leisure")
                or tags.get("tourism") or element.get("type"))
        nearby.append({"name": name, "kind": kind,
                       "url": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=17/{lat}/{lon}"})
    return nearby


def stage2_context(lat: float, lon: float, cfg: AtlasConfig) -> StageResult:
    """POI context around the resolved location; isolated failures."""
    started = time.time()
    try:
        nearby = _overpass_nearby(lat, lon, cfg.nearby_radius_m, cfg)
    except Exception as exc:
        return StageResult("context", "error", 0.0, {"nearby": []},
                           str(exc), time.time() - started)
    if not nearby:
        return StageResult("context", "no_data", 0.0, {"nearby": []},
                           "no named POIs in range", time.time() - started)
    return StageResult("context", "ok", 0.3, {"nearby": nearby},
                       f"{len(nearby)} POI(s) within {cfg.nearby_radius_m} m",
                       time.time() - started)