"""Stage 0.5 cheap enrichment for the EXIF fast path: reverse geocoding
(Nominatim, cached, 1 req/s), filename provenance hints, timestamp sanity."""

import os
import re
import time
from datetime import datetime

import requests

from .config import PipelineConfig
from .contracts import StageResult
from .ratelimit import wait_nominatim

_GEOCODE_CACHE = {}


def stage05_reverse_geocode(lat: float, lon: float, cfg: PipelineConfig) -> StageResult:
    """Reverse-geocode EXIF coordinates via Nominatim (cached, 1 req/s)."""
    started = time.time()
    key = (round(lat, 5), round(lon, 5))
    if key in _GEOCODE_CACHE:
        return StageResult("reverse_geocode", "ok", 0.7,
                           {"place": _GEOCODE_CACHE[key]}, "cached", 0.0)
    try:
        wait_nominatim()
        resp = requests.get(
            "https://nominatim.openstreetmap.org/reverse",
            params={"lat": lat, "lon": lon, "format": "jsonv2"},
            headers={"User-Agent": cfg.nominatim_ua},
            timeout=10,
        )
        if resp.status_code == 429:
            return StageResult("reverse_geocode", "error", 0.0, {},
                               "Nominatim rate limited (429)", time.time() - started)
        resp.raise_for_status()
        place = resp.json().get("display_name", "") or ""
        _GEOCODE_CACHE[key] = place
        return StageResult("reverse_geocode", "ok" if place else "no_data",
                           0.7 if place else 0.0,
                           {"place": place},
                           "reverse geocoded" if place else "no place name for coordinates",
                           time.time() - started)
    except requests.RequestException as exc:
        return StageResult("reverse_geocode", "error", 0.0, {}, str(exc), time.time() - started)


FILENAME_PATTERNS = (
    ("whatsapp", re.compile(r"^(?:IMG|VID|WA|PXL)-\d{8}-WA\d{4}", re.I)),
    ("telegram", re.compile(r"^(?:IMG|VID)-\d{8}-\d{6}", re.I)),
    ("screenshot", re.compile(r"^(?:Screenshot|SCR)[_-]?\d{4}-\d{2}-\d{2}", re.I)),
    ("iphone", re.compile(r"^IMG_\d{4}$", re.I)),
    ("android", re.compile(r"^PXL_\d{8}_\d{9}", re.I)),
)


def stage05_filename_hints(image_path: str) -> StageResult:
    """Cheap provenance hint from the file naming pattern (WhatsApp/Telegram/...)."""
    started = time.time()
    name = os.path.basename(image_path)
    hits = [label for label, pattern in FILENAME_PATTERNS if pattern.search(name)]
    return StageResult(
        "filename_hints",
        "ok" if hits else "no_data",
        0.2 if hits else 0.0,
        {"source_hint": hits, "filename": name},
        f"naming pattern suggests: {', '.join(hits)}" if hits else "no recognizable naming pattern",
        time.time() - started,
    )


def stage05_timestamp_sanity(exif: dict) -> StageResult:
    """Flag contradictions between capture time (DateTimeOriginal) and
    the file's last-modification time (DateTime).

    A large gap between the two means the file was re-saved or edited
    long after capture - a common sign of EXIF manipulation or a
    forwarded/re-encoded file. Gaps up to 1 hour are tolerated (device
    clock drift, timezone quirks, immediate re-saves)."""
    started = time.time()
    ts = exif.get("timestamps") or {}
    original = ts.get("original")
    modified = ts.get("modified")
    data = {"original": original, "modified": modified}
    if not original:
        return StageResult("timestamp_check", "no_data", 0.0, data,
                           "no capture timestamp to check", time.time() - started)
    if not modified:
        return StageResult("timestamp_check", "ok", 0.3, data,
                           "capture time present, no modification time to compare",
                           time.time() - started)
    try:
        t0 = datetime.strptime(original, "%Y-%m-%d %H:%M:%S")
        t1 = datetime.strptime(modified, "%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return StageResult("timestamp_check", "ok", 0.3, data,
                           "timestamps present but unparsable", time.time() - started)
    gap_h = abs((t1 - t0).total_seconds()) / 3600.0
    if gap_h > 1.0:
        note = (f"FLAG: modified time differs from capture time by "
                f"{gap_h / 24:.1f} days - file likely re-saved/edited")
        return StageResult("timestamp_check", "error", 0.6, data,
                           note, time.time() - started)
    return StageResult("timestamp_check", "ok", 0.3, data,
                       "capture and modification times consistent",
                       time.time() - started)