"""Stage 0 fast path: file hashing, EXIF extraction + GPS validation,
and the fusion step shared by both execution paths."""

import hashlib
import math
import os
import sys
import time
from typing import Optional

from PIL import Image

from .config import PipelineConfig
from .contracts import StageResult

try:
    from modules.metadata.exif_extractor import run as exif_run
except ImportError:
    try:
        from metadata.exif_extractor import run as exif_run
    except ImportError:
        try:
            sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
            from modules.metadata.exif_extractor import run as exif_run
        except ImportError:
            import exif_extractor as _exif_module
            exif_run = _exif_module.run

try:
    import imagehash
except ImportError:
    imagehash = None


def stage0_hash(image_path: str) -> StageResult:
    """SHA-256 + perceptual hash for file identity and visual fingerprint."""
    started = time.time()
    try:
        sha = hashlib.sha256()
        with open(image_path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                sha.update(chunk)
        phash = None
        if imagehash is not None:
            with Image.open(image_path) as img:
                phash = str(imagehash.phash(img))
        return StageResult(
            "hash", "ok", 1.0,
            {"sha256": sha.hexdigest(), "phash": phash},
            "imagehash unavailable" if phash is None else "sha256+phash computed",
            time.time() - started,
        )
    except Exception as exc:
        return StageResult("hash", "error", 0.0, {}, str(exc), time.time() - started)


def _validate_gps(gps: dict) -> Optional[str]:
    """Sanity-check EXIF GPS values; return problem description or None."""
    lat, lon = gps.get("latitude"), gps.get("longitude")
    if lat is None or lon is None:
        return "missing coordinate"
    if not (-90 <= lat <= 90) or not (-180 <= lon <= 180):
        return "coordinate out of range"
    if lat == 0.0 and lon == 0.0:
        return "null island - suspicious zero-zero coordinate"
    return None


def stage0_exif(image_path: str) -> StageResult:
    """Extract EXIF (reuses exif_extractor) and validate GPS coordinates."""
    started = time.time()
    result = exif_run(image_path)
    if "error" in result:
        return StageResult("exif", "error", 0.0, {}, result["error"], time.time() - started)
    gps = result.get("gps", {})
    problem = _validate_gps(gps)
    if problem:
        return StageResult(
            "exif", "no_data", 0.0,
            {"gps": gps, "device": result.get("device"), "timestamps": result.get("timestamps")},
            f"no usable GPS: {problem}",
            time.time() - started,
        )
    return StageResult(
        "exif", "ok", 0.9,
        {"gps": gps, "device": result.get("device"), "timestamps": result.get("timestamps")},
        "validated geotag present",
        time.time() - started,
    )


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance between two coordinates (km)."""
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def _best_geo_cluster(candidates: list, radius_km: float = 50.0) -> list:
    """Greedy clustering seeded by confidence order; returns the cluster
    with the highest summed confidence.

    A single distant outlier (e.g. one wrong reverse-search hit) used to
    drag the naive weighted centroid thousands of km away from the
    agreeing majority; clustering first makes the majority win."""
    ordered = sorted(candidates, key=lambda c: c.confidence, reverse=True)
    clusters = []
    for cand in ordered:
        target = None
        for cl in clusters:
            if any(_haversine_km(cand.lat, cand.lon, m.lat, m.lon) <= radius_km
                   for m in cl):
                target = cl
                break
        if target is None:
            clusters.append([cand])
        else:
            target.append(cand)
    return max(clusters, key=lambda cl: sum(c.confidence for c in cl))


def fuse(candidates: list, exif_result: Optional[StageResult]) -> dict:
    """Weighted centroid + confidence radius + top-K analyst handoff."""
    if exif_result is not None and exif_result.status == "ok":
        gps = exif_result.data["gps"]
        return {
            "method": "exif",
            "lat": gps["latitude"],
            "lon": gps["longitude"],
            "confidence": exif_result.confidence,
            "radius_m": 25,
            "note": exif_result.note,
        }

    if not candidates:
        return {"method": "none", "lat": None, "lon": None,
                "confidence": 0.0, "radius_m": None, "note": "no candidates"}

    geo = [c for c in candidates if c.lat is not None and c.lon is not None]
    if not geo:
        top = max(candidates, key=lambda c: c.confidence)
        return {"method": "identity", "lat": None, "lon": None,
                "confidence": round(top.confidence, 2), "radius_m": None,
                "note": f"{len(candidates)} identity/url match(es); no coordinates to fuse"}
    candidates = geo

    cluster = _best_geo_cluster(candidates)
    excluded = len(candidates) - len(cluster)
    total = sum(c.confidence for c in cluster)
    if total <= 0:
        best = max(candidates, key=lambda c: c.confidence)
        return {"method": "fusion", "lat": best.lat, "lon": best.lon,
                "confidence": 0.0, "radius_m": None,
                "note": "all candidates at zero confidence - no usable result"}

    w = sum(c.lat * c.confidence for c in cluster) / total
    lon = sum(c.lon * c.confidence for c in cluster) / total
    spread = max(((c.lat - w) ** 2 + (c.lon - lon) ** 2) ** 0.5 for c in cluster)
    confidence = min(sum(c.confidence for c in cluster) / len(cluster), 0.7)
    low = confidence < 0.4 or spread > 0.05
    note = "top-K handoff recommended" if low else "clustered candidates agree"
    if excluded:
        note += f"; {excluded} outlier candidate(s) excluded"
    return {
        "method": "fusion",
        "lat": w,
        "lon": lon,
        "confidence": confidence,
        "radius_m": max(100, spread * 111_000),
        "note": note,
    }