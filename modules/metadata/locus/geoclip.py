"""Stage 1 GeoCLIP country/region-level visual prior (optional, heavy)."""

import time
from typing import Optional

from .config import PipelineConfig
from .contracts import StageResult


def _derive_bbox(regions: list, half_span: float = 2.0) -> Optional[list]:
    """Weak bounding box around the top region centroid [lat_min, lon_min, lat_max, lon_max]."""
    if not regions:
        return None
    lat, lon = regions[0].get("lat"), regions[0].get("lon")
    if lat is None or lon is None:
        return None
    return [lat - half_span, lon - half_span, lat + half_span, lon + half_span]


def stage1_geoclip(image_path: str, cfg: PipelineConfig) -> StageResult:
    """GeoCLIP country/region-level prior (weak). Heavy; config-gated."""
    started = time.time()
    if not cfg.use_geoclip:
        return StageResult("geoclip", "skipped", 0.0, {},
                           "disabled (PHOTO_GEOLOC_USE_GEOCLIP=0)")
    try:
        import torch  # noqa: F401
        from geoclip import GeoCLIP
    except ImportError:
        return StageResult("geoclip", "skipped", 0.0, {},
                           "torch/geoclip not installed (needed since PHOTO_GEOLOC_USE_GEOCLIP=1)")
    try:
        model = GeoCLIP()
        preds = model.predict(image_path, top_k=cfg.geoclip_top_k)
        regions = [{"lat": float(lat), "lon": float(lon),
                    "confidence": 1.0 / max(len(preds), 1)} for lat, lon in preds]
        if not regions:
            return StageResult("geoclip", "no_data", 0.0, {"regions": [], "bbox": None},
                               "no region predictions", time.time() - started)
        return StageResult("geoclip", "ok", 0.35,
                           {"regions": regions, "bbox": _derive_bbox(regions)},
                           f"top-{len(regions)} regions from visual prior",
                           time.time() - started)
    except Exception as exc:
        return StageResult("geoclip", "error", 0.0, {"regions": [], "bbox": None},
                           str(exc), time.time() - started)