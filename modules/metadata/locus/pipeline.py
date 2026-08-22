"""run(): pipeline orchestration - fast path short-circuit, parallel
fallback, fusion, and the structured JSON output payload with trace."""

import os
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from typing import Optional

from .config import PipelineConfig, load_config
from .contracts import StageResult
from .core import fuse, stage0_exif, stage0_hash
from .enrichment import stage05_filename_hints, stage05_reverse_geocode, stage05_timestamp_sanity
from .geoclip import stage1_geoclip
from .ocr import stage1_ocr
from .overpass import stage2_overpass
from .reverse_search import stage1_reverse_search
from .sherlock import stage2_sherlock
from .solar import stage05_solar_sanity, stage2_solar


def run(image_path: str, cfg: Optional[PipelineConfig] = None) -> dict:
    """Run the full pipeline; returns the structured JSON payload."""
    cfg = cfg or load_config()
    trace = []

    if not os.path.isfile(image_path):
        return {"error": f"File not found: {image_path}"}

    def track(stage: StageResult):
        trace.append({"stage": stage.stage, "status": stage.status,
                      "confidence": stage.confidence, "note": stage.note,
                      "seconds": round(stage.seconds, 2)})
        return stage

    h = track(stage0_hash(image_path))
    exif = track(stage0_exif(image_path))
    fname = track(stage05_filename_hints(image_path))

    final = None
    candidates = []
    enriched = {"filename_hint": fname.data.get("source_hint") or None}
    if exif.status == "ok":
        final = fuse([], exif)
        geocode = track(stage05_reverse_geocode(
            exif.data["gps"]["latitude"], exif.data["gps"]["longitude"], cfg))
        tcheck = track(stage05_timestamp_sanity(exif.data))
        sun = track(stage05_solar_sanity(image_path, exif.data["gps"],
                                         exif.data["timestamps"], cfg))
        enriched.update({"place": geocode.data.get("place"),
                         "timestamp_note": tcheck.note,
                         "solar_note": sun.note if sun.status != "no_data" else None})
        summary = "Location from embedded GPS metadata."
    else:
        with ThreadPoolExecutor(max_workers=3) as pool:
            f_ocr = pool.submit(stage1_ocr, image_path, cfg)
            f_geo = pool.submit(stage1_geoclip, image_path, cfg)
            f_rs = pool.submit(stage1_reverse_search, image_path, cfg)
            ocr = track(f_ocr.result())
            geo = track(f_geo.result())
            rs = track(f_rs.result())
        handles = ocr.data.get("usernames") or []
        image_urls = [m.get("url") for m in (rs.data.get("matches") or []) if m.get("url")]
        sh = track(stage2_sherlock(handles, image_urls, image_path, cfg))
        op = track(stage2_overpass(ocr.data.get("text", ""), geo.data.get("bbox"), cfg))
        sol = track(stage2_solar(exif.data.get("timestamps", {}), exif.data.get("gps"), cfg))

        candidates = (sh.data.get("candidates") or []) + (op.data.get("candidates") or [])
        final = fuse(candidates, None)
        enriched.update({"ocr_text": ocr.data.get("text"),
                         "urls": ocr.data.get("urls"), "emails": ocr.data.get("emails"),
                         "usernames": ocr.data.get("usernames"),
                         "verified_emails": (ocr.data.get("verified") or {}).get("emails"),
                         "place_names": op.data.get("names"),
                         "reverse_match_urls": image_urls[:5],
                         "solar_note": sol.note if sol.status != "no_data" else None})
        if final["method"] == "fusion" and final["confidence"] > 0:
            summary = "Location determined from visual clues."
        elif final["method"] == "identity":
            summary = "No coordinates, but identity/url matches found - analyst review recommended."
        else:
            summary = "No location could be determined from this image."

    top_k = [asdict(c) for c in sorted(candidates, key=lambda c: c.confidence, reverse=True)[:5]]
    return {
        "file": {"path": image_path, "sha256": h.data.get("sha256"),
                 "phash": h.data.get("phash")},
        "gps": exif.data.get("gps") if exif.status == "ok" else None,
        "device": (exif.data.get("device") or {}) if exif.status != "error" else {},
        "timestamps": (exif.data.get("timestamps") or {}) if exif.status != "error" else {},
        "enriched": enriched,
        "candidates": [asdict(c) for c in candidates],
        "final": final,
        "top_k": top_k,
        "trace": trace,
        "summary": summary,
    }