"""Stage 4: correlation report - where this face/image appears across
platforms, grouped by platform with the evidence for each link
(same-image flag from whole-image hash, face verdict, handle)."""

import time

from ..locus.contracts import StageResult
from .config import DoppelConfig


def stage4_correlation(matches: list, cfg: DoppelConfig) -> StageResult:
    """Build the cross-platform correlation report from match entries."""
    started = time.time()
    if not matches:
        return StageResult("correlation", "no_data", 0.0, {"entries": []},
                           "no matches to correlate", time.time() - started)
    entries = [
        {"platform": m["platform"], "url": m["url"], "source": m["source"],
         "handle": m.get("handle"), "page_url": m.get("page_url"),
         "same_image": m.get("same_image", False),
         "image_distance": m.get("image_distance"), "face": m.get("face")}
        for m in matches]
    platforms = {}
    for e in entries:
        platforms[e["platform"]] = platforms.get(e["platform"], 0) + 1
    note = f"{len(entries)} link(s) across {len(platforms)} platform(s)"
    return StageResult("correlation", "ok", 0.5,
                       {"entries": entries, "platforms": platforms},
                       note, time.time() - started)