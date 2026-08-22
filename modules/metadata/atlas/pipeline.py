"""run(): Atlas orchestration - extract -> geocode -> disambiguate ->
context enrichment -> fusion, with the structured JSON output payload."""

from dataclasses import asdict
from typing import Optional

from ..locus.core import fuse
from ..locus.contracts import Candidate, StageResult
from .config import AtlasConfig, load_config
from .disambiguate import _haversine_km, stage15_disambiguate
from .enrichment import stage2_context
from .extraction import stage0_extract
from .geocode import stage1_geocode


def _maps_url(lat: float, lon: float) -> str:
    return f"https://www.google.com/maps?q={lat},{lon}"


def _best_cluster(ranked: list, cfg: AtlasConfig) -> list:
    """Greedy spatial clustering; returns the cluster with the highest
    summed score - agreement between independent references wins."""
    clusters = []
    for h in ranked:
        target = None
        for cl in clusters:
            if _haversine_km(cl[0]["lat"], cl[0]["lon"], h["lat"], h["lon"]) <= cfg.cluster_radius_km:
                target = cl
                break
        if target is None:
            clusters.append([h])
        else:
            target.append(h)
    best = max(clusters, key=lambda cl: sum(h["score"] for h in cl))
    best.sort(key=lambda h: h["score"], reverse=True)
    return best


def run(text: str, cfg: Optional[AtlasConfig] = None) -> dict:
    """Run the full Atlas pipeline on a text snippet; returns JSON payload."""
    cfg = cfg or load_config()
    trace = []

    if not text or not text.strip():
        return {"error": "empty input text"}

    def track(stage: StageResult):
        trace.append({"stage": stage.stage, "status": stage.status,
                      "confidence": stage.confidence, "note": stage.note,
                      "seconds": round(stage.seconds, 2)})
        return stage

    ex = track(stage0_extract(text, cfg))
    if ex.status == "error":
        return {"error": ex.note, "trace": trace}
    if ex.status == "no_data":
        return {
            "input": {"text": ex.data["text"], "language": ex.data["language"],
                      "country_prior": ex.data["country_prior"]},
            "extracted": [], "results": [], "nearby": [],
            "candidates": [], "final": {"method": "none", "lat": None, "lon": None,
                                        "confidence": 0.0, "radius_m": None,
                                        "note": "no place references found"},
            "top_k": [], "trace": trace,
            "summary": "No place references found in the text.",
        }

    gc = track(stage1_geocode(ex.data["candidates"], cfg))
    if gc.status != "ok":
        return {
            "input": {"text": ex.data["text"], "language": ex.data["language"],
                      "country_prior": ex.data["country_prior"]},
            "extracted": ex.data["candidates"], "results": [], "nearby": [],
            "candidates": [], "final": {"method": "none", "lat": None, "lon": None,
                                        "confidence": 0.0, "radius_m": None,
                                        "note": gc.note},
            "top_k": [], "trace": trace,
            "summary": ("Place references found, but no provider could resolve them."
                        if ex.data["candidates"] else
                        "No place references found - only URLs/emails were extracted."),
        }

    dis = track(stage15_disambiguate(gc.data["results"],
                                     ex.data.get("country_aliases") if cfg.use_country_prior else None,
                                     cfg))
    ranked = dis.data.get("ranked") or []
    main = _best_cluster(ranked, cfg) if ranked else []

    nearby = []
    if main:
        top = main[0]
        ctx = track(stage2_context(top["lat"], top["lon"], cfg))
        nearby = ctx.data.get("nearby") or []

    candidates = [
        Candidate(lat=h["lat"], lon=h["lon"], source=f"atlas:{h['provider']}",
                  confidence=round(min(max(h["score"], 0.0), 1.0), 2), url=_maps_url(h["lat"], h["lon"]),
                  reason=f"{h['candidate']} -> {h['display_name']}"
                         + (" [country prior conflict]" if h.get("prior_conflict") else ""))
        for h in main[:5]]
    final = fuse(candidates, None)

    if final["method"] == "fusion" and final["confidence"] > 0 and (final["radius_m"] or 0) <= 50_000:
        summary = "Location resolved from text references."
    elif candidates:
        summary = "Coordinates found, but candidates disagree - analyst review recommended."
    else:
        summary = "No location could be resolved from this text."

    return {
        "input": {"text": ex.data["text"], "language": ex.data["language"],
                  "country_prior": ex.data["country_prior"]},
        "extracted": ex.data["candidates"],
        "results": ranked[:10],
        "nearby": nearby[:10],
        "candidates": [asdict(c) for c in candidates],
        "final": final,
        "top_k": [asdict(c) for c in sorted(candidates, key=lambda c: c.confidence, reverse=True)[:5]],
        "trace": trace,
        "summary": summary,
    }