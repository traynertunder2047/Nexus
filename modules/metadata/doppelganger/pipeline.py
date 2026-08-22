"""run(): Doppelgänger orchestration - face extraction -> reverse-image
search -> face matching -> identity context -> correlation report."""

import os
import time
from dataclasses import asdict
from typing import Optional

from PIL import Image

from ..locus.core import fuse
from ..locus.contracts import Candidate, StageResult
from .config import DoppelConfig, load_config
from .context import stage3_context
from .correlation import stage4_correlation
from .face import detect_faces, largest_face
from .match import stage2_match
from .reverse import stage1_reverse


def _error_payload(message: str, image_path: str, handles: list, trace: list) -> dict:
    return {
        "error": message,
        "input": {"image_path": image_path, "faces": 0, "handle_hints": handles},
        "reverse": {"matches": [], "providers": [], "errors": []},
        "matches": [], "identities": [],
        "correlation": {"entries": [], "platforms": {}},
        "candidates": [],
        "final": {"method": "none", "lat": None, "lon": None, "confidence": 0.0,
                  "radius_m": None, "note": message},
        "top_k": [], "trace": trace, "summary": message,
    }


def run(image_path: str, handles: Optional[list] = None,
        cfg: Optional[DoppelConfig] = None) -> dict:
    """Run the full Doppelgänger pipeline; returns the JSON payload.

    handles: optional list of username hints whose platform avatars are
    fetched and face-compared (verification, not discovery).
    """
    cfg = cfg or load_config()
    handles = [h.lstrip("@") for h in (handles or []) if h]
    trace = []

    if not os.path.isfile(image_path):
        return _error_payload(f"File not found: {image_path}", image_path, handles, trace)

    def track(stage: StageResult):
        trace.append({"stage": stage.stage, "status": stage.status,
                      "confidence": stage.confidence, "note": stage.note,
                      "seconds": round(stage.seconds, 2)})
        return stage

    started = time.time()
    try:
        img = Image.open(image_path).convert("RGB")
        img.load()
    except Exception as exc:
        return _error_payload(f"unreadable image: {exc}", image_path, handles, trace)

    faces = detect_faces(img)
    src_face = largest_face(img)
    if src_face is None:
        track(StageResult("face", "no_data", 0.0, {"faces": 0},
                          "no face detected in image", time.time() - started))
        return {
            "input": {"image_path": image_path, "faces": 0, "handle_hints": handles},
            "reverse": {"matches": [], "providers": [], "errors": []},
            "matches": [], "identities": [], "correlation": {"entries": [], "platforms": {}},
            "candidates": [],
            "final": {"method": "none", "lat": None, "lon": None,
                      "confidence": 0.0, "radius_m": None,
                      "note": "no face detected - Doppelgänger needs a face"},
            "top_k": [], "trace": trace,
            "summary": "No face detected in the image - nothing to match.",
        }

    track(StageResult("face", "ok", 0.8, {"faces": len(faces)},
                      f"{len(faces)} face(s) detected", time.time() - started))

    rs = track(stage1_reverse(image_path, cfg))
    image_urls = [m.get("url") for m in (rs.data.get("matches") or []) if m.get("url")]

    mt = track(stage2_match(src_face, img, image_urls, handles, cfg))
    matches = mt.data.get("matches") or []

    ctx = track(stage3_context(image_urls, cfg))
    identities = ctx.data.get("identities") or []

    cor = track(stage4_correlation(matches, cfg))

    candidates = []
    for ident in identities:
        conf = 0.35
        for m in matches:
            if m.get("url") == ident.get("source_url") or m.get("page_url") == ident.get("source_url"):
                if "face" in m:
                    conf = 0.35 + 0.3 * m["face"]["confidence"]
                if m.get("same_image"):
                    conf += 0.1
                break
        candidates.append(Candidate(
            lat=None, lon=None,
            source=f"doppelganger:{ident['type']}",
            confidence=round(min(conf, 0.6), 2),
            url=ident.get("source_url", ""),
            reason=f"{ident['type']} '{ident['value']}' from page "
                   f"'{ident.get('page_title', '')}'"))

    verified_handles = {}
    for m in matches:
        if m.get("handle") and "face" in m:
            key = m["handle"].lower()
            if key not in verified_handles or m["face"]["confidence"] > verified_handles[key]["face"]["confidence"]:
                verified_handles[key] = m
    for handle, m in verified_handles.items():
        conf = 0.35 + 0.3 * m["face"]["confidence"] + (0.1 if m.get("same_image") else 0.0)
        candidates.append(Candidate(
            lat=None, lon=None,
            source=f"doppelganger:handle",
            confidence=round(min(conf, 0.6), 2),
            url=m["url"],
            reason=f"handle @{m['handle']} verified: avatar face match "
                   f"({m['face']['tier']}, distance {m['face']['distance']}) on {m['platform']}"))
    final = fuse(candidates, None)

    face_matches = sum(1 for m in matches if "face" in m)
    if candidates and face_matches:
        summary = "Identity candidates found on face-matched pages - analyst review recommended."
    elif candidates:
        summary = "Identity hints found on related pages - no face-level confirmation."
    elif face_matches:
        summary = f"Face matched on {face_matches} site(s), but no identity text was found."
    elif matches:
        summary = "Related images found, but no face match and no identity text."
    else:
        summary = "No related images or identity found."

    return {
        "input": {"image_path": image_path, "faces": len(faces),
                  "handle_hints": handles},
        "reverse": {"matches": (rs.data.get("matches") or [])[:cfg.max_matches],
                    "providers": rs.data.get("providers", []),
                    "errors": rs.data.get("errors", [])},
        "matches": matches[:cfg.max_matches],
        "identities": identities[:10],
        "correlation": {"entries": (cor.data.get("entries") or [])[:cfg.max_matches],
                        "platforms": cor.data.get("platforms", {})},
        "candidates": [asdict(c) for c in candidates],
        "final": final,
        "top_k": [asdict(c) for c in
                  sorted(candidates, key=lambda c: c.confidence, reverse=True)[:5]],
        "trace": trace,
        "summary": summary,
    }