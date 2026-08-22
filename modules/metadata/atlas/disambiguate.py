"""Stage 1.5: disambiguation of geocode hits.

1. Country-prior filtering: hits whose country contradicts the language
   prior are downranked (the language of the text is a strong signal).
2. Cross-candidate clustering: hits from different candidates within
   cfg.cluster_radius_km of each other reinforce each other - agreement
   between independent references is the strongest evidence.
3. Reverse-geocode verification of the top hit (reuses Locus's
   Nominatim cache/throttle): confirmed place names get a small boost."""

import math

from ..locus.contracts import StageResult
from ..locus.enrichment import stage05_reverse_geocode
from .config import AtlasConfig


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def _country_ok(hit: dict, aliases: tuple) -> bool:
    """True when the hit's country is compatible with the prior aliases."""
    if not aliases:
        return True
    country = (hit.get("country") or "").lower()
    if not country:
        return True
    return any(a in country or country in a for a in aliases)


def _ranked_hits(results: list, aliases: tuple, cfg: AtlasConfig) -> list:
    """Flatten hits -> ranked dicts with score, flags, cluster boost."""
    flat = []
    for res in results:
        for hit in res["hits"]:
            conflict = not _country_ok(hit, aliases) if cfg.use_country_prior else False
            score = hit.get("importance", 0.0)
            if hit["provider"] == "photon":
                score = 0.4
            if conflict:
                score -= 0.3
            else:
                score += 0.2
            flat.append({**hit, "candidate": res["candidate"],
                         "context": res.get("context", ""),
                         "score": score, "prior_conflict": conflict})
    for i, a in enumerate(flat):
        for b in flat[i + 1:]:
            if a["candidate"] == b["candidate"]:
                continue
            if _haversine_km(a["lat"], a["lon"], b["lat"], b["lon"]) <= cfg.cluster_radius_km:
                a["score"] += 0.15
                b["score"] += 0.15
    flat.sort(key=lambda h: h["score"], reverse=True)
    return flat


def stage15_disambiguate(results: list, aliases: tuple, cfg: AtlasConfig) -> StageResult:
    """Rank hits, then reverse-geocode-verify the top one (1 req/s, cached)."""
    import time
    started = time.time()
    if not results:
        return StageResult("disambiguate", "no_data", 0.0, {"ranked": []},
                           "no geocode results to rank", time.time() - started)
    prior = aliases[0] if aliases else None
    ranked = _ranked_hits(results, aliases, cfg)
    note = f"{len(ranked)} hit(s), {prior or 'no'} country prior"
    if prior:
        conflicts = sum(1 for h in ranked if h["prior_conflict"])
        note += f", {conflicts} prior-conflicting"
    data = {"ranked": ranked}
    if ranked:
        top = ranked[0]
        rev = stage05_reverse_geocode(top["lat"], top["lon"], cfg)
        if rev.status == "ok":
            top["score"] += 0.1
            data["verified"] = rev.data.get("place")
            data["verified_candidate"] = top["candidate"]
            note += ", top hit reverse-verified"
        ranked.sort(key=lambda h: h["score"], reverse=True)
    return StageResult("disambiguate", "ok", 0.5, data, note, time.time() - started)