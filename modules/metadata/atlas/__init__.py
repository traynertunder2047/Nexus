"""
Atlas - Text Place Geolocation Pipeline (Mode 1)
================================================
Resolves place references in free text (chat messages, captions, posts,
documents) to coordinates. Execution flow:

  Stage 0  - Extraction: normalize text, detect the text's language and
             derive a country prior (langdetect), pull place candidates
             via heuristic patterns: capitalized multi-word sequences
             ("Ristorante da Gigi"), prepositional anchors ("near X",
             "in X", "vicino a X") and street-type words. URL/email
             extraction reuses Locus's regexes.
  Stage 1  - Forward geocoding of each candidate: Nominatim search
             (primary, free, 1 req/s + UA), Photon (free fallback, no
             key), Google Geocoding (optional, keyed). Provider
             failures are isolated.
  Stage 1.5- Disambiguation: country prior downranks hits that
             contradict the text language ("ci vediamo al Colosseo" ->
             Rome, not the Las Vegas Colosseum); hits from different
             candidates within ~5 km reinforce each other (agreement
             between independent references is the strongest evidence);
             the top hit is reverse-geocoded for verification (reuses
             Locus's Nominatim cache/throttle).
  Stage 2  - Context enrichment: Overpass "what is at this place" -
             nearest named POIs around the resolved coordinate (reuses
             Locus's mirror list and politeness pattern).
  Fusion   - Weighted centroid + confidence radius + top-5 handoff
             (reuses Locus's fuse logic). Confidence comes from
             provider importance + prior agreement + cross-clustering.
  Output   - Structured JSON payload with full execution trace.

Every stage emits StageResult(stage, status, confidence, data, note);
status is one of: ok | no_data | skipped | error.

Package layout (mirrors Locus; contracts/fuse/Overpass reused):
  config.py         - AtlasConfig + load_config (env/.env keys & flags)
  extraction.py     - Stage 0: normalization, language prior, candidates
  geocode.py        - Stage 1: Nominatim / Photon / Google Geocoding
  disambiguate.py   - Stage 1.5: country filter, clustering, verification
  enrichment.py     - Stage 2: Overpass nearby-POI context
  pipeline.py       - run(): orchestration, trace, output payload
  __main__.py       - CLI: python -m modules.metadata.atlas "text..."

======================================================================
REQUIREMENTS
======================================================================
PYTHON PACKAGES
  Required:
    - requests            (already in requirements.txt)
    - langdetect          (language -> country prior; pip install langdetect)
  Reused from Locus (modules/metadata/locus/):
    - StageResult / Candidate contracts
    - URL_RE regex, Nominatim reverse-geocode cache/throttle,
      Overpass mirror list + politeness pattern, fuse()

API ENDPOINTS
    Free, no key:
    - Nominatim search (forward geocoding)
        GET https://nominatim.openstreetmap.org/search?q=..&format=jsonv2
        Usage policy: max 1 request/second, identify your app via the
        NOMINATIM_USER_AGENT env var.
    - Photon (forward geocoding fallback)
        GET https://photon.komoot.io/api/?q=..
        Free, no key, no strict rate limit.
    - Overpass API (nearby POI context)
        POST https://overpass-api.de/api/interpreter
        Mirrors: overpass.kumi.systems, overpass.private.coffee
        Usage policy: bounded queries, mirrors tried in order on failure.
    Keyed (skipped automatically if the key is missing):
    - Google Geocoding (optional third provider)
        GET https://maps.googleapis.com/maps/api/geocode/json?address=..
        key: GOOGLE_GEOCODING_API_KEY

ENVIRONMENT VARIABLES (.env)
    GOOGLE_GEOCODING_API_KEY=   # optional third geocoding provider
    NOMINATIM_USER_AGENT=OSINTNexusBot/1.0   # required by Nominatim policy
    ATLAS_USE_COUNTRY_PRIOR=1   # 0 = disable language->country filtering
======================================================================
"""

from ..locus.contracts import Candidate, StageResult
from .config import AtlasConfig, load_config
from .pipeline import run

__all__ = ["run", "load_config", "AtlasConfig", "StageResult", "Candidate"]