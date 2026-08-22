"""
Locus - Photo Geolocation Pipeline (Mode 3)
===========================================
Automated discovery of a photo's location and embedded identifiers
(URLs, emails, usernames). Execution flow:

  Stage 0  - Fast path: SHA-256 + perceptual hash, EXIF parse (reuses
             exif_extractor.run). Validated GPS -> short-circuit.
  Stage 0.5- Cheap enrichment: reverse-geocode EXIF coords (Nominatim,
             cached, 1 req/s enforced), timestamp sanity check, filename
             provenance hints (WhatsApp/Telegram/screenshot patterns),
             solar-vs-brightness forgery check (built-in NOAA math).
  Stage 1  - Parallel fallback (3 workers): OCR (+regex extraction of
             URLs/emails/usernames, email-validator gate, POI name
             heuristics), GeoCLIP weak prior (optional, heavy),
             reverse-search providers (config-gated by keys: Google
             Vision / SerpApi / TinEye / SauceNAO).
  Stage 2  - Sherlock: avatar/endpoint probing for OCR'd handles plus
             reverse-search match images; two-tier visual gate
             (strong <=10, weak 10-25 -> ORB when opencv available);
             built-in average-hash fallback when imagehash is absent.
             Overpass name queries (with GeoCLIP bbox); solar position.
  Fusion   - Weighted centroid + confidence radius + top-5 handoff;
             identity-only matches (no coordinates) reported separately.
  Output   - Structured JSON payload with full execution trace.

Every stage emits StageResult(stage, status, confidence, data, note);
status is one of: ok | no_data | skipped | error. Missing optional
dependencies or API keys produce "skipped", never a crash.

Package layout (each module has a single purpose):
  config.py         - PipelineConfig + load_config (env/.env keys & flags)
  contracts.py      - StageResult / Candidate dataclasses (stage contract)
  core.py           - Stage 0 fast path: hash, EXIF (+GPS validation), fuse
  enrichment.py     - Stage 0.5: reverse geocode, filename hints, timestamp check
  ocr.py            - Stage 1 OCR: preprocessing, langdetect two-pass, entities
  geoclip.py        - Stage 1 GeoCLIP prior (optional, heavy)
  reverse_search.py - Stage 1 providers: Vision / SerpApi / TinEye / SauceNAO
  sherlock.py       - Stage 2 handle probing + two-tier visual gate
  overpass.py       - Stage 2 OSM name queries (mirrors, rate-limited)
  solar.py          - NOAA sun position, forgery sanity, orientation constraint
  pipeline.py       - run(): orchestration, trace, output payload
  __main__.py       - CLI: python -m modules.metadata.locus <image>

======================================================================
REQUIREMENTS
======================================================================
PYTHON PACKAGES
  Required:
    - requests            (already in requirements.txt)
    - Pillow              (already in requirements.txt)
  Optional (stage skips itself when missing):
    - imagehash           (pHash; built-in average-hash fallback exists)
    - pytesseract         (OCR; needs the Tesseract binary, see below)
    - email-validator     (email verification gate; raw hits kept if absent)
    - langdetect          (two-pass OCR: auto-detect signage language and
                           re-run Tesseract with the matching language pack)
    - opencv-python       (ORB re-check of weak Sherlock matches)
    - numpy               (only used by the ORB re-check)
    - torch + geoclip     (GeoCLIP country/region prior; GPU recommended)

EXTERNAL BINARIES
    - Tesseract OCR engine: https://github.com/tesseract-ocr/tesseract
      Windows: tesseract-ocr-w64-setup-*.exe (must be on PATH)
      Language packs: tesseract-ocr-ita (Italian signage), eng (default)

API ENDPOINTS
    Free, no key:
    - Nominatim reverse geocode
        GET https://nominatim.openstreetmap.org/reverse?lat=..&lon=..
        Usage policy: max 1 request/second, identify your app via the
        NOMINATIM_USER_AGENT env var. Results cached by coordinates.
    - Overpass API (spatial queries from OCR names)
        POST https://overpass-api.de/api/interpreter
        Mirrors: overpass.kumi.systems, overpass.private.coffee
        Usage policy: bounded queries, mirrors tried in order on failure.
    - Platform probes (Sherlock, avatar/profile endpoints): no keys.
    Keyed (each provider is skipped automatically if its key is missing):
    - Google Cloud Vision webDetection (visual matches, local files OK)
        POST https://vision.googleapis.com/v1/images:annotate?key=KEY
        key: GOOGLE_VISION_API_KEY   (free tier ~1000 req/month)
    - SerpApi Google Images (reverse image search; needs public image URL)
        GET https://serpapi.com/search.json?engine=google_images
        key: SERPAPI_API_KEY         (free tier ~100 searches/month)
    - TinEye API (image upload, signed request)
        POST https://api.tineye.com/rest/
        keys: TINEYE_PUBLIC_KEY + TINEYE_PRIVATE_KEY (paid)
    - SauceNAO (anime/fanart matches, image upload)
        POST https://saucenao.com/search.php
        key: SAUCENAO_API_KEY        (free tier, rate limited)

ENVIRONMENT VARIABLES (.env)
    GOOGLE_VISION_API_KEY=      # reverse search (optional stage)
    SERPAPI_API_KEY=            # reverse search (optional stage)
    TINEYE_PUBLIC_KEY=          # reverse search (optional stage)
    TINEYE_PRIVATE_KEY=         # reverse search (optional stage)
    SAUCENAO_API_KEY=           # reverse search (optional stage)
    NOMINATIM_USER_AGENT=OSINTNexusBot/1.0   # required by Nominatim policy
    PHOTO_GEOLOC_USE_GEOCLIP=0  # 1 = enable heavy GeoCLIP stage
    PHOTO_GEOLOC_USE_SOLAR=0    # 1 = enable solar orientation stage
======================================================================
"""

from .config import PipelineConfig, load_config
from .contracts import Candidate, StageResult
from .pipeline import run

__all__ = ["run", "load_config", "PipelineConfig", "StageResult", "Candidate"]