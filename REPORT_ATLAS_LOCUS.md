# Atlas & Locus — Technical Analysis Report

**Scope:** `modules/metadata/atlas/` (Mode 1, text → location) and `modules/metadata/locus/` (Mode 3, photo → location).
**Entry points:** `python -m modules.metadata.atlas "text..."` and `python -m modules.metadata.locus <image>`.
**Date of analysis:** 2026-08-19.

---

## 1. What the two modes do

Both modes answer the same OSINT question — *where is this?* — from different
evidence. They share a small core (`locus/contracts.py`, `locus/core.py`'s
`fuse()`, `locus/overpass.py`, and now the shared rate limiter
`locus/ratelimit.py`).

| | **Atlas (Mode 1)** | **Locus (Mode 3)** |
|---|---|---|
| Input | Free text (chat message, caption, post, doc) | An image file |
| Evidence | Place names, language, URL/email mentions | EXIF/GPS, OCR scene text, reverse-image search, platform avatars |
| Output | Coordinates + POI context + JSON trace | Coordinates + identity matches + JSON trace |

Every stage returns a `StageResult(stage, status, confidence, data, note)` and
`status` is one of `ok | no_data | skipped | error`. Missing optional
dependencies or API keys must produce `skipped`, never a crash.

---

## 2. Atlas (text → location) — detailed logic

### Stage 0 — Extraction (`atlas/extraction.py`)
1. Normalize whitespace.
2. Detect language with **langdetect** → map to a country prior via the
   `LANG_TO_COUNTRIES` table (e.g. `it` → `Italy`, `ko` → `South Korea`).
   *Rationale:* the language a message is written in is a geolocation hint —
   "ci vediamo al Colosseo" almost certainly means Rome, not the Las Vegas
   copy. Short texts (< 12 chars) or undetectable text yield no prior.
3. Extract place candidates with three regex families:
   - **`CAP_SEQ_RE`** — capitalized multi-word sequences with optional
     middle articles/prepositions ("Ristorante da Gigi", "Hotel Splendido").
   - **`ANCHOR_RE`** — prepositional anchors ("near X", "in X", "vicino a X",
     "près de X", "bei X"…) + an optional leading article, then 1–4
     capitalized words.
   - **`SINGLE_WORD_RE`** — single capitalized words that are known cities
     (`CITY_SUFFIX_WORDS` from Locus: Roma, Milano, Paris, …).
   Words in `GENERIC_FIRST_WORDS` (articles, pronouns, common verbs) are
   rejected; duplicates are de-duplicated; each candidate keeps a snippet of
   surrounding context for the analyst report.
4. URLs are also pulled out (reusing Locus's `URL_RE`) and kept in the data —
   they are reported but are *not* place references.

### Stage 1 — Forward geocoding (`atlas/geocode.py`)
Each candidate is geocoded. The provider chain, with **failure isolation**
(one provider error never aborts the others):

1. **Nominatim search** (primary) — `GET https://nominatim.openstreetmap.org/search`
   with a `User-Agent` from `NOMINATIM_USER_AGENT`, **1 req/s** enforced,
   `limit=geocode_limit` (default 5). Returns lat/lon, display name, type,
   importance, country.
2. **Photon** (fallback, only when Nominatim returned nothing) —
   `GET https://photon.komoot.io/api/`, free, no key.
3. **Google Geocoding** (optional third source, only if
   `GOOGLE_GEOCODING_API_KEY` is set) — `GET https://maps.googleapis.com/maps/api/geocode/json`.

If a city was extracted ("Milano") and the candidate is a street/POI name
("Via Roma"), the query is joined: `"Via Roma, Milano"` — city context
disambiguates otherwise-ambiguous street names.

### Stage 1.5 — Disambiguation (`atlas/disambiguate.py`)
1. **Country-prior filter** (`_country_ok`): hits whose country contradicts the
   language→country prior are *downranked* (−0.3) and flagged
   `prior_conflict`; matching hits get +0.2. Disabled when
   `ATLAS_USE_COUNTRY_PRIOR=0`.
2. **Cross-candidate clustering**: hits from *different* candidates within
   `cluster_radius_km` (5 km) of each other get +0.15 each — independent
   agreement is the strongest evidence ("Piazza del Duomo" + "Milano" both
   resolving near the same point).
3. **Reverse-geocode verification**: the top hit is reverse-geocoded via
   Nominatim (reusing Locus's cache/throttle); a confirmed place name adds
   +0.1.
4. Hits are sorted by score into `ranked`.

### Fusion (`atlas/pipeline.py`, `_best_cluster`)
Greedy spatial clustering (radius `cluster_radius_km`), then the cluster with
the highest summed score wins; its hits become `Candidate`s (confidence =
clamped score, source `atlas:<provider>`, Google-Maps deep link). `fuse()` then
produces the final `{"method","lat","lon","confidence","radius_m","note"}`.
A `nearby` step (Stage 2) queries **Overpass** for named POIs around the
resolved point ("what is at this place").

### Atlas output payload
`input`, `extracted`, `results`, `nearby`, `candidates`, `final`, `top_k`,
`trace`, `summary`.

---

## 3. Locus (photo → location) — detailed logic

### Stage 0 — Fast path (`locus/core.py`, `locus/enrichment.py`)
1. **`stage0_hash`**: SHA-256 of the file (identity) + perceptual hash
   (`imagehash.phash`, with a built-in average-hash fallback) for visual
   fingerprinting.
2. **`stage0_exif`** (reuses `exif_extractor.run`): reads GPS (rationals →
   decimal degrees with N/S/E/W hemisphere handling), device (make/model/
   software/lens/serial) and timestamps (original/digitized/modified). GPS is
   validated (range + "null island" 0,0 check).
3. **GPS present → short-circuit**: `fuse([], exif)` returns the EXIF
   coordinate with confidence 0.9, radius 25 m, and the enrichment stages run:
   - `stage05_reverse_geocode` — Nominatim reverse, cached by rounded coords.
   - `stage05_timestamp_sanity` — capture vs modification-time contradiction
     check.
   - `stage05_solar_sanity` — NOAA sun-elevation vs image-brightness forgery
     check (night-tagged GPS + daylight photo = suspicious).
   - `stage05_filename_hints` — WhatsApp/Telegram/screenshot naming patterns.

### Stage 1 — Fallback path (no GPS), run in parallel (3 workers)
1. **OCR** (`locus/ocr.py`): upscale ×2 + grayscale (accuracy depends on it),
   then **Tesseract** (two passes when `langdetect` is installed: OCR with the
   configured packs, detect the signage language, re-OCR with the matching pack
   if longer). Entities extracted by regex: **URLs**, **emails** (validated
   with `email-validator`, `check_deliverability=False`), **usernames**
   (`@handle`), and **POI place names** (capitalized multi-word sequences, split
   at street-type words so Overpass gets clean names).
2. **GeoCLIP** (`locus/geoclip.py`, optional + heavy, gated by
   `PHOTO_GEOLOC_USE_GEOCLIP=1`): a vision model that predicts country/region
   coords from the image alone → a weak prior + a bounding box used to bound
   Overpass queries.
3. **Reverse-image search** (`locus/reverse_search.py`, each provider keyed and
   skipped when its key is missing):
   - **Google Cloud Vision `webDetection`** — base64 upload of the local file,
     no public URL needed.
   - **SerpApi Google Images** — needs a *public* image URL (skipped for local
     files with a note).
   - **TinEye** — multipart upload, MD5-signed request (`TINEYE_PUBLIC_KEY` +
     `TINEYE_PRIVATE_KEY`).
   - **SauceNAO** — multipart upload (`SAUCENAO_API_KEY`), mostly anime/fan-art
     matches.

### Stage 2 — Identity + spatial probes
1. **Sherlock** (`locus/sherlock.py`): for each OCR'd `@handle`, probe a fixed
   set of platform schemas (GitHub API, t.me, old Reddit about.json, Steam XML,
   TikTok oEmbed, YouTube, Instagram, X/Twitter profile-image endpoint) for the
   user's **avatar**. Also fetch the reverse-search match images. Every image is
   compared to the source photo with a **perceptual hash** and a **two-tier
   gate**: strong ≤ 10 (confidence 0.6), weak ≤ 25 (re-checked with **ORB**
   keypoints when `opencv` is available, else kept at 0.3), beyond → discarded.
   Uniform/flat images are excluded (their hashes are degenerate). Matches
   become identity-only Candidates (no coordinates).
2. **Overpass** (`locus/overpass.py`): the OCR'd POI names are queried against
   OpenStreetMap with `["name"~"<name>",i]` regex (bounded by the GeoCLIP
   bounding box when available). Returns real coordinate Candidates
   (confidence 0.45). Politeness: ≥ 2 s spacing, 3 mirrors, one 5 s-delayed
   retry.
3. **Solar** (`locus/solar.py`, gated by `PHOTO_GEOLOC_USE_SOLAR=1`): sun
   position at capture time (built-in NOAA approximation) → azimuth/elevation
   note; usually `no_data` on the fallback path because GPS is missing.

### Fusion & output
Candidates from Sherlock + Overpass go through `fuse()`. Identity-only matches
(`method: "identity"`) are reported separately. Output payload:
`file`, `gps`, `device`, `timestamps`, `enriched`, `candidates`, `final`,
`top_k`, `trace`, `summary`.

---

## 4. Tools, API endpoints and keys — what each is for

### Free endpoints (no key)
| Endpoint | Used for | Policy |
|---|---|---|
| **Nominatim** `GET /search` | Atlas forward geocoding (place name → coords) | 1 req/s, UA required |
| **Nominatim** `GET /reverse` | Locus/Atlas reverse geocoding (coords → place name) | 1 req/s, cached |
| **Photon** `GET /api/` | Atlas fallback geocoder | free, no key |
| **Overpass** `POST /api/interpreter` (3 mirrors) | "What is near here" / "find this POI name" against OpenStreetMap | ≥2 s spacing, bounded queries |
| **Platform probe endpoints** (GitHub API, t.me, old.reddit, Steam XML, TikTok oembed, YouTube, Instagram, X) | Sherlock handle→avatar probing | no keys |

### Keyed endpoints (stage is auto-skipped if the key is missing)
| Key (`.env`) | Endpoint | Purpose |
|---|---|---|
| `GOOGLE_GEOCODING_API_KEY` | Google Maps Geocoding | Optional 3rd Atlas geocoder |
| `GOOGLE_VISION_API_KEY` | Cloud Vision `images:annotate` webDetection | Reverse image search, local file OK |
| `SERPAPI_API_KEY` | `serpapi.com/search.json` (google_images) | Reverse image search (needs public URL) |
| `TINEYE_PUBLIC_KEY` + `TINEYE_PRIVATE_KEY` | `api.tineye.com/rest/` | Reverse image search (MD5-signed upload) |
| `SAUCENAO_API_KEY` | `saucenao.com/search.php` | Reverse image search (anime/fan-art) |

### Config flags
| Env var | Effect |
|---|---|
| `NOMINATIM_USER_AGENT` | Identifies the app to Nominatim (required by their policy) |
| `ATLAS_USE_COUNTRY_PRIOR=0` | Disables language→country downranking |
| `PHOTO_GEOLOC_USE_GEOCLIP=1` | Enables the heavy GeoCLIP vision prior |
| `PHOTO_GEOLOC_USE_SOLAR=1` | Enables the solar-position stage |

---

## 5. Glossary of terms

- **OCR** — Optical Character Recognition: converting an image's text into
  machine-readable characters (here via the Tesseract engine). OCR output is
  the primary geolocation signal when GPS is absent (signage, shop names).
- **EXIF** — Exchangeable Image File Format: metadata embedded by the camera
  (GPS, device, timestamps). Often stripped by social media.
- **GPS** — Global Positioning System coordinates; stored in EXIF as
  degree/minute/second rationals with N/S/E/W references.
- **Geocoding / forward** — human place name → coordinates.
- **Reverse geocoding** — coordinates → human place name.
- **POI** — Point Of Interest (named place: restaurant, station, hotel).
- **pHash / aHash** — perceptual / average image hash; visually similar images
  produce similar hashes, compared by **Hamming distance** (number of differing
  bits).
- **ORB** — keypoint-based feature matcher (OpenCV); used to re-verify "weak"
  visual matches.
- **SHA-256** — cryptographic file digest; file identity / deduplication.
- **langdetect** — language detection library; drives the country prior and the
  OCR second pass.
- **Country prior** — the language of the text as a prior on where it refers to.
- **Bounding box (bbox)** — lat/lon rectangle bounding a GeoCLIP region,
  restricting Overpass queries.
- **Base64 upload** — encoding a file's bytes into text for API JSON upload.
- **Multipart upload** — file upload over HTTP `multipart/form-data`.
- **Web detection** — Google Vision's "find this image / pages using it" API.
- **Avatar probing** — fetching a platform's profile image for a username.
- **Rate limiting / politeness** — respecting a provider's requests-per-second
  limit (Nominatim 1/s, Overpass ≥2 s) to avoid 429 blocks.
- **Mirror** — alternate server for the same service (Overpass has 3).
- **Fusion** — combining multiple candidates into one result: weighted centroid
  + confidence radius + top-K analyst handoff.
- **Centroid** — confidence-weighted average of candidate coordinates.
- **Cluster radius** — max distance for two hits to count as "agreeing".
- **Stage/status** — a pipeline step and its outcome
  (`ok | no_data | skipped | error`).

---

## 6. Bugs found and how they were fixed

### 6.1 `fuse()` — a single outlier dragged the centroid across the globe (HIGH)
`locus/core.py:123-125` computed a *straight confidence-weighted mean of every
candidate*. Confirmed with 3 Rome hits (conf 0.6) + 1 Tokyo hit (conf 0.5):
the "final" coordinate landed in the Black Sea, ~11,000 km off. One wrong
reverse-search hit silently poisoned the whole result.
**Fix:** added `_haversine_km()` + `_best_geo_cluster()` (confidence-seeded
greedy clustering, 50 km radius); the highest-summed-confidence cluster wins
and only its members are averaged. The note reports how many outliers were
excluded. Verified: Rome cluster now yields lat 41.903, lon 12.500.

### 6.2 `stage05_timestamp_sanity` was a stub (MEDIUM)
`locus/enrichment.py` docstring promised "Flag contradictions between capture
time and file modification time", but the body only checked that *a* timestamp
existed — a 152-day gap between `DateTimeOriginal` and `DateTime` passed as
"capture time present".
**Fix:** implemented the check: parse both, flag when they differ by > 1 hour
(status `error`, confidence 0.6, `FLAG: ...` note, matching the existing
`solar_sanity` convention). Verified both flag and benign (30 min) cases.

### 6.3 Independent Nominatim/Overpass throttles → policy violation (MEDIUM)
Atlas forward-geocoding kept its own `_LAST_NOMINATIM` (`atlas/geocode.py`)
while the reverse-geocode verification step used Locus's *separate* counter
(`locus/enrichment.py`). Two Nominatim calls could fire < 1 s apart in the same
process, risking HTTP 429. Same duplication for Overpass (`atlas/enrichment.py`
vs `locus/overpass.py`).
**Fix:** new `modules/metadata/locus/ratelimit.py` with shared `wait_nominatim()`
and `wait_overpass()`; all four call sites now use it and their private
globals were removed.

### 6.4 Atlas summary was wrong for URL/email-only text (LOW)
`atlas/pipeline.py`: extraction returns `ok` when only URLs are present (0 place
candidates), then geocode correctly returns `no_data`, but the summary claimed
"Place references found, but no provider could resolve them."
**Fix:** summary now depends on whether place candidates actually exist:
"No place references found - only URLs/emails were extracted." when
`ex.data["candidates"]` is empty.

### 6.5 Negative Candidate confidence (LOW)
`atlas/pipeline.py:95` `round(min(h["score"], 1.0), 2)` could emit negative
confidence when a prior-conflicting hit scored below zero.
**Fix:** clamp to `[0.0, 1.0]` via `min(max(score, 0.0), 1.0)`.

### 6.6 Missing Tesseract binary reported `error` instead of `skipped` (LOW)
`locus/ocr.py`: with `pytesseract` installed but the Tesseract binary absent
from PATH, the stage raised and returned `error` — violating the contract that
missing dependencies produce `skipped`.
**Fix:** `stage1_ocr` now checks `pytesseract.get_tesseract_version()` up front
and returns `skipped` with a clear note.

---

## 7. Improvements and weak points

**Robustness / correctness**
- *English has no country prior.* `LANG_TO_COUNTRIES` has no `en` entry — the
  language that dominates OSINT input gets no disambiguation. Add a
  `en → ("united states","united kingdom",…)` mapping (or make it list-valued
  and only downrank on strong contradictions).
- *Overpass name regex is substring-based.* `["name"~"Via Roma",i]` also matches
  "Via Romagna"; a short first-word variant ("Ristorante") matches
  "Ristoranti". Bound queries with word boundaries (`\b`) or exact name matches
  plus a `~` fallback.
- *`fuse` cluster radius is a flat 50 km.* Good enough now, but a
  distance-aware or source-aware radius would help (a Sherlock avatar hit and an
  Overpass POI can legitimately be tens of km apart).
- *Google Geocoding is always called even when Nominatim already hit.* Wastes
  paid quota and inflates clusters with near-duplicate hits; consider calling it
  only when the free providers disagree or return nothing.
- *Geocode stage is slow by design:* 8 candidates × 1 s Nominatim throttle ≥ 8 s
  minimum. Consider batching queries or raising the limit via an
  endpoint-independent worker.
- *Timestamp check threshold (1 h) is fixed.* Fine default; a per-analysis
  tolerance would avoid false flags on timezone-heavy uploads.

**Weak points for the OSINT model itself (adversarial reality)**
- **EXIF is the weakest evidence:** social platforms strip GPS/device/time, and
  every EXIF field is trivially forgeable. The solar-sanity and
  timestamp checks are the only forgery guards and they're heuristic.
- **OCR is easily defeated:** a single storefront/marquee with an irrelevant
  brand name ("Hotel Splendido" chains in every city) produces a confident
  wrong Overpass match. No cross-check between OCR-derived names and the
  reverse-image-search imagery.
- **Sherlock identity probes are platform-dependent and fragile:** endpoints
  change, X/Twitter now requires auth, Instagram/Reddit block default UAs, and
  `og:image` scraping depends on page markup. Handle reuse across platforms is
  assumed, but same-name accounts belonging to different people are common.
- **Reverse-image search coverage is thin:** SerpApi needs a public URL (local
  files can't use it), SauceNAO is anime-oriented, Vision/TinEye are keyed and
  rate-limited; a cropped/resized/watermarked photo may defeat all four.
- **No false-positive calibration:** confidences are hand-set constants
  (0.6/0.45/0.4…). A labeled dataset (image → known location) and per-provider
  precision/recall would turn gut-feel numbers into calibrated probabilities.
- **No retries/backoff beyond the single 5 s Overpass retry**, and no handling
  for Nominatim 429 beyond an empty result — burst analysis of multiple photos
  in one process can still get throttled.
- **Privacy/legal:** probing third-party platforms (Sherlock) and uploading
  photos to Google/TinEye/SauceNAO sends the *subject's* data to external
  vendors; the tool has no opt-in gate or data-retention note for that.
- **`exif_extractor` format guard is narrow** (JPEG/PNG/TIFF/WEBP only) and
  GPS handling for `GPS_ALTITUDE_REF` bytes assumes little-endian — edge cases
  worth hardening with more real-world samples.

**Code-quality notes**
- `atlas/extraction.py` `GENERIC_FIRST_WORDS` contains duplicates ("una").
- `FILENAME_PATTERNS` mislabels the generic `IMG-<date>-<time>` Android pattern
  as "Telegram" and includes `PXL-` under WhatsApp; PXL is the Pixel camera
  prefix, not WhatsApp.
- `atlas/geocode.py` `_photon_search` hardcodes `importance: 0.4`, which
  `_ranked_hits` then also forces — the Photon score is effectively constant;
  expose Photon's actual quality/rank field.
- Long-running stages have no progress/interrupt handling; a cancelled run
  leaves the rate limiter timestamps stale (only affects the *next* run's first
  wait, and only by making it longer — harmless).
- No unit tests exist for either package; the trace/status contract makes them
  easy to add with mocked HTTP (responses / httpx-mock).