"""
Doppelgänger - Face Search Pipeline (Mode 2)
============================================
Finds where a person's face appears on the internet and correlates
accounts/identities around it. Execution flow:

  Stage 0  - Face extraction: OpenCV Haar cascade (bundled with
             opencv-python); largest face is cropped for comparison.
             No face -> the mode is not applicable, clean early exit.
  Stage 1  - Reverse-image search (reuses Locus's providers: Google
             Vision / SerpApi / TinEye / SauceNAO, shared API keys).
             Returns every indexed page/image where the photo appears.
  Stage 2  - Face matching: every returned image (and the og:image of
             HTML pages that failed as direct images) is fetched, its
             faces detected and compared to the source face. Optional
             handle hints: platform avatars are fetched and compared
             too (verification of a suspected username). Each link
             carries a face verdict (strong/lbph/weak) and a
             whole-image hash distance (same-avatar correlation).
  Stage 3  - Identity context: pages are scraped for title / author /
             og:title and emails, handles, URLs and person-name
             candidates are extracted (Atlas regexes reused). The face
             is the matching key; the page text is where the identity
             appears (poster, news article, profile page).
  Stage 4  - Correlation report: every link grouped by platform with
             same-image flag, face verdict and evidence URL.
  Output   - Identity-only Candidates (no coordinates; fuse reports
             method "identity"), correlation map, structured payload.

Honest limits: a face alone cannot be mapped to a name by open tooling
- identity still comes from the text around the matched images, and
from the analyst's pivots (handles, emails, context). This mode is a
triage/verification tool, not automatic identification.

Every stage emits StageResult(stage, status, confidence, data, note);
status is one of: ok | no_data | skipped | error.

Package layout (reuses Locus + Atlas modules):
  config.py       - DoppelConfig + load_config (env/.env keys & flags)
  face.py         - Stage 0: Haar detection, crop, avhash + LBPH compare
  reverse.py      - Stage 1: reverse search (Locus providers) + page fetch
  match.py        - Stage 2: face-compare reverse hits + avatar probes
  context.py      - Stage 3: page scraping + identity text extraction
  correlation.py  - Stage 4: cross-platform correlation report
  pipeline.py     - run(): orchestration, trace, output payload
  __main__.py     - CLI: python -m modules.metadata.doppelganger <image> [handle...]

======================================================================
REQUIREMENTS
======================================================================
PYTHON PACKAGES
  Required:
    - requests            (already in requirements.txt)
    - Pillow              (already in requirements.txt)
    - opencv-contrib-python  (face detection + LBPH comparison)
  Reused from Locus (modules/metadata/locus/):
    - StageResult / Candidate contracts, fuse()
    - reverse-search providers, Sherlock schemas + hash gates,
      URL/email/handle regexes
  Reused from Atlas (modules/metadata/atlas/):
    - CAP_SEQ_RE person-name pattern, generic-word filters

API ENDPOINTS
    Free, no key:
    - Platform profile endpoints (avatar probing, same as Sherlock):
        GET https://api.github.com/users/{handle}
        GET https://t.me/{handle}
        GET https://old.reddit.com/user/{handle}/about.json
        GET https://steamcommunity.com/id/{handle}?xml=1
        GET https://www.tiktok.com/oembed?url=...
        GET https://www.youtube.com/@{handle}
        GET https://www.instagram.com/{handle}/
        GET https://api.twitter.com/i/users/profile_image?...&size=original
    - Any page the reverse search returns (scraped for title/author/og tags).
    Keyed (providers are skipped automatically if their key is missing):
    - Google Cloud Vision webDetection
        POST https://vision.googleapis.com/v1/images:annotate?key=KEY
        key: GOOGLE_VISION_API_KEY   (free tier ~1000 req/month)
    - SerpApi Google Images (needs public image URL)
        GET https://serpapi.com/search.json?engine=google_images
        key: SERPAPI_API_KEY
    - TinEye API (image upload, signed request)
        POST https://api.tineye.com/rest/
        keys: TINEYE_PUBLIC_KEY + TINEYE_PRIVATE_KEY (paid)
    - SauceNAO (image upload)
        POST https://saucenao.com/search.php
        key: SAUCENAO_API_KEY

ENVIRONMENT VARIABLES (.env)
    GOOGLE_VISION_API_KEY=      # reverse search (optional stage)
    SERPAPI_API_KEY=            # reverse search (optional stage)
    TINEYE_PUBLIC_KEY=          # reverse search (optional stage)
    TINEYE_PRIVATE_KEY=         # reverse search (optional stage)
    SAUCENAO_API_KEY=           # reverse search (optional stage)
    NOMINATIM_USER_AGENT=OSINTNexusBot/1.0   # polite probing identity
======================================================================
"""

from ..locus.contracts import Candidate, StageResult
from .config import DoppelConfig, load_config
from .pipeline import run

__all__ = ["run", "load_config", "DoppelConfig", "StageResult", "Candidate"]