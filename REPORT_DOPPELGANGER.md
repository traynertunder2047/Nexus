# Doppelgänger - Mode 2 (Face Search) - Implementation Report

## 1. What was built

`modules/metadata/doppelganger/` - a face-search pipeline that answers:
"**Where does this face appear online, and what identity/accounts surround it?**"

It works in two directions:

- **Discovery** - reverse-image-search the photo, then face-compare every hit
  to confirm the face actually appears there (not just the same photo pasted
  elsewhere).
- **Verification** - the analyst supplies suspected usernames; each platform
  avatar is fetched and face-compared to the photo, confirming or refuting that
  the handle belongs to the person in the photo.

### Package structure (9 files, ~600 lines)

| File | Role |
|---|---|
| `__init__.py` | docstring (flow, requirements, endpoints) + re-exports |
| `config.py` | `DoppelConfig` + `load_config()` (env/.env keys and gates) |
| `face.py` | Stage 0: Haar cascade detection, crop, avhash + LBPH comparison |
| `reverse.py` | Stage 1: reverse-image search (reuses Locus providers) + page fetch |
| `match.py` | Stage 2: face-compare reverse hits + platform-avatar probes |
| `context.py` | Stage 3: page scraping + identity-text extraction |
| `correlation.py` | Stage 4: cross-platform correlation report |
| `pipeline.py` | `run()`: orchestration, trace, output payload |
| `__main__.py` | CLI: `python -m modules.metadata.doppelganger <image> [handle...]` |

`requirements.txt` gained `opencv-contrib-python`; `.env.example` documents that
Doppelgänger shares the Locus reverse-search keys. No new env vars required.

## 2. Logic flow - from user input to final output

```
user input:  photo file  +  optional handle hints  (e.g. "torvalds")
                     |
                     v
Stage 0  FACE EXTRACTION        [face.py]
   decode image (PIL), run OpenCV Haar cascade (frontalface_default,
   bundled with opencv-python). Largest face is cropped with a 15%
   margin -> "src_face" (283x283 for the test avatar).
   No face detected  -> early exit: summary "No face detected - nothing
   to match." (this mode is unusable on a face-less photo).
                     |
                     v
Stage 1  REVERSE-IMAGE SEARCH   [reverse.py -> locus/reverse_search.py]
   Upload/submit the photo to the configured providers (Google Vision /
   SerpApi / TinEye / SauceNAO; Locus keys shared). Each provider stage
   skips itself if its key is missing. Returns indexed pages+images where
   the photo appears, per provider.
   No keys configured -> status "skipped", pipeline continues (probes +
   handle verification still work).
                     |
                     v
Stage 2  FACE MATCHING          [match.py]
   For every returned image URL (thread pool, 8 workers):
     - fetch bytes -> decode -> detect faces -> compare cropped face to
       src_face with a two-tier gate:
         strong  if avhash distance <= 10      -> confidence 0.7
         lbph    if LBPH distance   <= 80      -> confidence 0.5
         weak    if avhash distance <= 25      -> confidence 0.3
     - whole-image perceptual hash distance is also computed:
       same_image=True when distance <= 10 (the *same avatar photo*
       reused across sites = account-correlation signal).
     - a URL that is really an HTML page is re-read and its og:image is
       compared instead (so "the photo on this page" is still tested).
   For every handle hint: fetch the platform avatar (Sherlock schemas:
   GitHub API, Telegram, Reddit JSON, Steam XML, Instagram, YouTube, X,
   TikTok oEmbed, ...) and run the same comparison.
   An entry is kept if it has a face verdict OR same_image.
                     |
                     v
Stage 3  IDENTITY CONTEXT       [context.py]
   Up to 5 page URLs are scraped (title, author meta, og:title) and the
   text is mined for identity hints with Locus + Atlas regexes:
     - emails   (EMAIL_RE)          -> type "email"
     - @handles (HANDLE_RE)         -> type "handle"
     - URLs     (URL_RE)            -> type "url"
     - capitalized multi-word names (CAP_SEQ_RE minus generic words)
                                    -> type "name"
   The face is the matching key; the page text is where the identity
   actually appears (poster, news article, profile page).
                     |
                     v
Stage 4  CORRELATION REPORT      [correlation.py]
   Every link grouped by platform (github/telegram/x/reddit/...), with
   same-image flag, face verdict, handle and evidence URL. Answers "the
   same face/avatar is on these N accounts".
                     |
                     v
CANDIDATES + FUSE
   - each extracted identity becomes a Candidate (identity method, no
     coordinates), confidence 0.35, boosted +0.3 x face-verdict
     confidence if the identity came from a face-matched page, +0.1 if
     same_image, capped at 0.6;
   - every verified handle becomes a Candidate: reason "handle @x
     verified: avatar face match (strong, distance 0) on github";
   - fuse() (Locus) reports final method "identity" + top_k.
                     |
                     v
output: JSON payload  { input, reverse, matches, identities,
                        correlation, candidates, final, top_k, trace,
                        summary }
   trace = per-stage (stage, status, confidence, note, seconds).
```

### Honest limit (stated in the package docstring)

A face alone cannot be mapped to a name by open tooling - PimEyes/Clearview
are locked down and social platforms block scraping. Identity therefore comes
from the text around the matched images and from the analyst's pivots
(handles, emails, context). Doppelgänger is a **triage/verification tool,
not automatic identification**.

## 3. Tools / API endpoints used

### Local tools (no network)
- **OpenCV (opencv-contrib-python 5.0.0)** - Haar cascade face detection
  (frontalface_default.xml, bundled) + `cv2.face.LBPHFaceRecognizer` local
  face comparison.
- **Pillow** - image decode, crop, RGB conversion.
- **Perceptual hashing + Hamming distance** (Locus `_compute_phash` /
  `_avg_hash` / `_hamming`) - whole-image similarity, same-avatar signal.
- **Regex libraries** (Locus `ocr.py`, Atlas `extraction.py`) - email /
  handle / URL / person-name extraction.

### Reverse-image providers (shared keys with Locus; skipped without key)
- Google Cloud Vision `webDetection` - `POST https://vision.googleapis.com/v1/images:annotate?key=KEY`
- SerpApi Google Images - `GET https://serpapi.com/search.json?engine=google_images`
- TinEye API - `POST https://api.tineye.com/rest/`
- SauceNAO - `POST https://saucenao.com/search.php`

### Handle-avatar probes (free, no key; same schemas as Sherlock)
- GitHub `GET https://api.github.com/users/{handle}`
- Telegram `GET https://t.me/{handle}`
- Reddit `GET https://old.reddit.com/user/{handle}/about.json`
- Steam `GET https://steamcommunity.com/id/{handle}?xml=1`
- Instagram `GET https://www.instagram.com/{handle}/`
- YouTube `GET https://www.youtube.com/@{handle}`
- X/Twitter `GET https://api.twitter.com/i/users/profile_image?...&size=original`
- TikTok oEmbed
- ...(full Sherlock schema set)

### Page scraping
- HTTP fetch + meta-tag parsing (og:title / og:image / author / <title>)
  of any page the reverse search returns.

## 4. Errors and bugs encountered, and how they were fixed

1. **`opencv-python` 5.0.0.93 is a stripped build** - it ships without
   `CascadeClassifier` and without the `haarcascades` data package, so face
   detection was impossible. *Fix:* downgraded to `opencv-python<5`
   (4.14.0), which restored the cascade API and bundled 19 cascade files.

2. **`cv2.face` (LBPH) missing from every standard OpenCV build** - the
   local face-distance comparator could not be imported. *Fix:* switched to
   **`opencv-contrib-python` 5.0.0**, the full build - CascadeClassifier,
   haarcascades data, `cv2.face` and `LBPHFaceRecognizer_create` all
   verified present. `requirements.txt` now pins `opencv-contrib-python`.
   (Reproducibility note: the plain `opencv-python` name must NOT be
   used; its 5.x wheels are stripped.)

3. **GitHub avatar host not attributed to a platform** - the probe returned
   `platform: "avatars.githubusercontent.com"` because the fragment
   `"github.com"` is not a substring of `"avatars.githubusercontent.com"`.
   *Fix:* extended the domain map with the real CDN hosts
   (`githubusercontent`, `ytimg`, `twimg`, `fbcdn`, `scontent`,
   `steamstatic`, `discordapp`, `cdninstagram`). The probe now reports
   `platform: "github"`.

4. **A verified handle produced no identity candidate** - handle
   verification is a core use-case (analyst suspects a username), but
   candidates were built only from stage-3 page text, so a strong avatar
   face match never reached `fuse()` and the run ended with
   `final: none` despite a perfect 0-distance match. *Fix:* `pipeline.py`
   now emits a `doppelganger:handle` Candidate per verified handle
   (confidence 0.35 + 0.3 x verdict + 0.1 if same_image, capped 0.6,
   reason "handle @x verified: avatar face match (strong, distance 0)").
   Verified by live run: `final` became `method: "identity",
   confidence: 0.6`.

5. **Error paths violated the payload contract** - `run()` returned a bare
   `{"error": ...}` dict for a missing file, so downstream callers crashed
   with `KeyError: 'final'`. *Fix:* added `_error_payload()` so every exit
   path returns the full payload shape (input / final / trace / summary /
   candidates / ...) with the message embedded in `error`, `final.note`
   and `summary`.

6. *(Earlier in the session, already logged for the Locus report)* the
   stripped 5.0.0.93 wheel was first swapped for 4.14.0 before the contrib
   switch - both steps were verified live with face boxes on the test
   avatar.

## 5. Verification performed (live)

| Test | Result |
|---|---|
| `avatar_src.png` alone | 1 face detected, crop 283x283 |
| Self-match (`face_verdict(face, face)`) | strong, distance 0, LBPH 0.0 |
| CLI `... avatar_src.png torvalds` | GitHub avatar fetched, **strong match distance 0**, same_image, platform github, Candidate `@torvalds verified`, final identity 0.6 |
| CLI `... avatar_src.png billgates` | no match, 0 candidates (negative verification works) |
| `avatar_src.png` no handles | graceful, final none, summary "No related images..." |
| `geo.jpg` / `plain.jpg` / `sign.png` / `unrelated.png` | 0 faces detected (negatives correct) |
| `unrelated.png torvalds` | "No face detected" early exit |
| missing file | full payload with error + summary, no crash |
| stage3_context on `https://github.com/torvalds` | `Linus Torvalds` name extracted from og:title |
| Reverse-search with no keys | status "skipped", pipeline continues |

All 9 files pass `py_compile`; `from modules.metadata.doppelganger import
run, load_config, DoppelConfig, StageResult, Candidate` imports cleanly.