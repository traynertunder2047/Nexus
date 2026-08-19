# OSINTNexusBot

A modular Python 3.14 CLI toolchain for **open-source intelligence (OSINT)
collection and correlation** - built to support lawful, authorized research
on publicly available data.

## Scope

The project covers three investigation-oriented use cases ("modes"), each
implemented as a self-contained, independently runnable package, plus
supporting modules for identity and network reconnaissance:

| Mode | Name | What it does |
|---|---|---|
| 1 | **Atlas** (`modules/metadata/atlas/`) | Text place search: extracts place names from free text (e.g. *"near the Colosseum in Rome"*), geocodes them (Nominatim + Photon + Google), disambiguates and fuses candidates into a single location estimate |
| 2 | **Doppelganger** (`modules/metadata/doppelganger/`) | Face search: detects a face in a photo (OpenCV), reverse-searches it, face-compares every hit, verifies suspected usernames via platform avatars, scrapes identity context and builds a cross-platform correlation report |
| 3 | **Locus** (`modules/metadata/locus/`) | Photo geolocation: EXIF/GPS extraction, OCR + language detection, reverse-image search, geocoding and point fusion to estimate where a photo was taken |

**Supporting modules** (in progress):

- `modules/identity/` - email lookup/prediction, breach and password checks,
  phone validation, social-link correlation
- `modules/network/` - WHOIS, DNS enumeration, port scanning, IP geolocation

## Design principles

- **Modular and standalone** - every mode runs on its own via
  `python -m modules.metadata.<mode>`; no global state between modes.
- **Graceful degradation** - every stage that needs an API key skips itself
  when the key is missing; the toolchain runs out of the box and improves
  as keys are added (see `.env.example`).
- **Transparent output** - each run returns a structured JSON payload with a
  per-stage trace (status, confidence, note, timing) so results can be
  audited and reproduced.

## Honest limits

- Only public, login-free endpoints are used: no PimEyes/Clearview-style
  face identification, no social-platform scraping, no credential attacks.
- A face alone cannot be mapped to a name by this tooling - identity comes
  from the text around matched images and the analyst's own pivots.
- Results are **triage/support evidence**, not identification: every mode
  flags uncertainty (radius, disagreement, low confidence) and expects
  analyst review.

## Usage

```powershell
.\.venv\Scripts\python.exe -m modules.metadata.atlas "near the Eiffel Tower, Paris"
.\.venv\Scripts\python.exe -m modules.metadata.locus photo.jpg
.\.venv\Scripts\python.exe -m modules.metadata.doppelganger photo.jpg [handle1 handle2 ...]
```

Implementation reports: `REPORT_ATLAS_LOCUS.md`, `REPORT_DOPPELGANGER.md`.

## Responsibility

OSINTNexusBot is an analysis tool for lawful, consensual, and authorized
investigations (defensive research, missing-person support, media
verification, personal-security audits). Operators are responsible for
complying with applicable laws, platform terms of service, and privacy
rules in their jurisdiction. The toolchain deliberately does not include
phishing, credential-theft, or scraping capabilities.