"""Stage 1 OCR: preprocessing, two-pass language detection, regex entity
extraction (URLs / emails / usernames) and POI place-name heuristics."""

import io
import re
import time
from typing import Optional

from PIL import Image

from .config import PipelineConfig
from .contracts import StageResult

try:
    import pytesseract
except ImportError:
    pytesseract = None

try:
    from email_validator import validate_email
except ImportError:
    validate_email = None

try:
    from langdetect import detect as _detect_lang
    from langdetect import LangDetectException as _LangDetectException
except ImportError:
    _detect_lang = None
    _LangDetectException = Exception

LANGDETECT_TO_TESSERACT = {
    "it": "ita", "en": "eng", "de": "deu", "fr": "fra", "es": "spa",
    "pt": "por", "nl": "nld", "ru": "rus", "ja": "jpn", "zh-cn": "chi_sim",
    "zh-tw": "chi_tra", "ar": "ara", "tr": "tur", "pl": "pol", "cs": "ces",
    "hu": "hun", "sv": "swe", "da": "dan", "fi": "fin", "no": "nor",
    "el": "ell", "ro": "ron", "bg": "bul", "uk": "ukr", "hr": "hrv",
    "sr": "srp", "sk": "slk", "sl": "slv", "et": "est", "lt": "lit",
    "lv": "lav",
}


def _preprocess_for_ocr(image_path: str) -> io.BytesIO:
    """Upscale + grayscale in memory; OCR accuracy depends on it."""
    with Image.open(image_path) as img:
        gray = img.convert("L")
        gray = gray.resize((gray.width * 2, gray.height * 2), Image.LANCZOS)
        buf = io.BytesIO()
        gray.save(buf, format="PNG")
        buf.seek(0)
        return buf


EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"']+")
HANDLE_RE = re.compile(r"(?<![\w.])@[a-zA-Z0-9_]{3,30}")
CAP_SEQ_RE = re.compile(
    r"(?<![A-Za-zÀ-ÿ])(?:[A-ZÀ-Ý][a-zà-ÿ'’\-]+"
    r"(?:\s+(?i:de|del|della|dei|di|da|d'|la|le|il|lo|i|gli|san|santa|sant'|"
    r"st\.|via|piazza|viale|corso|vico|largo|località|fra))?\s+){1,2}"
    r"[A-ZÀ-Ý][a-zà-ÿ'’\-]+(?!(?i:via|piazza|viale|corso|vico|largo|st\.)\b)(?![A-Za-zÀ-ÿ])"
)


def _extract_entities(text: str) -> dict:
    """Regex extraction of URLs/emails/usernames; emails validated separately."""
    emails = list(dict.fromkeys(EMAIL_RE.findall(text)))
    urls = [u if u.startswith(("http://", "https://")) else "https://" + u
            for u in dict.fromkeys(URL_RE.findall(text))]
    usernames = [u.lstrip("@") for u in dict.fromkeys(HANDLE_RE.findall(text))]
    verified_emails = []
    if validate_email is not None:
        for e in emails:
            try:
                validate_email(e, check_deliverability=False)
                verified_emails.append(e)
            except Exception:
                pass
    else:
        verified_emails = list(emails)
    return {"urls": urls, "emails": emails, "usernames": usernames,
            "verified": {"emails": verified_emails}}


STREET_WORD_RE = re.compile(r"\s+(via|piazza|viale|corso|vico|largo|st\.)\s+", re.I)


def _extract_place_names(text: str, max_names: int = 5) -> list:
    """Heuristic POI candidates: Title-Case multi-word sequences (signage pattern).

    Matches are split at street-type words ("Hotel Splendido Via Roma" ->
    "Hotel Splendido" + "Via Roma") so Overpass gets clean names. Deliberately
    conservative: only clean multi-word capitalized sequences survive.
    """
    names, seen = [], set()

    def add(cand: str):
        key = cand.lower()
        if key not in seen and len(cand) >= 3:
            seen.add(key)
            names.append(cand)

    for m in CAP_SEQ_RE.finditer(text):
        match = m.group(0).strip()
        while True:
            sm = STREET_WORD_RE.search(match)
            if not sm:
                break
            left, street = match[:sm.start()].strip(), sm.group(1).capitalize()
            if left:
                add(left)
            match = street + " " + match[sm.end():].strip()
        if match:
            add(match)
        if len(names) >= max_names:
            break
    return names[:max_names]


def _resolve_tess_langs(cfg: PipelineConfig) -> Optional[str]:
    """Effective Tesseract language list, filtered by installed packs.

    Prevents a crash when cfg.tesseract_lang references a pack that is
    not installed (default install ships only eng+osd).
    """
    requested = [lang for lang in cfg.tesseract_lang.split("+") if lang]
    try:
        available = set(pytesseract.get_languages(config=""))
    except Exception:
        available = None
    if available is None:
        return "+".join(requested) if requested else None
    effective = [lang for lang in requested if lang in available]
    if not effective:
        effective = list(available & {"eng"})
    return "+".join(effective) if effective else None


def _ocr_pass(buf: io.BytesIO, lang: str, cfg: PipelineConfig) -> str:
    """One Tesseract pass over the preprocessed buffer."""
    return pytesseract.image_to_string(Image.open(buf), lang=lang).strip()


def stage1_ocr(image_path: str, cfg: PipelineConfig) -> StageResult:
    """OCR scene text, then extract + validate URLs/emails/usernames.

    Two-pass language detection when langdetect is installed: first pass
    with the configured default languages, detect the dominant language,
    then re-OCR with the detected language pack when it differs and is
    available. The language of short signage text is itself a
    geolocation signal, so the threshold is 12 chars - below that
    langdetect typically raises "No features in text" (caught and
    ignored). A misdetected language can only produce a shorter read,
    which is discarded (only longer reads replace the first pass).
    """
    started = time.time()
    if pytesseract is None:
        return StageResult("ocr", "skipped", 0.0, {}, "pytesseract not installed")
    try:
        pytesseract.get_tesseract_version()
    except Exception:
        return StageResult("ocr", "skipped", 0.0, {},
                           "Tesseract binary not found on PATH (install tesseract-ocr)",
                           time.time() - started)
    langs = _resolve_tess_langs(cfg)
    if not langs:
        return StageResult("ocr", "skipped", 0.0, {},
                           "no Tesseract language packs installed", time.time() - started)
    try:
        buf = _preprocess_for_ocr(image_path)
    except Exception as exc:
        return StageResult("ocr", "error", 0.0, {}, str(exc), time.time() - started)
    try:
        text = _ocr_pass(buf, langs, cfg)
    except Exception as exc:
        return StageResult("ocr", "error", 0.0, {}, str(exc), time.time() - started)
    detected = None
    re_ocred = False
    if _detect_lang is not None and len(text) >= 12:
        try:
            lang = _detect_lang(text)
            detected = LANGDETECT_TO_TESSERACT.get(lang)
            if detected and detected not in langs.split("+"):
                buf.seek(0)
                try:
                    second = _ocr_pass(buf, detected, cfg)
                except Exception:
                    second = ""
                if len(second) > len(text):
                    text = second
                re_ocred = True
        except _LangDetectException:
            pass
    if not text:
        return StageResult("ocr", "no_data", 0.0,
                           {"text": "", "urls": [], "emails": [], "usernames": [],
                            "verified": {"emails": []}, "place_names": []},
                           "no readable text", time.time() - started)
    entities = _extract_entities(text)
    entities["place_names"] = _extract_place_names(text)
    entities["text"] = text
    note = "OCR extracted text" + (" (re-OCR with detected language)" if re_ocred else "")
    return StageResult(
        "ocr", "ok", 0.4,
        entities,
        note,
        time.time() - started,
    )