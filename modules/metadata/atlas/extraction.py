"""Stage 0: text normalization, language -> country prior, and heuristic
place-name extraction (capitalized sequences, prepositional anchors).
The language of the text is itself a geolocation prior: "ci vediamo
davanti al Colosseo" is far more likely to mean Rome than the Las Vegas
Colosseum - the country filter in Stage 1.5 exploits exactly that."""

import re
import time
from typing import Optional

from ..locus.contracts import StageResult
from ..locus.ocr import URL_RE
from ..locus.overpass import CITY_SUFFIX_WORDS
from .config import AtlasConfig

try:
    from langdetect import detect as _detect_lang
    from langdetect import LangDetectException as _LangDetectException
except ImportError:
    _detect_lang = None
    _LangDetectException = Exception

LANG_TO_COUNTRIES = {
    "it": ("italy", "italia"),
    "fr": ("france",),
    "de": ("germany", "deutschland"),
    "es": ("spain", "espana", "españa"),
    "nl": ("netherlands",),
    "pl": ("poland", "polska"),
    "ru": ("russia",),
    "ja": ("japan",),
    "ko": ("south korea",),
    "tr": ("turkey", "turkiye", "türkiye"),
    "el": ("greece",),
    "sv": ("sweden", "sverige"),
    "da": ("denmark",),
    "fi": ("finland",),
    "no": ("norway",),
    "ro": ("romania", "românia"),
    "bg": ("bulgaria",),
    "uk": ("ukraine",),
    "hr": ("croatia",),
    "sr": ("serbia",),
    "cs": ("czechia", "czech republic"),
    "sk": ("slovakia",),
    "hu": ("hungary", "magyarorszag", "magyarország"),
    "he": ("israel",),
    "th": ("thailand",),
    "vi": ("vietnam",),
    "id": ("indonesia",),
    "zh-cn": ("china",),
    "zh-tw": ("taiwan",),
}

CAP_SEQ_RE = re.compile(
    r"(?<![A-Za-zÀ-ÿ])(?:[A-ZÀ-Ý][a-zà-ÿ'’\-]+"
    r"(?:\s+(?i:de|del|della|dei|di|da|d'|la|le|il|lo|i|gli|san|santa|sant'|st\.|"
    r"von|van|der|den|zum|zur|und|du|des|les|en|el|los|las|do|dos|das|y|e|o|na|"
    r"ul|pr\.|rue|street|strasse|platz|calle|rua|gatan|vej|katu|via|piazza|"
    r"viale|corso))?\s+){1,2}"
    r"[A-ZÀ-Ý][a-zà-ÿ'’\-]+(?![A-Za-zÀ-ÿ])"
)

ANCHOR_RE = re.compile(
    r"\b(?i:in|at|near|next to|close to|downtown|uptown|outside|inside|"
    r"vicino a|presso|davanti a|di fronte a|da|nel|nella|nelle|nei|"
    r"bei|beim|im|am|an der|auf der|in der|à|a|en|au|aux|près de|"
    r"na|w|przy|у|в|на|по)\s+"
    r"(?:(?i:the|a|an|il|lo|la|le|un|una|uno|el|los|las|les|der|die|das|"
    r"ein|eine|het|de)\s+)?"
    r"([A-ZÀ-Ý][a-zà-ÿ'’\-]*(?:\s+[A-ZÀ-Ý][a-zà-ÿ'’\-]*){0,3})"
)

ANCHOR_ARTICLE_RE = re.compile(
    r"^(?i:the|a|an|il|lo|la|le|un|una|uno|el|los|las|les|der|die|das|"
    r"ein|eine|het|de)\s+")

GENERIC_FIRST_WORDS = {
    "the", "a", "an", "this", "that", "these", "those", "my", "our", "your",
    "his", "her", "its", "we", "you", "they", "i", "he", "she", "it", "and",
    "or", "but", "if", "then", "when", "where", "what", "who", "why", "how",
    "in", "on", "at", "to", "for", "of", "from", "with", "by", "is", "are",
    "was", "were", "be", "been", "will", "would", "can", "could", "should",
    "may", "might", "must", "do", "does", "did", "have", "has", "had", "not",
    "no", "so", "very", "just", "please", "hello", "hi", "hey", "dear",
    "today", "tomorrow", "yesterday", "tonight", "morning", "afternoon",
    "evening", "monday", "tuesday", "wednesday", "thursday", "friday",
    "saturday", "sunday", "oggi", "ieri", "domani", "stasera", "quando",
    "dove", "come", "perche", "perché", "non", "un", "una", "uno", "una",
    "il", "lo", "la", "i", "gli", "le", "di", "che", "e", "a", "in", "da",
    "ma", "se", "poi", "anche", "solo", "qui", "lì", "li", "me", "te", "si",
    "c'è", "c'e", "sono", "ciao", "grazie", "prego", "bene", "male",
}


def _detect_country(text: str) -> dict:
    """Language -> country prior; None when ambiguous or undetectable."""
    if _detect_lang is None or len(text) < 12:
        return {"language": None, "country_prior": None, "country_aliases": None}
    try:
        lang = _detect_lang(text)
    except _LangDetectException:
        return {"language": None, "country_prior": None, "country_aliases": None}
    countries = LANG_TO_COUNTRIES.get(lang)
    return {"language": lang, "country_prior": countries[0] if countries else None,
            "country_aliases": countries if countries else None}


def _context(text: str, start: int, end: int, width: int = 60) -> str:
    """Snippet around a match for the analyst report."""
    lo, hi = max(0, start - width // 2), min(len(text), end + width // 2)
    return text[lo:hi].strip()


SINGLE_WORD_RE = re.compile(r"(?<![A-Za-zÀ-ÿ])[A-ZÀ-Ý][a-zà-ÿ'’\-]{2,}(?![A-Za-zÀ-ÿ])")


def _extract_place_names(text: str, max_names: int = 8) -> list:
    """Capitalized multi-word sequences + prepositional anchor groups +
    single capitalized words that are known cities."""
    names, seen = [], set()
    seq_spans = []

    def add(cand: str, kind: str, start: int, end: int):
        key = cand.lower()
        if key in seen or len(cand) < 3:
            return
        if cand.split()[0].lower() in GENERIC_FIRST_WORDS:
            return
        seen.add(key)
        names.append({"name": cand, "kind": kind, "context": _context(text, start, end)})

    for m in CAP_SEQ_RE.finditer(text):
        seq_spans.append((m.start(), m.end()))
        add(m.group(0).strip(), "sequence", m.start(), m.end())
        if len(names) >= max_names:
            break
    for m in ANCHOR_RE.finditer(text):
        start, end = m.start(1), m.end(1)
        if any(s <= start and end <= e for s, e in seq_spans):
            continue
        name = ANCHOR_ARTICLE_RE.sub("", m.group(1).strip())
        add(name, "anchor", start, end)
        if len(names) >= max_names:
            break
    for m in SINGLE_WORD_RE.finditer(text):
        word = m.group(0)
        if word.lower() in CITY_SUFFIX_WORDS and not any(
                s <= m.start() and m.end() <= e for s, e in seq_spans):
            add(word, "city", m.start(), m.end())
            if len(names) >= max_names:
                break
    return names[:max_names]


def stage0_extract(text: str, cfg: AtlasConfig) -> StageResult:
    """Normalize text, detect language/country prior, extract candidates."""
    started = time.time()
    norm = re.sub(r"\s+", " ", text).strip()
    if not norm:
        return StageResult("extraction", "error", 0.0, {},
                           "empty input text", time.time() - started)
    lang = _detect_country(norm)
    names = _extract_place_names(norm, cfg.max_candidates)
    urls = list(dict.fromkeys(URL_RE.findall(norm)))
    if not names and not urls:
        return StageResult("extraction", "no_data", 0.0,
                           {"text": norm, "language": lang["language"],
                            "country_prior": lang["country_prior"],
                            "country_aliases": lang["country_aliases"],
                            "candidates": [], "urls": urls},
                           "no place-like references found", time.time() - started)
    note = (f"{len(names)} place candidate(s)" +
            (f", language {lang['language']} -> prior {lang['country_prior']}"
             if lang["language"] else ""))
    return StageResult("extraction", "ok", 0.5,
                       {"text": norm, "language": lang["language"],
                        "country_prior": lang["country_prior"],
                        "country_aliases": lang["country_aliases"],
                        "candidates": names, "urls": urls},
                       note, time.time() - started)