"""Stage 3: scrape matched pages for identity text (title, author meta,
og:title) and extract emails / handles / URLs / person-name candidates
from it. The face is the matching key; the page text is where the
identity actually appears (missing-person poster, news article, profile
page naming the person)."""

import time
from concurrent.futures import ThreadPoolExecutor

from ..atlas.extraction import CAP_SEQ_RE, GENERIC_FIRST_WORDS
from ..locus.contracts import StageResult
from ..locus.ocr import EMAIL_RE, HANDLE_RE, URL_RE
from .config import DoppelConfig
from .reverse import _fetch_page, _page_info

IMAGE_EXTS = (".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".avif", ".tiff")
MAX_IDENTITIES = 10


def _extract_identities(text: str) -> list:
    """Emails, handles, URLs and capitalized multi-word names from text."""
    items = []
    for e in dict.fromkeys(EMAIL_RE.findall(text)):
        items.append({"type": "email", "value": e})
    for h in dict.fromkeys(HANDLE_RE.findall(text)):
        items.append({"type": "handle", "value": h.lstrip("@")})
    for u in dict.fromkeys(URL_RE.findall(text)):
        items.append({"type": "url", "value": u})
    for m in CAP_SEQ_RE.finditer(text):
        name = m.group(0).strip()
        if name.split()[0].lower() in GENERIC_FIRST_WORDS:
            continue
        items.append({"type": "name", "value": name})
    seen, out = set(), []
    for it in items:
        key = (it["type"], it["value"].lower())
        if key not in seen:
            seen.add(key)
            out.append(it)
    return out[:MAX_IDENTITIES]


def stage3_context(urls: list, cfg: DoppelConfig) -> StageResult:
    """Fetch up to max_context_pages HTML pages and extract identities."""
    started = time.time()
    pages = list(dict.fromkeys(
        u for u in urls if not u.lower().split("?")[0].endswith(IMAGE_EXTS)
    ))[:cfg.max_context_pages]
    if not pages:
        return StageResult("context", "no_data", 0.0, {"identities": []},
                           "no page URLs to scrape", time.time() - started)
    identities = []
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {pool.submit(_fetch_page, u, cfg): u for u in pages}
        for future in futures:
            html = future.result()
            if not html:
                continue
            info = _page_info(html)
            text = " ".join(filter(None, [info["title"], info["author"],
                                          info.get("og_title", "")]))
            for it in _extract_identities(text):
                it["source_url"] = futures[future]
                it["page_title"] = info["title"]
                identities.append(it)
    if not identities:
        return StageResult("context", "no_data", 0.0, {"identities": []},
                           "no identity text on the pages", time.time() - started)
    note = f"{len(identities)} identity hint(s) from {len(pages)} page(s)"
    return StageResult("context", "ok", 0.4, {"identities": identities},
                       note, time.time() - started)