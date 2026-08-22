"""Shared rate limiting for public API providers.

Nominatim (1 req/s) and Overpass (2 s spacing) are used by both Locus
and Atlas. The throttle state lives in one place so the two pipelines -
and the stages within one pipeline run - cannot exceed the providers'
usage policies when their requests fire back-to-back in the same
process. Previously each module kept its own counter: Atlas's forward
geocode stage could be followed within the same second by a reverse
geocode (Locus's counter), risking HTTP 429 rate-limit responses."""

import time

_LAST_NOMINATIM = 0.0
_LAST_OVERPASS = 0.0


def wait_nominatim() -> None:
    """Enforce Nominatim's 1 request/second policy (shared across stages)."""
    global _LAST_NOMINATIM
    delay = _LAST_NOMINATIM + 1.0 - time.time()
    if delay > 0:
        time.sleep(delay)
    _LAST_NOMINATIM = time.time()


def wait_overpass() -> None:
    """Enforce a minimum 2 s spacing between Overpass queries (shared)."""
    global _LAST_OVERPASS
    delay = _LAST_OVERPASS + 2.0 - time.time()
    if delay > 0:
        time.sleep(delay)
    _LAST_OVERPASS = time.time()
