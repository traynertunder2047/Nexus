from __future__ import annotations

import logging
import os
import re
import time
from contextlib import contextmanager
from email.utils import parsedate_to_datetime
from typing import Any, Callable, Dict, Iterable, Optional, Tuple

import requests

# ---------------------------------------------------------------------------
# Status constants
# ---------------------------------------------------------------------------

STATUS_OK = "ok"
STATUS_NO_DATA = "no_data"
STATUS_ERROR = "error"

# ---------------------------------------------------------------------------
# Logging hygiene — mirror whois_lookup: suppress chatty library loggers
# ---------------------------------------------------------------------------

def install_nullhandler(logger_name: str) -> None:
    """Attach a NullHandler to `logger_name` so unconfigured loggers stay quiet.

    Idempotent: safe to call twice.
    """
    logger = logging.getLogger(logger_name)
    if not any(isinstance(h, logging.NullHandler) for h in logger.handlers):
        logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Timing
# ---------------------------------------------------------------------------

def elapsed_ms(start: float) -> int:
    """Milliseconds elapsed since `start` (from time.monotonic())."""
    return round((time.monotonic() - start) * 1000)


@contextmanager
def timed():
    """Context manager yielding a callable that returns elapsed ms.

    Usage:
        with timed() as ms:
            do_work()
        payload["elapsed_ms"] = ms()
    """
    start = time.monotonic()
    yield lambda: elapsed_ms(start)


# ---------------------------------------------------------------------------
# Email validation — single seam for all identity modules
# ---------------------------------------------------------------------------

# Fallback regex when email-validator is not installed (should not happen —
# it is a direct dep).
_FALLBACK_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def validate_email(address: str, *, check_deliverability: bool = False) -> tuple[bool, str]:
    """Validate `address` using email-validator; returns (ok, normalized).

    On success, `normalized` is the lower-cased, trimmed, normalized address
    (e.g. punycode domain, lowercased local-part handling is library-defined).
    On failure, `normalized` is "" and `ok` is False.
    check_deliverability passes through to email-validator (DNS/MX check) —
    default False to avoid network in offline tests.
    Falls back to a permissive regex when email-validator is unavailable.
    """
    raw = (address or "").strip()
    if not raw:
        return False, ""
    try:
        from email_validator import validate_email as _ev  # type: ignore
        from email_validator import EmailNotValidError  # type: ignore

        try:
            info = _ev(raw, check_deliverability=check_deliverability)
            # info.normalized is the canonical form; keep lowercased for
            # consistency with breach APIs which are case-insensitive.
            normalized = getattr(info, "normalized", raw).lower()
            return True, normalized
        except EmailNotValidError:
            return False, ""
    except ImportError:
        # Graceful fallback — still catches obvious typos.
        if _FALLBACK_RE.match(raw):
            return True, raw.lower()
        return False, ""


# ---------------------------------------------------------------------------
# Uniform envelope helpers
# ---------------------------------------------------------------------------

def error_result(
    message: str,
    *,
    query: Optional[Dict[str, Any]] = None,
    elapsed: Optional[int] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Envelope for transport/validation/API errors.

    Always has status=error and error=<message>. Optionally carries the
    echoed query and elapsed_ms so callers can correlate failures.
    """
    payload: Dict[str, Any] = {
        "status": STATUS_ERROR,
        "error": message,
        "findings": [],
        "summary": message,
    }
    if elapsed is not None:
        payload["elapsed_ms"] = elapsed
    if query is not None:
        payload["query"] = query
    if extra:
        payload.update(extra)
    return payload


def no_data_result(
    message: str,
    *,
    query: Optional[Dict[str, Any]] = None,
    elapsed: Optional[int] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Envelope for successful lookups that returned nothing (no_data)."""
    payload: Dict[str, Any] = {
        "status": STATUS_NO_DATA,
        "findings": [],
        "summary": message,
    }
    if elapsed is not None:
        payload["elapsed_ms"] = elapsed
    if query is not None:
        payload["query"] = query
    if extra:
        payload.update(extra)
    return payload


# ---------------------------------------------------------------------------
# Retry / backoff (P2.4) — shared transport wrapper for identity API calls
# ---------------------------------------------------------------------------

# Status codes worth retrying: rate limiting + transient server errors.
# 4xx like 400/401/403/404 are permanent for a given request — never retried.
RETRYABLE_STATUS = (429, 500, 502, 503, 504)


def _retry_settings() -> Dict[str, float]:
    """Read retry knobs from the environment at call time (not import time)
    so tests can override them per-test via monkeypatch.setenv."""
    try:
        attempts = max(0, int(os.environ.get("RETRY_ATTEMPTS", "2")))
    except ValueError:
        attempts = 2
    try:
        backoff = max(0.0, float(os.environ.get("RETRY_BACKOFF", "0.5")))
    except ValueError:
        backoff = 0.5
    try:
        max_sleep = max(0.0, float(os.environ.get("RETRY_MAX_SLEEP", "20")))
    except ValueError:
        max_sleep = 20.0
    return {"attempts": attempts, "backoff": backoff, "max_sleep": max_sleep}


def retry_after_seconds(response: Any, max_sleep: float) -> Optional[float]:
    """Extract a wait time from a Retry-After header, capped at max_sleep.

    Supports both delay-seconds ("30") and HTTP-date ("Wed, 21 Oct 2015
    07:28:00 GMT") forms per RFC 7231. Returns None when absent/unparseable
    or when the parsed date is in the past.
    """
    headers = getattr(response, "headers", None) or {}
    raw = headers.get("Retry-After")
    if not raw:
        return None
    raw = str(raw).strip()
    try:
        return min(float(int(raw)), max_sleep)
    except ValueError:
        pass
    try:
        target = parsedate_to_datetime(raw).timestamp()
    except (TypeError, ValueError):
        return None
    wait = target - time.time()
    if wait <= 0:
        return None
    return min(wait, max_sleep)


def _backoff_sleep(backoff: float, attempt: int, max_sleep: float) -> float:
    """Exponential backoff for `attempt` (0-based), capped at max_sleep."""
    return min(backoff * (2 ** attempt), max_sleep)


def request_with_retries(
    fn: Callable[[], Any],
    *,
    attempts: Optional[int] = None,
    backoff: Optional[float] = None,
    max_sleep: Optional[float] = None,
    retry_status: Iterable[int] = RETRYABLE_STATUS,
    retry_exc: Tuple[type, ...] = (requests.RequestException,),
    sleep: Callable[[float], None] = time.sleep,
    label: str = "",
) -> Any:
    """Call `fn()` (a zero-arg HTTP request thunk), retrying transient failures.

    Semantics:
      - Retries when fn() raises one of `retry_exc` (connection errors, timeouts)
        or when the response status is in `retry_status` (429/5xx).
      - Non-retryable responses (400/401/403/404, or any success) are returned
        immediately — callers keep their existing error mapping untouched.
      - Waits honor the server's Retry-After header when present (capped at
        max_sleep), else exponential backoff: backoff * 2^attempt.
      - `attempts` = number of RETRIES after the initial call (0 = single try).
      - Returns the last response when retries are exhausted (callers then map
        it to their error payload as before); re-raises the last exception when
        the transport itself kept failing.
    """
    settings = _retry_settings()
    if attempts is None:
        attempts = int(settings["attempts"])
    if backoff is None:
        backoff = settings["backoff"]
    if max_sleep is None:
        max_sleep = settings["max_sleep"]

    total = attempts + 1  # initial call + retries
    retry_status = set(retry_status)

    for attempt in range(total):
        last_exc: Optional[BaseException] = None
        try:
            response = fn()
        except retry_exc as e:  # transport-level failure
            last_exc = e
            response = None

        if response is not None and response.status_code not in retry_status:
            return response  # success or permanent 4xx — caller decides

        if attempt == total - 1:
            if last_exc is not None:
                raise last_exc
            return response

        if response is not None:
            wait = retry_after_seconds(response, max_sleep)
            if wait is None:
                wait = _backoff_sleep(backoff, attempt, max_sleep)
        else:
            wait = _backoff_sleep(backoff, attempt, max_sleep)
        if wait > 0:
            sleep(wait)

    # Unreachable (loop always returns/raises) — defensive
    raise RuntimeError("request_with_retries loop exited unexpectedly")
