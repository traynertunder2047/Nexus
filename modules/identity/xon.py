from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Tuple

import requests

try:
    from dotenv import load_dotenv  # type: ignore

    load_dotenv()
except Exception:
    pass

from .helpers import request_with_retries

# ---------------------------------------------------------------------------
# Endpoints (env-overridable so tests / paid tiers can point elsewhere)
# ---------------------------------------------------------------------------

XON_CHECK_EMAIL = os.environ.get(
    "XON_CHECK_EMAIL_URL", "https://api.xposedornot.com/v1/check-email/{email}"
)
XON_ANALYTICS = os.environ.get(
    "XON_ANALYTICS_URL", "https://api.xposedornot.com/v1/breach-analytics"
)
XON_PASSWORDS = os.environ.get(
    "XON_PASSWORDS_URL", "https://passwords.xposedornot.com/api/v1/pass/anon/{prefix}"
)

# ---------------------------------------------------------------------------
# Per-product User-Agents — callers pass the right one in
# ---------------------------------------------------------------------------

UA_BREACH_CHECKER = "Nexus/1.0"
UA_BREACH_ANALYTICS = "Nexus/1.0"
UA_PASSWORD_CHECKER = "Nexus/1.0"

SERVER_ERROR_CODES = (502, 503)

# ---------------------------------------------------------------------------
# Low-level GET seam — single place to mock in offline tests
# ---------------------------------------------------------------------------


def request_xon(
    url: str,
    *,
    params: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 10,
    retries: Optional[int] = None,
) -> requests.Response:
    """GET `url` with XON-appropriate headers; returns the raw Response.

    Does NOT call raise_for_status() — the caller decides how to handle
    per-endpoint not-found semantics (check-email uses 404 *or* 200+Error,
    analytics uses 200+null, passwords uses 404).

    Transient failures (429/5xx, connection errors) are retried automatically
    via the shared backoff helper; permanent statuses pass through untouched.
    """
    return request_with_retries(
        lambda: requests.get(url, params=params, headers=headers or {}, timeout=timeout),
        attempts=retries,
        label="xposedornot",
    )


def status_error_payload(
    response: requests.Response, *, provider: str = "XposedOrNot"
) -> Optional[Dict[str, str]]:
    """Map transport-level HTTP errors to a uniform error message.

    Returns {"error": <msg>} for recognised status codes, else None so the
    caller should fall through to raise_for_status / body inspection.
    """
    code = response.status_code
    if code == 401:
        return {"error": f"Unauthorized — invalid or missing API key ({provider})."}
    if code == 429:
        retry = response.headers.get("Retry-After") if hasattr(response, "headers") else None
        hint = f" Retry-After: {retry}s." if retry else ""
        return {"error": f"Rate limit exceeded on {provider} API.{hint}"}
    if code in SERVER_ERROR_CODES:
        return {"error": f"{provider} server error, please retry later."}
    return None


def flatten_breaches(nested: Any) -> List[str]:
    """Flatten XposedOrNot's nested breaches field into a deduped ordered list.

    The live API returns {"breaches": [["Breach1","Breach2"],["Breach2","Breach3"]]}.
    Empty / missing input yields [].
    """
    seen: set[str] = set()
    out: List[str] = []
    for group in nested or []:
        if not isinstance(group, (list, tuple)):
            # Defensive: some older dumps used a flat list
            group = [group]
        for name in group:
            if isinstance(name, str) and name and name not in seen:
                seen.add(name)
                out.append(name)
            elif not isinstance(name, str) and name not in seen:
                # unlikely but keep non-string breach ids
                seen.add(name)  # type: ignore[arg-type]
                out.append(name)  # type: ignore[arg-type]
    return out
