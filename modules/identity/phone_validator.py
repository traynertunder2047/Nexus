from __future__ import annotations

import json, os, time, sys

import phonenumbers
import requests
from phonenumbers import carrier, geocoder

from ..usage import usage_line
from .helpers import (
    STATUS_ERROR,
    STATUS_OK,
    elapsed_ms,
    request_with_retries,
)

try:
    from dotenv import load_dotenv  # type: ignore

    load_dotenv()
except Exception:
    pass

VERIFONE_ENDPOINT = "https://api.veriphone.io/v3/verify"
USER_AGENT = "Nexus/1.0"


def _parse(raw_input: str, default_region: str = "IT"):
    """Parse + validate; returns (parsed, error_message).

    Uses phonenumbers.parse with default_region, then is_valid_number.
    """
    try:
        parsed = phonenumbers.parse(raw_input, default_region)
    except phonenumbers.NumberParseException as e:
        return None, f"Parsing failed: {e}"
    if not phonenumbers.is_valid_number(parsed):
        return None, "Invalid phone number structure."
    return parsed, None


def _resolve_veriphone_key(explicit: str | None = None) -> str | None:
    """API key precedence: explicit arg > VERIPHONE_API_KEY env var > None."""
    if explicit:
        return explicit.strip() or None
    return os.environ.get("VERIPHONE_API_KEY", "").strip() or None


def _veriphone_lookup(e164: str, api_key: str, timeout: int = 10) -> requests.Response:
    """Query Veriphone /v3/verify for one E164 number; returns raw Response.

    Seam for offline tests — monkeypatch this, not requests.
    """
    return request_with_retries(
        lambda: requests.get(
            VERIFONE_ENDPOINT,
            params={"phone": e164},
            headers={"Authorization": f"Bearer {api_key}", "User-Agent": USER_AGENT},
            timeout=timeout,
        ),
        label="veriphone",
    )


def _live_payload(
    e164: str,
    *,
    live: bool | None,
    api_key: str | None,
    timeout: int,
) -> dict:
    """Run the optional Veriphone live stage; returns the payload["live"] block.

    live semantics: None = auto (run iff a key is available), True = force
    (report an error block if no key), False = skip (no network).
    All failures are contained here and returned as {"error": ...} so the
    offline result is never lost.
    """
    key = _resolve_veriphone_key(api_key)
    if live is False or (live is None and not key):
        return {}
    if not key:
        return {"error": "--live requested but VERIPHONE_API_KEY is not set."}

    try:
        response = _veriphone_lookup(e164, api_key=key, timeout=timeout)
    except requests.RequestException as e:
        return {"error": f"Veriphone request failed: {e}"}

    if response.status_code == 401:
        return {"error": "Veriphone: invalid or missing API key."}
    if response.status_code == 402:
        return {"error": "Veriphone: insufficient credits (free tier exhausted?)."}
    if response.status_code == 429:
        retry = response.headers.get("Retry-After") if hasattr(response, "headers") else None
        hint = f" Retry-After: {retry}s." if retry else ""
        return {"error": f"Veriphone: rate limit exceeded.{hint}"}
    try:
        response.raise_for_status()
    except requests.RequestException:
        return {"error": f"Veriphone returned HTTP {response.status_code}."}

    try:
        data = response.json()
    except ValueError:
        return {"error": "Veriphone returned invalid JSON."}
    if not isinstance(data, dict) or data.get("status") not in ("success", None):
        msg = (data or {}).get("message", "unknown error") if isinstance(data, dict) else data
        return {"error": f"Veriphone error: {msg}"}

    return {
        "provider": "veriphone",
        "carrier": data.get("carrier") or "Unknown",
        "phone_type": data.get("phone_type") or "Unknown",
        "region": data.get("phone_region") or data.get("country") or "Unknown",
        "international": data.get("international_number") or "",
        "local": data.get("local_number") or "",
    }


def search_phone_pipeline(raw_input: str, default_region: str = "IT") -> dict:
    """Validate + normalize a phone number and return metadata.

    The legacy entrypoint kept for backwards-compat (used by
    phone_breach_check). Deliberately live=False so breach checks never
    spend Veriphone credits.
    """
    result = run(raw_input, default_region=default_region, live=False)
    if result.get("status") == STATUS_ERROR:
        return {"status": "error", "message": result.get("error", "Invalid phone number.")}
    # Map unified payload back to the legacy shape expected by phone_breach_check tests
    return {
        "status": "success",
        "search_keys": result["search_keys"],
        "metadata": result["metadata"],
        "database_hits": [],
    }


def run(
    raw_input: str,
    default_region: str = "IT",
    live: bool | None = None,
    timeout: int = 10,
    VERIPHONE_API_KEY: str | None = None,  # noqa: N803 — explicit key override
) -> dict:
    """Validate + normalize a phone number; returns unified payload.

    live: None = auto (Veriphone stage runs iff VERIPHONE_API_KEY is set),
    True = force (offline result kept even if the stage errors),
    False = never touch the network.

    Never raises — all parse/validation failures become status=error.
    """
    start = time.monotonic()
    raw = (raw_input or "").strip()
    query = {"input": raw, "default_region": default_region}
    if not raw:
        return {
            "status": STATUS_ERROR,
            "error": "No phone number provided.",
            "findings": [],
            "summary": "No phone number provided.",
            "elapsed_ms": elapsed_ms(start),
            "query": query,
        }

    parsed, err = _parse(raw, default_region)
    if err is not None:
        return {
            "status": STATUS_ERROR,
            "error": err,
            "findings": [],
            "summary": err,
            "elapsed_ms": elapsed_ms(start),
            "query": query,
        }

    e164_key = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    msisdn_key = e164_key.lstrip("+")
    # country = ISO region the number belongs to (always resolvable once parsed,
    # e.g. "IT"); area = geographic description (city/region) from the geocoder,
    # which is empty for mobile/non-geographic numbers.
    country = phonenumbers.region_code_for_number(parsed) or "Unknown"
    area = geocoder.description_for_number(parsed, "en") or "Unknown"
    net_carrier = carrier.name_for_number(parsed, "en") or "Unknown"
    valid = phonenumbers.is_valid_number(parsed)

    payload = {
        "status": STATUS_OK,
        "valid": valid,
        "search_keys": {"e164": e164_key, "msisdn": msisdn_key},
        "metadata": {"country": country, "area": area, "carrier": net_carrier},
        "findings": [],
        "summary": f"{e164_key} — {country} ({net_carrier})",
        "elapsed_ms": elapsed_ms(start),
        "query": query,
    }

    # --- Optional live enrichment (Veriphone) — failures are contained ---
    live_block = _live_payload(e164_key, live=live, api_key=VERIPHONE_API_KEY, timeout=timeout)
    if live_block:
        payload["live"] = live_block
        if "error" in live_block:
            payload["findings"].append(f"Live lookup failed: {live_block['error']}")
        else:
            live_carrier = live_block.get("carrier")
            if net_carrier == "Unknown" and live_carrier and live_carrier != "Unknown":
                payload["metadata"]["carrier"] = live_carrier
                payload["findings"].append(
                    f"Carrier resolved via Veriphone live lookup: {live_carrier}"
                )
            if live_block.get("phone_type") and live_block["phone_type"] != "Unknown":
                payload["findings"].append(f"Line type: {live_block['phone_type']}")
        payload["elapsed_ms"] = elapsed_ms(start)

    return payload


# ---------------------------------------------------------------------------
# Human-readable renderer
# ---------------------------------------------------------------------------


def render(payload: dict) -> str:
    """Render a run() payload as a readable report (default CLI output)."""
    if payload.get("status") == STATUS_ERROR:
        q = payload.get("query", {})
        head = f"Phone Validator: {q.get('input') or ''}".strip()
        return f"{head or 'Phone Validator'} failed\n  Error: {payload.get('error') or 'unknown error'}"
    lines = [f"Phone Validator: {payload['search_keys']['e164']}"]
    lines.append(f"  Status    : {payload.get('status')} ({payload.get('elapsed_ms', '?')} ms)")
    lines.append(f"  Valid     : {payload.get('valid')}")
    lines.append(f"  E164      : {payload['search_keys']['e164']}")
    lines.append(f"  MSISDN    : {payload['search_keys']['msisdn']}")
    lines.append(f"  Country   : {payload['metadata']['country']}")
    lines.append(f"  Area      : {payload['metadata']['area']}")
    lines.append(f"  Carrier   : {payload['metadata']['carrier']}")
    live_block = payload.get("live") or {}
    if live_block:
        if "error" in live_block:
            lines.append(f"  Live      : failed — {live_block['error']}")
        else:
            lines.append(
                f"  Live      : {live_block.get('provider')} — type {live_block.get('phone_type')},"
                f" carrier {live_block.get('carrier')}"
            )
            if live_block.get("international"):
                lines.append(f"  Intl fmt  : {live_block['international']}")
            if live_block.get("local"):
                lines.append(f"  Local fmt : {live_block['local']}")
    for note in payload.get("findings") or []:
        lines.append(f"  Note      : {note}")
    lines.append(f"  Summary   : {payload.get('summary')}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI: python -m modules.identity.phone_validator [--json] <phone>
# ---------------------------------------------------------------------------


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    want_json = False
    default_region = "IT"
    timeout = 10.0
    live: bool | None = False  # default offline: only --live spends Veriphone credits
    positional: list[str] = []
    usage = usage_line("modules.identity.phone_validator", "[--json] <phone> [--region CC] [--timeout SEC] [--live|--no-live]")
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in ("-h", "--help"):
            print(usage)
            return 0
        if arg in ("--json", "-j"):
            want_json = True
        elif arg == "--region":
            if i + 1 >= len(argv):
                print("--region requires a country code (e.g. IT, US)", file=sys.stderr)
                return 2
            default_region = argv[i + 1].strip().upper()
            i += 1
        elif arg == "--timeout":
            if i + 1 >= len(argv):
                print("--timeout requires a number of seconds", file=sys.stderr)
                return 2
            try:
                timeout = float(argv[i + 1])  # type: ignore
            except ValueError:
                print(f"Invalid --timeout '{argv[i + 1]}'", file=sys.stderr)
                return 2
            i += 1
        elif arg == "--live":
            live = True
        elif arg == "--no-live":
            live = False
        elif arg.startswith("-"):
            print(f"Unknown option: {arg}", file=sys.stderr)
            print(usage, file=sys.stderr)
            return 2
        else:
            positional.append(arg)
        i += 1

    if not positional:
        print(usage, file=sys.stderr)
        return 1
    if len(positional) > 1:
        print("One phone number at a time.", file=sys.stderr)
        print(usage, file=sys.stderr)
        return 2

    payload = run(positional[0], default_region=default_region, live=live, timeout=int(timeout))
    if want_json:
        print(json.dumps(payload, indent=2))
    else:
        print(render(payload))
    return 0 if payload.get("status") != STATUS_ERROR else 1


if __name__ == "__main__":
    sys.exit(main())
