from __future__ import annotations

import json
import sys
import time

from ..usage import usage_line
from .helpers import STATUS_ERROR, STATUS_OK, elapsed_ms
from . import password_checker, strong_password

USER_AGENT = "Nexus/1.0"

__all__ = ["run", "render", "main", "assess_password"]


def assess_password(
    password: str,
    *,
    timeout: int = 10,
    check_breaches: bool = True,
) -> dict:
    """Back-compat alias for run() — the name used in the original P2.3 plan."""
    return run(password, timeout=timeout, check_breaches=check_breaches)


def _verdict(strength: dict, breach: dict | None) -> str:
    """Decision matrix: exposure always wins over strength."""
    if breach is not None and breach.get("exposed"):
        return "compromised"
    score = strength.get("score", 0)
    if score < 40:
        return "weak"
    if score < 60:
        return "fair"
    return "strong"


def run(
    password: str,
    *,
    timeout: int = 10,
    check_breaches: bool = True,
) -> dict:
    """
    Assess `password` for strength (local) and breach exposure (network).

    check_breaches=False skips the network stage entirely (offline mode).
    Never raises; the password is never included in any returned data.
    """
    start = time.monotonic()
    query = {"provider": "local+xposedornot"}

    if not isinstance(password, str) or not password:
        msg = "Password must be a non-empty string."
        return {
            "status": STATUS_ERROR,
            "error": msg,
            "findings": [],
            "summary": msg,
            "elapsed_ms": elapsed_ms(start),
            "query": query,
        }

    # --- Stage 1: local strength (offline, always runs) ---
    strength = strong_password.run(password)
    if "error" in strength:
        msg = strength["error"]
        return {
            "status": STATUS_ERROR,
            "error": msg,
            "findings": [],
            "summary": msg,
            "elapsed_ms": elapsed_ms(start),
            "query": query,
        }

    findings: list[str] = list(strength.get("issues") or [])

    # --- Stage 2: breach exposure (network, containable) ---
    breach: dict | None = None
    if check_breaches:
        breach = password_checker.run(password, timeout=timeout)
        if breach.get("status") == STATUS_ERROR:
            # Contained: strength verdict stands, failure is reported
            findings.append(f"Breach check unavailable: {breach.get('error')}")
        elif breach.get("exposed"):
            findings.append(
                f"Exposed in {breach.get('count')} known breach(es) — do NOT reuse this password."
            )
            if breach.get("wordlist"):
                findings.append("Password appears in known wordlists.")
        else:
            findings.append("Not found in known breach databases.")

    verdict = _verdict(strength, breach)

    if breach is not None and breach.get("exposed"):
        summary = (
            f"COMPROMISED — found in {breach.get('count')} breach(es); "
            f"strength was {strength.get('label')} ({strength.get('score')}/100)."
        )
    elif breach is None:
        summary = f"{strength.get('label')} ({strength.get('score')}/100) — breach check skipped."
    elif breach.get("status") == STATUS_ERROR:
        summary = (
            f"{strength.get('label')} ({strength.get('score')}/100) — "
            f"breach check could not complete."
        )
    else:
        summary = (
            f"{strength.get('label')} ({strength.get('score')}/100) and "
            f"not found in known breaches."
        )

    payload: dict = {
        "status": STATUS_OK,
        "verdict": verdict,
        "strength": strength,
        "breach": breach,
        "findings": findings,
        "summary": summary,
        "elapsed_ms": elapsed_ms(start),
        "query": query,
    }
    return payload


# ---------------------------------------------------------------------------
# Human-readable renderer
# ---------------------------------------------------------------------------


def render(payload: dict) -> str:
    """Render a run() payload as a readable report (default CLI output)."""
    if payload.get("status") == STATUS_ERROR:
        return f"Password Assessor failed\n  Error: {payload.get('error') or 'unknown error'}"

    verdict = payload.get("verdict", "?")
    lines = [f"Password Assessor: verdict {verdict.upper()}"]
    lines.append(f"  Status    : {payload.get('status')} ({payload.get('elapsed_ms', '?')} ms)")

    strength = payload.get("strength") or {}
    lines.append(
        f"  Strength  : {strength.get('label')} ({strength.get('score')}/100),"
        f" ~{strength.get('entropy_bits')} bits entropy, len {strength.get('length')}"
    )

    breach = payload.get("breach")
    if breach is None:
        lines.append("  Breach    : skipped (--skip-breach)")
    elif breach.get("status") == STATUS_ERROR:
        lines.append(f"  Breach    : failed — {breach.get('error')}")
    else:
        lines.append(
            f"  Breach    : exposed={breach.get('exposed')} count={breach.get('count')}"
            f" wordlist={breach.get('wordlist')}"
        )

    for issue in payload.get("findings") or []:
        lines.append(f"  Note      : {issue}")
    lines.append(f"  Summary   : {payload.get('summary')}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI: python -m modules.identity.password_assessor [--json] [password]
# ---------------------------------------------------------------------------


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    want_json = False
    check_breaches = True
    timeout = 10.0
    positional: list[str] = []
    usage = (
        usage_line("modules.identity.password_assessor", "[--json] [password] [--skip-breach] [--timeout SEC]")
        + "\n"
        "Pass no password to get a masked prompt (recommended: keeps the password\n"
        "out of shell history and process lists)."
    )
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in ("-h", "--help"):
            print(usage)
            return 0
        if arg in ("--json", "-j"):
            want_json = True
        elif arg == "--skip-breach":
            check_breaches = False
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
        elif arg.startswith("-"):
            print(f"Unknown option: {arg}", file=sys.stderr)
            print(usage, file=sys.stderr)
            return 2
        else:
            positional.append(arg)
        i += 1

    if len(positional) > 1:
        print("One password at a time.", file=sys.stderr)
        print(usage, file=sys.stderr)
        return 2

    if positional:
        password = positional[0]
    else:
        # Masked, key-by-key prompt — password never appears on screen or in history
        try:
            password = strong_password._masked_input(
                "Password (masked; strength + breach check): "
            )
        except (KeyboardInterrupt, EOFError):
            print(file=sys.stderr)
            return 1
        if not password:
            print("No password provided.", file=sys.stderr)
            return 1

    payload = run(password, timeout=int(timeout), check_breaches=check_breaches)
    if want_json:
        print(json.dumps(payload, indent=2))
    else:
        print(render(payload))
    return 0 if payload.get("status") != STATUS_ERROR else 1


if __name__ == "__main__":
    sys.exit(main())
