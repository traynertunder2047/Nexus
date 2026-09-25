"""WHOIS Lookup - modules/network/whois_lookup.py
=================================================
Retrieves domain registration and administrative metadata (registrar,
registrant/admin contacts, registration/expiry dates, nameservers, EPP
status codes, DNSSEC) through WHOIS/RDAP, using the `whoisdomain` library.

Retrieval design
----------------
The module never speaks WHOIS/RDAP itself: every live query funnels through
a single seam `_lookup()` (a thin wrapper over whoisdomain.query) so all
downstream logic is unit-testable offline by monkeypatching that seam.

  * Protocol selection is delegated to the library: RDAP over HTTPS when the
    TLD supports it, classic WHOIS (port 43, with registrar referral
    chaining) otherwise.  The payload's ``query.method`` is therefore
    reported as "auto" - the library decides per-TLD.
  * Contacts (registrant/admin/abuse) are redaction-aware: GDPR and privacy
    services mean most registrations return ""/"REDACTED FOR PRIVACY"/proxy
    addresses.  The payload never fabricates data - unpopulated or proxy
    contacts are collapsed to the literal string "redacted".
  * Registration-age and expiry-proximity analysis is derived in pure
    functions so it is fully testable offline.
  * Typed library errors (UnknownTldError, WhoisCommandTimeoutError,
    WhoisQuotaExceededError, ...) map to graceful {"status": "error"}
    payloads - never exceptions to the caller.

Output shape (Option A - semantic groups)
-----------------------------------------
The JSON payload is organized by meaning, not by source field:
  domain -> status -> query -> registrar -> contacts -> timeline
         -> name_servers -> security -> findings -> summary

  * ``timeline`` merges the raw dates (created/updated/expires) with the
    derived analysis (age_days, recently_registered, days_to_expiry,
    expiring_soon, expired) so the analyst never cross-references two
    blocks to answer "when was this registered, and is that a flag?"
  * ``findings`` is the human-actionable list (redaction notes, age/expiry
    red flags, notable EPP states); ``summary`` is the one-line recap.
  * Operational status lives at the top of the payload, not buried in a
    section.

CLI (Option C - human first)
----------------------------
The default CLI prints a readable two-column report; ``--json`` dumps the
full machine payload.

Honest limits
-------------
  * Administrative identity data is routinely withheld by registrars;
    absence is reported as "redacted", not treated as "no data".
  * WHOIS servers are rate-limited and occasionally unstable; a failed
    query reports the reason instead of crashing.
  * Only the registered domain itself is queried - no subdomain/registrar
    reconnaissance, no bulk scanning.

Run from the repo root:
  .\\.venv\\Scripts\\python.exe -m modules.network.whois_lookup example.com
  .\\.venv\\Scripts\\python.exe -m modules.network.whois_lookup --json example.com
"""

import json, logging, re, sys
from datetime import datetime, timezone
from time import monotonic

import whoisdomain
import whoisdomain.exceptions as _whois_exc  # base error class lives here

# whoisdomain logs a bare DataResponse repr at WARNING level whenever an
# RDAP answer fails (before falling back to WHOIS).  With no logging
# handlers configured, Python's logging 'lastResort' handler echoes that
# repr to stderr - pure library noise.  A NullHandler consumes it at the
# source without disabling real handlers an embedding app may add later.
logging.getLogger("whoisdomain").addHandler(logging.NullHandler())

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Strings that indicate a contact/field is withheld by the registrar or a
# privacy/proxy service.  Case-insensitive substring match.
REDACTION_MARKERS = [
    "redact", "privacy", "proxy", "whoisguard", "whois protect",
    "not disclosed", "data protected", "onsite", "contact privacy",
    "registrant of the domain", "see privacy", "gdpr", "limited by",
]

# Registration younger than this many days is flagged as "recent".
RECENT_DAYS = 365
# Expiry within this many days is flagged as "expiring soon".
EXPIRY_WINDOW_DAYS = 90

_EPP_STATUSES_IGNORED = {"client delete prohibited", "client transfer prohibited",
                         "client update prohibited", "server delete prohibited",
                         "server transfer prohibited", "server update prohibited"}


def _now_utc():
    return datetime.now(timezone.utc)


def _coerce_dt(value):
    """Return a datetime (naive -> assumed UTC) or None."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    if isinstance(value, str) and value.strip():
        try:
            return datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def _first(value):
    """First element of lists/tuples, else the scalar itself (""/None passthrough)."""
    if isinstance(value, (list, tuple, set)):
        return value[0] if value else ""
    return value if value is not None else ""


def _is_redacted(value):
    """True when a contact field is missing, withheld or a privacy proxy."""
    text = str(value or "").lower()
    return (not text) or any(marker in text for marker in REDACTION_MARKERS)


# ---------------------------------------------------------------------------
# Lookup seam (tests monkeypatch this)
# ---------------------------------------------------------------------------

def _lookup(domain, timeout=15.0, ignore_returncode=True, **pc_kwargs):
    """Query whoisdomain for `domain`; returns its Domain object or None.

    This is the ONLY place whoisdomain is touched.  A ParameterContext
    controls the library's politeness/timeout behaviour.
    """
    pc = whoisdomain.ParameterContext(timeout=timeout,
                                      ignore_returncode=ignore_returncode,
                                      **pc_kwargs)
    return whoisdomain.query(domain, pc=pc)


def _name_servers(domain):
    """Nameservers from a Domain object -> sorted list of hostnames."""
    ns = domain.name_servers or []
    if isinstance(ns, str):
        ns = [ns]
    return sorted({str(n).strip().lower().rstrip(".") for n in ns if str(n).strip()})


def _statuses(domain):
    """EPP status codes from a Domain object -> sorted list."""
    raw = domain.statuses or domain.status or ""
    if isinstance(raw, str):
        raw = [s for s in (part.strip() for part in raw.splitlines()) if s]
    out = set()
    for item in raw or []:
        text = str(item).strip()
        if text:
            out.add(text.lower())
    return sorted(out)


def _epp_flag(statuses):
    """Notable EPP states (client/server hold, redemption, transfer pending,
    pending delete, expired, autoRenewPeriod) that analysts care about; the
    routine client/server transfer-prohibited codes are filtered as noise."""
    interesting = []
    for s in statuses:
        if s in _EPP_STATUSES_IGNORED:
            continue
        if any(word in s for word in ("hold", "redemption", "pending", "delete",
                                      "expired", "autorenewperiod", "inactive")):
            interesting.append(s)
    return interesting


# ---------------------------------------------------------------------------
# 1. Registration / administrative metadata mapping
# ---------------------------------------------------------------------------

def _contact_flat(value):
    """Collapse a contact field to a single string: the value itself, or the
    literal "redacted" when withheld/empty/privacy-proxied."""
    if _is_redacted(value):
        return "redacted"
    return str(value).strip()


def map_registration(domain_obj) -> dict:
    """Normalize a whoisdomain Domain into the semantic groups.

    Returns the sections that do not depend on "now":
    registrar / contacts (+ registrant_country) / dates (raw) /
    name_servers / security.
    """
    created = _coerce_dt(_first(getattr(domain_obj, "creation_date", "")))
    updated = _coerce_dt(_first(getattr(domain_obj, "updated_date", "")))
    expires = _coerce_dt(_first(getattr(domain_obj, "expiration_date", "")))

    registrar = str(getattr(domain_obj, "registrar", "") or "").strip()
    registrar_url = str(getattr(domain_obj, "registrar_url", "") or "").strip()
    emails = getattr(domain_obj, "emails", None) or []
    if isinstance(emails, str):
        emails = [emails]
    emails = sorted({str(e).strip().lower() for e in emails if str(e).strip()})

    statuses = _statuses(domain_obj)
    dnssec = getattr(domain_obj, "dnssec", None)
    dnssec = (bool(dnssec) if dnssec is not None else None)  # ""/False -> False

    return {
        "registrar": {
            "name": registrar or None,
            "url": registrar_url or None,
        },
        "contacts": {
            "registrant": _contact_flat(_first(getattr(domain_obj, "registrant", ""))),
            "admin": _contact_flat(_first(getattr(domain_obj, "admin", ""))),
            "abuse": _contact_flat(_first(getattr(domain_obj, "abuse_contact", ""))),
            "emails": emails,
            "registrant_country":
                str(getattr(domain_obj, "registrant_country", "") or "").strip()
                or None,
        },
        "dates": {
            "created": created.isoformat() if created else None,
            "updated": updated.isoformat() if updated else None,
            "expires": expires.isoformat() if expires else None,
        },
        "name_servers": _name_servers(domain_obj),
        "security": {
            "dnssec": dnssec,
            "statuses": statuses,
        },
    }


# ---------------------------------------------------------------------------
# 2. Registration-age / expiry analysis (pure functions)
# ---------------------------------------------------------------------------

def registration_age_days(created, now=None):
    """Days since creation (0 if created in the future), else None."""
    created = _coerce_dt(created)
    if created is None:
        return None
    now = now or _now_utc()
    return max(0, (now - created).days)


def days_to_expiry(expires, now=None):
    """Days until expiry; negative when already expired; None when missing."""
    expires = _coerce_dt(expires)
    if expires is None:
        return None
    now = now or _now_utc()
    return (expires - now).days


def analyze_registration(domain_obj, now=None) -> dict:
    """Derive age/expiry signals from a Domain object.

    Returns the timeline-merge fields plus a human notes list:
    age_days, recently_registered, days_to_expiry, expiring_soon, expired, notes.
    """
    now = now or _now_utc()
    created = _coerce_dt(_first(getattr(domain_obj, "creation_date", "")))
    expires = _coerce_dt(_first(getattr(domain_obj, "expiration_date", "")))

    age_days = registration_age_days(created, now)
    exp_days = days_to_expiry(expires, now)

    notes = []
    if age_days is not None and age_days < RECENT_DAYS:
        notes.append(f"Recently registered ({age_days} days ago) - verify legitimacy")
    if exp_days is not None:
        if exp_days < 0:
            notes.append(f"Domain EXPIRED {-exp_days} days ago")
        elif exp_days <= EXPIRY_WINDOW_DAYS:
            notes.append(f"Expires within {exp_days} days - possible takeover window")
    if not notes:
        notes.append("No registration-age/expiry red flags")

    return {
        "age_days": age_days,
        "recently_registered": age_days is not None and age_days < RECENT_DAYS,
        "days_to_expiry": exp_days,
        "expiring_soon": exp_days is not None and 0 <= exp_days <= EXPIRY_WINDOW_DAYS,
        "expired": exp_days is not None and exp_days < 0,
        "notes": notes,
    }


def build_findings(mapped: dict, analysis: dict) -> list:
    """Assemble the human-actionable findings list from the mapped groups."""
    findings = []
    contacts = mapped["contacts"]

    role_label = {"registrant": "registrant", "admin": "administrative",
                  "abuse": "abuse"}
    redacted_roles = []
    for role in ("registrant", "admin"):
        if contacts.get(role) == "redacted":
            redacted_roles.append(role_label[role])
    if redacted_roles:
        findings.append(
            f"{len(redacted_roles)}/2 identity contact(s) redacted "
            f"({', '.join(redacted_roles)}) - GDPR/privacy withholding"
        )

    epp = _epp_flag(mapped["security"]["statuses"])
    for state in epp:
        findings.append(f"Notable EPP state: {state}")

    findings.extend(analysis["notes"])

    # dnssec / expiry interplay worth calling out
    sec = mapped["security"]
    if sec.get("dnssec") is False and analysis.get("age_days") is not None \
            and analysis["age_days"] > RECENT_DAYS:
        findings.append("DNSSEC not enabled on an established domain")
    return findings


# ---------------------------------------------------------------------------
# Orchestration: run()
# ---------------------------------------------------------------------------

def run(domain, timeout=15.0, ignore_returncode=True, **pc_kwargs) -> dict:
    """Full WHOIS/RDAP lookup for a domain; returns the JSON payload."""
    domain = (domain or "").strip().lower().rstrip(".")
    if not domain:
        return {"status": "error", "error": "No domain provided."}
    if not re.fullmatch(r"(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+"
                        r"[a-z]{2,63}", domain):
        return {"status": "error",
                "error": f"'{domain}' is not a valid domain name."}

    start = monotonic()
    try:
        domain_obj = _lookup(domain, timeout=timeout,
                             ignore_returncode=ignore_returncode, **pc_kwargs)
    except whoisdomain.UnknownTldError as e:
        return {"status": "error", "domain": domain,
                "error": f"Unsupported TLD: {e}"}
    except whoisdomain.WhoisCommandTimeoutError as e:
        return {"status": "error", "domain": domain,
                "error": f"WHOIS/RDAP server timed out: {e}"}
    except whoisdomain.WhoisQuotaExceededError as e:
        return {"status": "error", "domain": domain,
                "error": f"WHOIS rate limit / quota exceeded: {e}"}
    except whoisdomain.WhoisPrivateRegistryError as e:
        return {"status": "error", "domain": domain,
                "error": f"Private registry refused lookup: {e}"}
    except whoisdomain.FailedParsingWhoisOutputError as e:
        return {"status": "error", "domain": domain,
                "error": f"WHOIS response could not be parsed: {e}"}
    except whoisdomain.WhoisCommandFailedError as e:
        return {"status": "error", "domain": domain,
                "error": f"WHOIS command failed: {e}"}
    except _whois_exc.WhoisExceptionError as e:  # library base error
        return {"status": "error", "domain": domain,
                "error": f"WHOIS error: {e}"}
    elapsed_ms = round((monotonic() - start) * 1000)

    if domain_obj is None:
        return {"status": "no_data", "domain": domain, "elapsed_ms": elapsed_ms,
                "error": "No WHOIS/RDAP record returned for this domain."}

    mapped = map_registration(domain_obj)
    analysis = analyze_registration(domain_obj)

    # TLD: prefer the library's own parse, fall back to the last label
    tld = str(getattr(domain_obj, "tld", "") or "").strip()         or (domain.rpartition(".")[2] if "." in domain else None)

    # timeline = raw dates + derived analysis merged into one block
    timeline = dict(mapped["dates"])
    for key in ("age_days", "recently_registered", "days_to_expiry",
                "expiring_soon", "expired"):
        timeline[key] = analysis[key]

    findings = build_findings(mapped, analysis)
    reg = mapped["registrar"]["name"] or "unknown registrar"
    created = timeline["created"]
    expires = timeline["expires"]
    age = timeline["age_days"]
    exp_days = timeline["days_to_expiry"]

    first = f"{domain}: registered under {reg}"
    if created:
        first += f" on {created[:10]}"
        if age is not None:
            first += f" ({age:,} days ago)"
    else:
        first += " (creation date not published)"
    summary_parts = [first]
    if expires:
        if exp_days is None:
            summary_parts.append(f"expires {expires[:10]}")
        elif exp_days < 0:
            summary_parts.append(f"expired {-exp_days:,} days ago")
        elif exp_days == 0:
            summary_parts.append("expires today")
        else:
            summary_parts.append(f"expires {expires[:10]} (in {exp_days:,} days)")
    ns_txt = ", ".join(mapped["name_servers"])
    summary_parts.append(f"{len(mapped['name_servers'])} name server(s): {ns_txt}" if ns_txt else "no name servers published")
    summary_parts.append(f"dnssec {'enabled' if mapped['security']['dnssec'] else 'disabled'}")

    return {
        "domain": domain,
        "tld": tld,
        "status": "ok",
        "query": {"method": "auto", "elapsed_ms": elapsed_ms},
        "registrar": mapped["registrar"],
        "contacts": mapped["contacts"],
        "timeline": timeline,
        "name_servers": mapped["name_servers"],
        "security": mapped["security"],
        "findings": findings,
        "summary": "; ".join(summary_parts) + ".",
    }


# ---------------------------------------------------------------------------
# 3. Human-readable renderer (Option C)
# ---------------------------------------------------------------------------

def _fmt_date(iso):
    return iso[:10] if iso else None


def render(payload: dict) -> str:
    """Render a run() payload as a readable two-column report."""
    if payload.get("status") == "ok":
        domain = payload["domain"]
        rows = []

        status_txt = f"ok   (via auto RDAP/WHOIS, {payload['query']['elapsed_ms']} ms)"
        rows.append(("Status", status_txt))

        reg = payload["registrar"]
        reg_txt = reg.get("name") or "unknown registrar"
        if reg.get("url"):
            reg_txt = f"{reg_txt} ({reg['url']})"
        rows.append(("Registrar", reg_txt))
        rows.append(("TLD", payload.get("tld") or "(unknown)"))

        tl = payload["timeline"]
        created = _fmt_date(tl.get("created"))
        if created:
            age = tl.get("age_days")
            created_txt = created + (f"  ({age:,} days ago)" if age is not None else "")
            rows.append(("Registered", created_txt))
        updated = _fmt_date(tl.get("updated"))
        if updated:
            rows.append(("Updated", updated))
        expires = _fmt_date(tl.get("expires"))
        if expires is not None:
            exp_days = tl.get("days_to_expiry")
            if exp_days is None:
                exp_txt = expires
            elif exp_days < 0:
                exp_txt = f"{expires}  (EXPIRED {-exp_days:,} days ago)"
            elif exp_days == 0:
                exp_txt = f"{expires}  (expires today)"
            else:
                exp_txt = f"{expires}  (in {exp_days:,} days)"
            rows.append(("Expires", exp_txt))

        ns = payload.get("name_servers") or []
        rows.append(("Name servers", ", ".join(ns) if ns else "(none)"))

        sec = payload.get("security") or {}
        dnssec = sec.get("dnssec")
        rows.append(("DNSSEC", "enabled" if dnssec else "disabled"))

        contacts = payload.get("contacts") or {}
        contact_parts = []
        for role in ("registrant", "admin", "abuse"):
            val = contacts.get(role)
            contact_parts.append(f"{role}: {val if val else 'not published'}")
        rows.append(("Contacts", "  |  ".join(contact_parts)))
        country = contacts.get("registrant_country")
        if country:
            rows.append(("Registrant country", country))
        emails = contacts.get("emails") or []
        if emails:
            rows.append(("Emails", ", ".join(emails)))

        width = max(len(k) for k, _ in rows)
        # label column + separators:  "  " + label padded + "  : "
        value_col = 2 + width + 4
        lines = [f"WHOIS Lookup: {domain}"]
        for label, value in rows:
            lines.append(f"  {label:<{width}}  : {value}")

        findings = payload.get("findings") or []
        if findings:
            lines.append(f"  {'Findings':<{width}}  :")
            for f in findings:
                lines.append(" " * value_col + f"- {f}")
        else:
            lines.append(f"  {'Findings':<{width}}  : none")
        return "\n".join(lines)

    if payload.get("status") == "error":
        domain = payload.get("domain")
        head = f"WHOIS Lookup: {domain}" if domain else "WHOIS Lookup"
        return f"{head} failed\n  Error: {payload.get('error') or 'unknown error'}"
    # no_data
    return (f"WHOIS Lookup: {payload.get('domain')} returned no data\n"
            f"  {payload.get('error') or 'no WHOIS/RDAP record'}")


# ---------------------------------------------------------------------------
# CLI: python -m modules.network.whois_lookup [--json] example.com
# ---------------------------------------------------------------------------

def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    want_json = False
    args = []
    for a in argv:
        if a in ("-h", "--help"):
            print(__doc__.split("Run from the repo root:")[0])
            print("Usage: python -m modules.network.whois_lookup [--json] <domain>")
            return 0
        if a in ("--json", "-j"):
            want_json = True
        elif a.startswith("-"):
            print(f"Unknown option: {a}", file=sys.stderr)
            print("Usage: python -m modules.network.whois_lookup [--json] <domain>")
            return 2
        else:
            args.append(a)

    if not args:
        print("Usage: python -m modules.network.whois_lookup [--json] <domain>")
        return 1

    payload = run(args[0])
    if want_json:
        print(json.dumps(payload, indent=2, default=str))
    else:
        print(render(payload))
    return 0 if payload.get("status") == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
