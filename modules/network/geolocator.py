"""Geolocator - modules/network/geolocator.py
=================================================
IP address geolocation + network profiling via the ip-api.com service:

  1) Lookup          - resolves an IPv4/IPv6 address to a geographic and
                       network profile (country, region, city, coordinates,
                       timezone, ISP, organization, ASN, reverse-DNS name)
  2) Derived signals - provider flags (mobile / proxy / hosting) are
                       surfaced as findings
  3) Verdict         - top-level status + one-line summary, same payload
                       contract as the sibling network modules

Design notes
------------
* Every live request funnels through the _lookup seam so the whole module
  is testable fully offline by monkeypatching it.
* Transport: the free ip-api tier is HTTP-only. The endpoint defaults to
  http://ip-api.com/json/ and can be overridden with the IP_API_URL environment variable
  (e.g. to point at a paid HTTPS endpoint when your plan supports it).
* run() never prompts: the CLI requires the address as an argument, and the
  function takes it as a parameter (the old interactive input() is gone).

Run from the repo root:
  ./.venv/Scripts/python.exe -m modules.network.geolocator 8.8.8.8
  ./.venv/Scripts/python.exe -m modules.network.geolocator 8.8.8.8 --json
"""

import ipaddress, os, json, re, sys
from time import monotonic

import requests

# Load .env if present so IP_API_URL / keys work without manual export.
# Mirrors the behaviour of the identity/metadata modules.
try:
    from dotenv import load_dotenv  # type: ignore
    load_dotenv()
except Exception:
    pass

USER_AGENT = ("Mozilla/5.0 (compatible; OSINTNexusBot/1.0; "
              "+https://example.invalid)")


# ---------------------------------------------------------------------------
# Endpoint + lookup seam
# ---------------------------------------------------------------------------

def _endpoint():
    """Resolve the ip-api endpoint (env override wins over the default)."""
    url = os.environ.get("IP_API_URL", "http://ip-api.com/json/")
    # Free ip-api.com tier is HTTP-only – https://ip-api.com/json/ always
    # returns 403. Auto-correct the common misconfiguration so a stale .env
    # or shell export doesn't break every lookup. Paid plans use a different
    # host (e.g. https://pro.ip-api.com/…) and are left untouched.
    if url.startswith("https://ip-api.com/"):
        url = "http://" + url[len("https://"):]
    return url


def _lookup(ip, timeout=10.0):
    """Query ip-api for one address; returns the parsed JSON dict.

    Raises requests.RequestException on transport / HTTP failure.
    """
    url = _endpoint().rstrip("/") + "/" + ip
    resp = requests.get(url, timeout=timeout,
                        headers={"User-Agent": USER_AGENT})
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_ip(ip):
    """Return an error message when ip is not a valid IPv4/IPv6 address."""
    if not ip:
        return "No IP address provided."
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return f"'{ip}' is not a valid IPv4/IPv6 address"
    return None

# ---------------------------------------------------------------------------
# Mapping + findings
# ---------------------------------------------------------------------------

def _split_as(as_str):
    """Split ip-api's 'AS15169 Google LLC' into (ASN, org name)."""
    if not as_str:
        return None, None
    text = str(as_str).strip()
    m = re.match(r"AS[0-9]+", text)
    asn = m.group(0) if m else None
    name = text[m.end():].strip() if m else text
    return asn, name or None


def _parse(data):
    """Map an ip-api response dict into geo/network groups."""
    geo = {"country": data.get("country"),
           "country_code": data.get("countryCode"),
           "region": data.get("region"),
           "region_name": data.get("regionName"),
           "city": data.get("city"),
           "zip": data.get("zip"),
           "latitude": data.get("lat"),
           "longitude": data.get("lon"),
           "timezone": data.get("timezone")}
    asn, parsed_name = _split_as(data.get("as"))
    network = {"isp": data.get("isp"),
               "org": data.get("org"),
               "asn": asn,
               "as_name": data.get("asname") or parsed_name,
               "reverse_dns": data.get("reverse"),
               "mobile": bool(data.get("mobile")),
               "proxy": bool(data.get("proxy")),
               "hosting": bool(data.get("hosting"))}
    return geo, network


def _build_findings(network):
    """Aggregate actionable notes from the provider's flag fields."""
    findings = []
    if network["proxy"]:
        findings.append("Address is flagged as a proxy / VPN exit point")
    if network["hosting"]:
        findings.append("Address belongs to a hosting / cloud provider range")
    if network["mobile"]:
        findings.append("Address is on a mobile / cellular network")
    return findings


# ---------------------------------------------------------------------------
# Orchestration: run()
# ---------------------------------------------------------------------------

def run(ip, timeout=10.0):
    """Geolocate one IP address; returns the JSON payload.

    Payload shape mirrors the sibling modules:
      ip -> status -> elapsed_ms -> lookup -> geo -> network -> findings
      -> summary
    """
    ip = (ip or "").strip()
    err = validate_ip(ip)
    if err:
        return {"status": "error", "error": err}
    start = monotonic()
    try:
        data = _lookup(ip, timeout)
    except requests.RequestException as e:
        msg = f"Lookup failed: {e}"
        # Make the free-tier HTTPS mistake obvious instead of a raw 403.
        if "403" in str(e):
            raw = os.environ.get("IP_API_URL", "")
            if raw.startswith("https://ip-api.com/"):
                msg += " — free ip-api.com tier is HTTP-only; " \
                       "set IP_API_URL=http://ip-api.com/json/ " \
                       "(or use your paid https://pro.ip-api.com/… endpoint)"
            else:
                msg += " (hint: free ip-api tier requires http://ip-api.com/json/)"
        return {"status": "error", "error": msg}
    if data.get("status") != "success":
        return {"status": "error",
                "error": data.get("message") or "Lookup returned no data"}
    geo, network = _parse(data)
    findings = _build_findings(network)
    elapsed_ms = round((monotonic() - start) * 1000)
    place = ", ".join(x for x in (geo["city"] or "", geo["region_name"] or "")
                      if x)
    summary = f"{ip}: {place + ', ' if place else ''}{geo['country']}"
    if geo["latitude"] is not None:
        summary += f" ({geo['latitude']}, {geo['longitude']})"
    if network["isp"]:
        summary += f"; ISP: {network['isp']}"
    return {
        "ip": ip,
        "status": "ok",
        "elapsed_ms": elapsed_ms,
        "lookup": {"endpoint": _endpoint(), "provider": "ip-api"},
        "geo": geo,
        "network": network,
        "findings": findings,
        "summary": summary,
    }

# ---------------------------------------------------------------------------
# Human-readable renderer (same presentation layer as the siblings)
# ---------------------------------------------------------------------------

def render(payload):
    """Render a run() payload as a readable report (default CLI output)."""
    if payload.get("status") == "error":
        head = (f"Geolocator: {payload.get('ip')}"
                if payload.get("ip") else "Geolocator")
        return (f"{head} failed" + chr(10) +
                f"  Error: {payload.get('error') or 'unknown error'}")

    g = payload["geo"]
    n = payload["network"]
    rows = [("Status", payload["status"]),
            ("Elapsed", f"{payload['elapsed_ms']} ms"),
            ("Country", g.get("country") or "(none)"),
            ("Region", g.get("region_name") or g.get("region") or "(none)"),
            ("City", g.get("city") or "(none)")]
    if g.get("zip"):
        rows.append(("Postal code", g["zip"]))
    lat, lon = g.get("latitude"), g.get("longitude")
    rows.append(("Coordinates",
                 f"{lat}, {lon}" if lat is not None else "(none)"))
    rows.append(("Timezone", g.get("timezone") or "(none)"))
    rows.append(("ISP", n.get("isp") or "(none)"))
    rows.append(("Organization", n.get("org") or "(none)"))
    rows.append(("ASN", n.get("asn") or "(none)"))
    if n.get("reverse_dns"):
        rows.append(("Reverse DNS", n["reverse_dns"]))
    flags = ", ".join(x for x in ("proxy", "hosting", "mobile") if n.get(x))
    rows.append(("Flags", flags if flags else "none flagged"))

    lines = [f"Geolocator: {payload['ip']}"]
    width = max(len(k) for k, _ in rows)
    for label, value in rows:
        lines.append(f"  {label:<{width}}  : {value}")

    findings = payload.get("findings") or []
    lines.append("")
    lines.append("  Findings")
    if findings:
        for f in findings:
            lines.append(f"    - {f}")
    else:
        lines.append("    - none")
    return chr(10).join(lines)


# ---------------------------------------------------------------------------
# CLI: python -m modules.network.geolocator [--json] <ip> [...]
# ---------------------------------------------------------------------------

def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    want_json = False
    timeout = 10.0
    positional = []
    usage = ("Usage: python -m modules.network.geolocator [--json] <ip> "
             "[--timeout SEC]")
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in ("-h", "--help"):
            print(__doc__.split("Run from the repo root:")[0])
            print(usage)
            return 0
        if arg in ("--json", "-j"):
            want_json = True
        elif arg == "--timeout":
            if i + 1 >= len(argv):
                print("--timeout requires a number of seconds",
                      file=sys.stderr)
                return 2
            try:
                timeout = float(argv[i + 1])
            except ValueError:
                print(f"Invalid --timeout '{argv[i + 1]}'",
                      file=sys.stderr)
                return 2
            i += 1
        elif arg.startswith("-"):
            print(f"Unknown option: {arg}", file=sys.stderr)
            print(usage)
            return 2
        else:
            positional.append(arg)
        i += 1

    if not positional:
        print(usage)
        return 1
    if len(positional) > 1:
        print("One IP address at a time.", file=sys.stderr)
        print(usage)
        return 2

    payload = run(positional[0], timeout=timeout)
    if want_json:
        print(json.dumps(payload, indent=2))
    else:
        print(render(payload))
    return 0 if payload.get("status") != "error" else 1


if __name__ == "__main__":
    sys.exit(main())
