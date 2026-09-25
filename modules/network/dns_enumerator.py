"""DNS Enumerator - modules/network/dns_enumerator.py
====================================================
DNS footprint enumeration for OSINT asset mapping:

  1) Core record mapping      - A/AAAA, MX, NS, TXT (SPF / DMARC / SaaS
                                verification tokens), CNAME, PTR (reverse)
  2) Subdomain discovery      - Certificate Transparency (crt.sh), optional
                                passive-DNS providers (SecurityTrails /
                                VirusTotal), dictionary brute-force with
                                wildcard filtering, permutation generation
  3) Asset intelligence       - wildcard DNS detection, zone transfer (AXFR)
     & vulnerability          - subdomain takeover (dangling CNAME) checks
       indicators

Design notes
------------
* DNS queries go through a small seam (_resolve) so every stage can be
  tested fully offline by monkeypatching it.
* Every stage degrades gracefully: optional API-key stages report
  status "skipped" when no key is set (they never fail the run); HTTP /
  DNS failures produce per-stage notes.
* Politeness limits: brute-force/permutation scanning is bounded by
  max_queries, each request has a timeout, and takeover checks fetch at
  most one page per cloud-backed host.

Run from the repo root:
  .\\.venv\\Scripts\\python.exe -m modules.network.dns_enumerator example.com
  .\\.venv\\Scripts\\python.exe -m modules.network.dns_enumerator example.com --no-axfr
  .\\.venv\\Scripts\\python.exe -m modules.network.dns_enumerator example.com --json
"""

import concurrent.futures, json, ipaddress, os, random, re, socket, sys, requests

from time import monotonic, sleep

import dns.exception, dns.query, dns.rdatatype, dns.reversename, dns.resolver

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CRT_SH_URL = "https://crt.sh/"
USER_AGENT = "OSINTNexusBot-DNSEnumerator/1.0"

# Default wordlist for dictionary brute-force (overridable via run/CLI).
DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "imap", "mx", "ns1", "ns2",
    "ns3", "admin", "administrator", "api", "app", "apps", "autodiscover",
    "beta", "blog", "cms", "cpanel", "dashboard", "db", "demo", "dev",
    "development", "dns", "docs", "email", "exchange", "files", "git",
    "help", "home", "host", "intranet", "localhost", "login", "mail2",
    "mobile", "monitor", "mysql", "new", "news", "old", "panel",
    "phpmyadmin", "portal", "prod", "production", "qa", "remote", "secure",
    "server", "service", "services", "shop", "staging", "stage", "static",
    "status", "support", "test", "testing", "tools", "upload", "vpn", "web",
    "webmail2", "www2", "www3", "www4",
]

# Permutation vocabulary: environment words + separators swapped around a label.
ENV_WORDS = [
    "dev", "stage", "staging", "prod", "production", "test", "qa", "uat",
    "beta", "alpha", "pre", "demo", "new", "old", "backup", "v2",
]
SEPARATORS = ["-", ".", "_"]

# Takeover fingerprint table: provider -> (cname substrings, HTTP body markers)
TAKEOVER_FINGERPRINTS = {
    "aws-s3": (["amazonaws.com", "s3."],
               ["NoSuchBucket", "The specified bucket does not exist"]),
    "github-pages": (["github.io"],
                     ["There isn't a GitHub Pages site here"]),
    "heroku": (["herokuapp.com"], ["No such app"]),
    "netlify": (["netlify.app"], ["Not Found - Request ID"]),
    "azure": (["azurewebsites.net", "cloudapp.net", "trafficmanager.net"],
              ["404 Web Site not found"]),
    "shopify": (["myshopify.com"],
                ["Sorry, this shop is currently unavailable"]),
    "wordpress": (["wordpress.com"], ["Do you want to register"]),
    "bitbucket": (["bitbucket.io"], ["Repository not found"]),
    "surge": (["surge.sh"], ["project not found"]),
    "readme": (["readme.io"], ["Project doesn't exist"]),
    "unbounce": (["unbouncepages.com"],
                 ["The requested URL was not found on this server"]),
    "zendesk": (["zendesk.com"], ["Help Center Closed"]),
    "fastly": (["fastly.net", "global.fastly.net"],
               ["Fastly error: unknown domain"]),
    "ghost": (["ghost.io"],
              ["The thing you were looking for is no longer here"]),
    "intercom": (["custom.intercom.help"], ["This Inbox is inactive"]),
    "statuspage": (["statuspage.io"], ["This Statuspage has been retired"]),
}

# TXT prefixes that reveal third-party SaaS integrations.
TOKEN_PREFIXES = [
    "google-site-verification=", "atlassian-domain-verification=",
    "facebook-domain-verification=", "google-adsense-verification=",
    "yandex-verification=", "github-verification=",
    "keybase-site-verification=", "ms=", "ms-domain-verification=",
    "onetrust-domain-verification=", "webexdomainverification=",
    "apple-domain-verification=", "citrix-verification=",
    "hackerone-site-verification=", "amazonses=", "docusign=",
    "google-hangouts=oembed-provider", "brave-ledger-verification=",
    "docker-verification=", "godaddy-site-verification=",
]

# Random label used for wildcard detection (stable per process).
_RANDOM_LABEL = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=12))


def _is_ip(text):
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# DNS seam (tests monkeypatch this)
# ---------------------------------------------------------------------------

def _resolve(name, rdtype, timeout=5.0):
    """Resolve `name` for `rdtype`, returning a list of rdata text strings.

    Every DNS feature funnels through this function so offline tests can
    replace it with a fake. Any DNS failure returns [] (never raises).
    """
    try:
        answer = dns.resolver.resolve(name, dns.rdatatype.from_text(rdtype),
                                      lifetime=timeout)
        return [rdata.to_text() for rdata in answer]
    except dns.exception.DNSException:
        return []


def _strip_quotes(text):
    """TXT rdata arrives quoted/escaped ('"v=spf1 ..."' or escaped quotes)."""
    return text.strip().strip('"').replace('\\"', '"')


# ---------------------------------------------------------------------------
# 1. Core Record Mapping
# ---------------------------------------------------------------------------

def address_records(domain, timeout=5.0):
    """A / AAAA queries -> IPv4/IPv6 address lists for the host."""
    return {
        "a": _resolve(domain, "A", timeout),
        "aaaa": _resolve(domain, "AAAA", timeout),
    }


def mx_records(domain, timeout=5.0):
    """MX query -> [{"priority": int, "exchange": "host"}] (sorted)."""
    out = []
    for rec in _resolve(domain, "MX", timeout):
        parts = rec.split()
        if len(parts) >= 2:
            try:
                # RFC 7505 null MX uses a literal "." exchange (no mail);
                # preserve it instead of stripping to an empty string.
                exchange = parts[1]
                if exchange != ".":
                    exchange = exchange.rstrip(".")
                out.append({"priority": int(parts[0]),
                            "exchange": exchange})
            except ValueError:
                continue
    out.sort(key=lambda m: m["priority"])
    return out


def ns_records(domain, timeout=5.0):
    """NS query -> list of authoritative nameserver hostnames."""
    return [r.rstrip(".") for r in _resolve(domain, "NS", timeout)]


def txt_analysis(domain, timeout=5.0):
    """TXT query + `_dmarc` sub-query; classify SPF / DMARC / SaaS tokens.

    Returns {"raw": [...], "spf": str|None, "dmarc": str|None,
             "verification_tokens": [{"type": str, "value": str}]}
    """
    raw = []
    for r in _resolve(domain, "TXT", timeout):
        for chunk in r.split('" "'):
            raw.append(_strip_quotes(chunk))

    spf = next((t for t in raw if t.lower().startswith("v=spf1")), None)
    dmarc = None
    for r in _resolve("_dmarc." + domain, "TXT", timeout):
        text = _strip_quotes(r)
        if text.lower().startswith("v=dmarc1"):
            dmarc = text
            break

    tokens = []
    for text in raw:
        lower = text.lower()
        for prefix in TOKEN_PREFIXES:
            if lower.startswith(prefix.lower()):
                tokens.append({"type": prefix.rstrip("="),
                               "value": text[len(prefix):].strip('"')})
                break
    return {"raw": raw, "spf": spf, "dmarc": dmarc,
            "verification_tokens": tokens}


def cname_target(host, timeout=5.0):
    """CNAME query -> canonical hostname, or None when no alias exists."""
    records = _resolve(host, "CNAME", timeout)
    return records[0].rstrip(".") if records else None


def ptr_records(ips, timeout=5.0):
    """Reverse DNS (PTR) for a list of IPs -> {ip: [hostnames]}."""
    out = {}
    for ip in ips:
        if not _is_ip(ip):
            continue
        try:
            rev = dns.reversename.from_address(ip).to_text()
        except Exception:
            out[ip] = []
            continue
        out[ip] = [r.rstrip(".") for r in _resolve(rev, "PTR", timeout)]
    return out


def core_record_mapping(domain, timeout=5.0):
    """Assemble the full core record mapping block for a domain."""
    addrs = address_records(domain, timeout)
    ips = addrs["a"] + addrs["aaaa"]
    return {
        "status": "ok",
        "a": addrs["a"],
        "aaaa": addrs["aaaa"],
        "mx": mx_records(domain, timeout),
        "ns": ns_records(domain, timeout),
        "txt": txt_analysis(domain, timeout),
        "cname": cname_target(domain, timeout),
        "ptr": ptr_records(ips, timeout),
        "resolved_ips": ips,
    }


# ---------------------------------------------------------------------------
# 2. Subdomain Discovery
# ---------------------------------------------------------------------------

def ct_log_scan(domain, timeout=15.0, retries=2, backoff=0.5):
    """Certificate Transparency (crt.sh) log scraping - passive discovery.

    crt.sh is a free community endpoint and intermittently returns 404 / 5xx
    responses or times out; up to `retries` extra attempts are made with a
    short backoff before the stage reports an error.
    """
    url = f"{CRT_SH_URL}?q=%25.{domain}&output=json"
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    attempt = 0
    data = None
    while True:
        attempt += 1
        try:
            resp = requests.get(url, headers=headers, timeout=timeout)
            if resp.status_code == 200:
                data = resp.json()
                break
            note = f"crt.sh returned HTTP {resp.status_code}"
        except requests.RequestException as e:
            note = f"crt.sh request failed: {e}"
        except ValueError:
            note = "crt.sh returned non-JSON payload"
        if attempt <= retries:
            sleep(backoff * attempt)
            continue
        return {"status": "error", "note": f"{note} (after {attempt} attempts)"}

    if not isinstance(data, list):
        return {"status": "error", "note": "Unexpected crt.sh response shape"}

    subdomains = set()
    for cert in data:
        if not isinstance(cert, dict):
            continue
        for field in ("name_value", "common_name"):
            value = cert.get(field)
            if not value:
                continue
            for name in value.splitlines():
                name = name.strip().lower().lstrip("*.")
                if name == domain or name.endswith("." + domain):
                    subdomains.add(name)
    subdomains.discard(domain)
    return {"status": "ok", "count": len(subdomains),
            "subdomains": sorted(subdomains)}


def passive_dns_lookup(domain, timeout=15.0):
    """Passive DNS aggregation from optional keyed providers.

    Consults SecurityTrails, VirusTotal and Censys, each only when its
    matching env key(s) are present; otherwise the stage reports status
    "skipped".  Aggregate counts are best-effort per provider.
    """
    subdomains = set()
    notes = []

    st_key = os.getenv("SECURITYTRAILS_API_KEY")
    if st_key:
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        headers = {"APIKEY": st_key, "Accept": "application/json"}
        try:
            resp = requests.get(url, headers=headers, timeout=timeout)
            if resp.status_code == 200:
                for sub in (resp.json().get("subdomains") or []):
                    if sub:
                        subdomains.add(f"{sub.lower().rstrip('.')}.{domain}")
            elif resp.status_code == 401:
                notes.append("SecurityTrails: invalid API key")
            else:
                notes.append(f"SecurityTrails: HTTP {resp.status_code}")
        except requests.RequestException as e:
            notes.append(f"SecurityTrails: {e}")

    vt_key = os.getenv("VIRUSTOTAL_API_KEY")
    if vt_key:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
        headers = {"x-apikey": vt_key, "Accept": "application/json"}
        try:
            resp = requests.get(url, headers=headers, timeout=timeout)
            if resp.status_code == 200:
                for item in (resp.json().get("data") or []):
                    sid = item.get("id") or ""
                    if sid.endswith("." + domain):
                        subdomains.add(sid.lower())
            else:
                notes.append(f"VirusTotal: HTTP {resp.status_code}")
        except requests.RequestException as e:
            notes.append(f"VirusTotal: {e}")

    cs_id = os.getenv("CENSYS_API_ID")
    cs_secret = os.getenv("CENSYS_API_SECRET")
    if cs_id and cs_secret:
        url = "https://search.censys.io/api/v2/certificates/search"
        try:
            resp = requests.get(
                url, params={"q": f"names: {domain}", "per_page": 100},
                auth=(cs_id, cs_secret),
                headers={"Accept": "application/json"}, timeout=timeout)
            if resp.status_code == 200:
                data = resp.json()
                hits = ((data.get("result") or {}).get("hits")
                        or data.get("hits") or [])
                for hit in hits:
                    for name in (hit.get("names") or []):
                        n = str(name).strip().lower().lstrip("*.")
                        if n != domain and n.endswith("." + domain):
                            subdomains.add(n)
            elif resp.status_code in (401, 403):
                notes.append("Censys: invalid API credentials")
            else:
                notes.append(f"Censys: HTTP {resp.status_code}")
        except requests.RequestException as e:
            notes.append(f"Censys: {e}")

    if subdomains:
        return {"status": "ok", "count": len(subdomains),
                "note": "; ".join(notes) if notes else "",
                "subdomains": sorted(subdomains)}
    if notes:
        return {"status": "error", "note": "; ".join(notes), "subdomains": []}
    return {"status": "skipped",
            "note": "No passive-DNS API key configured (SECURITYTRAILS_API_KEY "
                    "/ VIRUSTOTAL_API_KEY / CENSYS_API_ID + CENSYS_API_SECRET)",
            "subdomains": []}


def wildcard_detection(domain, timeout=5.0):
    """Wildcard DNS detection via a random non-existent subdomain.

    Returns {"enabled": bool, "probe": str, "ips": [...]}; enabled means
    the zone answers for any name, so brute-force hits need filtering.
    """
    probe = f"{_RANDOM_LABEL}.{domain}"
    ips = [ip for ip in _resolve(probe, "A", timeout) if _is_ip(ip)]
    return {"enabled": bool(ips), "probe": probe, "ips": ips}


def _filter_wildcard(hostnames, wildcard_ips):
    """Drop hostnames whose only addresses are the wildcard answer IPs."""
    if not wildcard_ips:
        return hostnames, 0
    kept, skipped = [], 0
    for h in hostnames:
        if h["ips"] and all(ip in wildcard_ips for ip in h["ips"]):
            skipped += 1
        else:
            kept.append(h)
    return kept, skipped


def resolve_batch(hostnames, timeout=5.0, max_workers=10):
    """Resolve A + CNAME for many hostnames concurrently.

    Returns {hostname: {"ips": [...], "cname": str|None}}.
    """
    out = {}

    def _one(name):
        ips = [ip for ip in _resolve(name, "A", timeout) if _is_ip(ip)]
        return name, ips, cname_target(name, timeout)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        for name, ips, cname in pool.map(_one, hostnames):
            if ips or cname:
                out[name] = {"ips": ips, "cname": cname}
    return out


def dictionary_bruteforce(domain, wordlist=None, timeout=5.0,
                          max_workers=10, max_queries=250):
    """Dictionary brute-force resolution of common prefixes.

    Returns {"status","queried","found":[{hostname, ips, cname}],
             "skipped_wildcard"}.
    """
    wordlist = wordlist or DEFAULT_WORDLIST
    candidates = []
    seen = set()
    for word in wordlist:
        word = word.strip().lower().lstrip("*.").rstrip(".")
        if not word or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", word):
            continue
        if word in seen:
            continue
        seen.add(word)
        candidates.append(f"{word}.{domain}")
        if len(candidates) >= max_queries:
            break

    resolved = resolve_batch(candidates, timeout, max_workers)
    found = [{"hostname": name, "ips": h["ips"], "cname": h["cname"]}
             for name, h in resolved.items()]
    return {"status": "ok", "queried": len(candidates), "found": found}


def permutation_scan(domain, base_names, timeout=5.0, max_workers=10,
                     max_queries=250):
    """Generate + resolve permutations of known valid subdomains."""
    candidates = generate_permutations(domain, base_names, cap=max_queries)
    resolved = resolve_batch(candidates, timeout, max_workers)
    found = [{"hostname": name, "ips": h["ips"], "cname": h["cname"]}
             for name, h in resolved.items()]
    return {"status": "ok", "generated": len(candidates),
            "found": found, "candidates": candidates}


def generate_permutations(domain, base_names, cap=250):
    """Pure permutation generator - environment-word / separator mutations.

    Given known subdomains (e.g. app-dev.example.com) produces likely
    siblings (app-stage, app-prod, app.example.com, app_v2, ...). Pure and
    deterministic (sorted) so it is unit-testable offline.
    """
    out = set()
    known = set(base_names)
    for name in known:
        if not name.endswith("." + domain):
            continue
        label = name[: -(len(domain) + 1)]
        parts = re.split(r"[-._]", label)
        # label without any env suffix (app-dev -> app)
        core = parts[0] if parts else label
        if not core or not core.isalnum():
            continue
        for sep in SEPARATORS:
            for env in ENV_WORDS:
                out.add(f"{core}{sep}{env}.{domain}")
                out.add(f"{env}{sep}{core}.{domain}")
        # swap an existing env token with every other env token
        for i, part in enumerate(parts):
            if part in ENV_WORDS:
                for env in ENV_WORDS:
                    if env == part:
                        continue
                    swapped = parts[:i] + [env] + parts[i + 1:]
                    out.add(f"{'-'.join(swapped)}.{domain}")
    # drop names we already know about
    out.difference_update(known)
    result = sorted(out)
    return result[:cap]


# ---------------------------------------------------------------------------
# 3. Asset Intelligence & Vulnerability Indicators
# ---------------------------------------------------------------------------

def zone_transfer_check(domain, nameservers, timeout=8.0):
    """AXFR attempt against each public NS server of the target zone.

    dnspython's xfr() requires an IP address, so each nameserver hostname
    is resolved to its A record(s) first and every address is tried.

    Returns {"status","vulnerable","checked_servers",
             "servers":[{nameserver, ip, vulnerable, note, sample?}]}
    """
    servers = []
    for ns in nameservers:
        entry = {"nameserver": ns, "vulnerable": False, "note": ""}
        ips = [ip for ip in _resolve(ns, "A", timeout) if _is_ip(ip)]
        if not ips:
            entry["note"] = "Nameserver could not be resolved to an IP"
            servers.append(entry)
            continue
        entry["ip"] = ips[0]
        try:
            messages = list(dns.query.xfr(ips[0], domain, timeout=timeout,
                                          lifetime=timeout))
            # A real zone transfer yields multiple messages (SOA ... SOA).
            # A single SOA-only reply is dnspython's "refused" shape.
            answers = sum(len(m.answer) for m in messages)
            if len(messages) <= 1:
                entry["note"] = "Transfer refused (only SOA returned)"
            else:
                entry["vulnerable"] = True
                entry["record_count"] = answers
                entry["note"] = "Zone transfer ALLOWED"
                entry["sample"] = [
                    rr.to_text() if hasattr(rr, "to_text") else str(rr)
                    for rr in messages[1].answer][:10]
        except (dns.query.TransferError, dns.exception.FormError) as e:
            entry["note"] = f"Transfer refused: {e}"
        except dns.exception.Timeout:
            entry["note"] = "Transfer timed out"
        except dns.exception.DNSException as e:
            entry["note"] = f"DNS error: {e}"
        except socket.error as e:
            entry["note"] = f"Connection error: {e}"
        except Exception as e:  # pragma: no cover - last-resort guard
            entry["note"] = f"AXFR error: {e}"
        servers.append(entry)

    return {
        "status": "ok",
        "vulnerable": any(s["vulnerable"] for s in servers),
        "checked_servers": len(servers),
        "servers": servers,
    }


def _provider_for_cname(target):
    """Return the provider key whose cname substring appears in `target`."""
    t = (target or "").lower()
    for provider, (fragments, _markers) in TAKEOVER_FINGERPRINTS.items():
        if any(frag.lower() in t for frag in fragments):
            return provider
    return None


def _http_marker(body, provider):
    """True when the fetched page body matches a provider 'gone' marker."""
    markers = TAKEOVER_FINGERPRINTS.get(provider, (None, []))[1]
    low = (body or "").lower()
    return any(m.lower() in low for m in markers)


def subdomain_takeover_check(hosts, timeout=8.0):
    """Dangling-CNAME / subdomain takeover checks for resolved hosts.

    Each host whose CNAME points at a known cloud provider is probed:
      - DNS: does the canonical target still resolve?
      - HTTP: one GET to the host; body markers indicate a released resource.

    Returns {"status","count","checks":[...]}.  A host is reported
    "vulnerable" only when the cloud resource is demonstrably gone.
    """
    checks = []
    for host in hosts:
        hostname = host.get("hostname")
        cname = host.get("cname")
        provider = _provider_for_cname(cname)
        if not hostname or not provider:
            continue

        check = {
            "hostname": hostname,
            "cname": cname,
            "provider": provider,
            "dns_dangling": False,
            "http_gone": False,
            "evidence": "",
            "status": "ok",
        }
        # 1) DNS: target no longer resolves -> dangling
        target_ips = [ip for ip in _resolve(cname, "A", timeout) if _is_ip(ip)]
        check["dns_dangling"] = not target_ips
        check["evidence"] = ("canonical target does not resolve" if check["dns_dangling"]
                             else "canonical target resolves")

        # 2) HTTP: one bounded fetch, look for provider release markers
        try:
            resp = requests.get(f"https://{hostname}/", timeout=timeout,
                                headers={"User-Agent": USER_AGENT},
                                allow_redirects=True)
            gone = _http_marker(resp.text, provider)
            check["http_gone"] = gone
            check["http_status"] = resp.status_code
            check["evidence"] += f"; HTTP {resp.status_code}" + \
                (" matches release marker" if gone else "")
        except requests.RequestException as e:
            check["evidence"] += f"; HTTP probe failed: {e}"

        check["status"] = "vulnerable" if (check["dns_dangling"] or check["http_gone"]) \
            else "ok"
        checks.append(check)

    return {"status": "ok", "count": len(checks), "checks": checks}


# ---------------------------------------------------------------------------
# Orchestration: run()
# ---------------------------------------------------------------------------

def run(domain, timeout=5.0, do_passive=True, do_bruteforce=True,
        do_permutations=True, do_axfr=True, do_takeover=True,
        max_queries=250, max_workers=10, wordlist=None):
    """Full DNS enumeration run over a domain; returns the JSON payload.

    The payload is organized for humans AND machines:
      domain -> status -> elapsed_ms -> record_mapping -> subdomain_discovery
      -> known_subdomains -> asset_intelligence -> findings -> summary

    * ``status`` is the top-level verdict: "ok" when every stage that ran
      succeeded, "partial" when an optional stage reported an error, or
      "error" for a failed run.
    * ``findings`` aggregates the actionable notes from every stage
      (mail-security gaps, wildcard filtering, zone-transfer / takeover
      risks, stage errors) so nothing important is buried in a nested block.
    """
    domain = (domain or "").strip().lower().rstrip(".")
    if not domain:
        return {"status": "error", "error": "No domain provided."}
    if not re.fullmatch(r"(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+"
                        r"[a-z]{2,63}", domain):
        return {"status": "error",
                "error": f"'{domain}' is not a valid domain name."}

    start = monotonic()
    findings = []
    failed_stages = []

    # ---- 1. Core record mapping
    rm = core_record_mapping(domain, timeout)

    # Mail-security posture: only when the domain actually receives mail
    # (a literal "." exchange is the RFC 7505 null-MX "no mail" marker).
    has_mail = any(m.get("exchange") != "." for m in rm["mx"])
    if has_mail:
        if not rm["txt"].get("spf"):
            findings.append("No SPF record published for mail-receiving domain")
        if not rm["txt"].get("dmarc"):
            findings.append(f"No DMARC policy found at _dmarc.{domain}")

    # Third-party domain-verification tokens published in TXT records
    # (e.g. google-site-verification=... for Search Console).
    tokens = rm["txt"].get("verification_tokens") or []
    if tokens:
        kinds = sorted({t.get("type", "token") for t in tokens})
        findings.append(
            f"{len(tokens)} domain-verification token(s) for third-party "
            f"services ({', '.join(kinds)})")

    # ---- wildcard detection first: it shapes brute-force filtering
    wildcard = wildcard_detection(domain, timeout)
    wildcard_ips = set(wildcard["ips"])
    if wildcard["enabled"]:
        findings.append(
            f"Wildcard DNS enabled on {domain} (probe {wildcard['probe']} "
            f"resolves) - brute-force results are filtered against it")

    discovery = {}

    # ---- 2. Subdomain discovery
    known = set()
    ct = ct_log_scan(domain)
    discovery["certificate_transparency"] = ct
    if ct.get("status") == "ok":
        known.update(ct["subdomains"])
        if ct["subdomains"]:
            findings.append(
                f"CT logs exposed {len(ct['subdomains'])} subdomain(s)")
    elif ct.get("status") == "error":
        failed_stages.append("certificate_transparency")
        findings.append(f"Certificate Transparency scan failed: {ct['note']}")

    passive = {"status": "skipped", "note": "disabled", "subdomains": []}
    if do_passive:
        passive = passive_dns_lookup(domain)
    discovery["passive_dns"] = passive
    if passive.get("status") == "ok":
        known.update(passive["subdomains"])
        if passive["subdomains"]:
            findings.append(
                f"Passive DNS returned {len(passive['subdomains'])} subdomain(s)")
    elif passive.get("status") == "error":
        failed_stages.append("passive_dns")
        findings.append(f"Passive DNS failed: {passive['note']}")

    bf = {"status": "skipped", "note": "disabled", "found": []}
    if do_bruteforce:
        bf = dictionary_bruteforce(domain, wordlist, timeout, max_workers,
                                   max_queries)
    discovery["dictionary_bruteforce"] = bf
    if bf.get("status") == "ok" and bf.get("found"):
        findings.append(f"Dictionary scan resolved {len(bf['found'])} host(s)")
    elif bf.get("status") == "error":
        failed_stages.append("dictionary_bruteforce")
        findings.append(f"Dictionary scan failed: {bf['note']}")

    perm = {"status": "skipped", "note": "disabled", "found": [],
            "generated": 0}
    if do_permutations and known:
        perm_result = permutation_scan(domain, sorted(known), timeout,
                                       max_workers, max_queries)
        # keep the count but drop the (potentially large) candidate dump
        perm = {k: v for k, v in perm_result.items() if k != "candidates"}
        if perm.get("status") == "ok" and perm.get("found"):
            findings.append(
                f"Permutation scan found {len(perm['found'])} host(s) from "
                f"{perm.get('generated', 0)} candidates")
        elif perm.get("status") == "error":
            failed_stages.append("permutation_scan")
            findings.append(f"Permutation scan failed: {perm['note']}")
    discovery["permutation_scan"] = perm

    # ---- merge all discovery hostnames + apply wildcard filter
    merged = {}
    for bucket in (bf.get("found", []), perm.get("found", [])):
        for h in bucket:
            merged[h["hostname"]] = h
    hosts = list(merged.values())
    hosts, skipped_wild = _filter_wildcard(hosts, wildcard_ips)
    if skipped_wild:
        findings.append(
            f"{skipped_wild} discovered host(s) filtered as wildcard answers")
    hosts.sort(key=lambda h: h["hostname"])

    # ---- 3. Asset intelligence / vulnerability indicators
    ai = {}
    ai["wildcard_dns"] = wildcard

    axfr = {"status": "skipped", "note": "disabled"}
    if do_axfr:
        axfr = zone_transfer_check(domain, rm["ns"], timeout)
    ai["zone_transfer"] = axfr
    if do_axfr:
        if axfr.get("vulnerable"):
            for s in axfr.get("servers", []):
                if s.get("vulnerable"):
                    findings.append(
                        f"Zone transfer (AXFR) ALLOWED on {s['nameserver']}"
                        + (f" ({s.get('ip')})" if s.get("ip") else "")
                        + " - the whole zone can be copied")
        elif axfr.get("checked_servers"):
            findings.append(
                f"Zone transfer refused on all {axfr['checked_servers']} "
                f"name server(s)")

    takeover = {"status": "skipped", "note": "disabled", "count": 0,
                "checks": []}
    if do_takeover and hosts:
        takeover = subdomain_takeover_check(hosts, timeout)
    ai["subdomain_takeover"] = takeover
    ai["hosts"] = hosts
    if do_takeover and hosts:
        vulnerable = [c for c in takeover["checks"]
                      if c["status"] == "vulnerable"]
        for c in vulnerable:
            findings.append(
                f"Subdomain takeover risk: {c['hostname']} -> {c['cname']} "
                f"({c['provider']})")
        if takeover["checks"] and not vulnerable:
            findings.append(
                f"No takeover risk among {len(takeover['checks'])} "
                f"cloud-backed host(s) checked")

    # ---- top-level verdict
    if failed_stages:
        status = "partial"
        findings.append(
            f"{len(failed_stages)} stage(s) reported errors: "
            f"{', '.join(sorted(set(failed_stages)))}")
    else:
        status = "ok"
    elapsed_ms = round((monotonic() - start) * 1000)

    # ---- summary line
    vuln = [c for c in takeover["checks"] if c["status"] == "vulnerable"]
    summary = (
        f"{domain}: {len(rm['a']) + len(rm['aaaa'])} address record(s), "
        f"{len(rm['mx'])} MX, {len(rm['ns'])} NS, "
        f"{ct.get('count', 0)} CT subdomains, "
        f"{len(known)} unique known subdomain(s), "
        f"{len(hosts)} live host(s) mapped, "
        f"{len(vuln)} takeover candidate(s)."
    )
    if status == "partial":
        summary += f" ({len(failed_stages)} stage(s) with errors)"

    return {
        "domain": domain,
        "status": status,
        "elapsed_ms": elapsed_ms,
        "record_mapping": rm,
        "subdomain_discovery": discovery,
        "known_subdomains": sorted(known),
        "asset_intelligence": ai,
        "findings": findings,
        "summary": summary,
    }


# ---------------------------------------------------------------------------
# 4. Human-readable renderer (same presentation layer as whois_lookup)
# ---------------------------------------------------------------------------

def _host_label(host):
    """'name [ip, ip]' for a resolved-host dict."""
    name = host.get("hostname", "")
    ips = host.get("ips") or []
    return f"{name} [{', '.join(ips)}]" if ips else name


def _stage_text(block, value_fn):
    """Human text for a discovery/intel stage block (status-aware)."""
    status = block.get("status", "skipped")
    if status == "ok":
        return value_fn(block)
    if status == "skipped":
        note = block.get("note") or "skipped"
        return f"skipped - {note}"
    note = block.get("note") or "error"
    return f"error - {note}"


def render(payload):
    """Render a run() payload as a readable report (default CLI output)."""
    if payload.get("status") == "error":
        head = f"DNS Enumerator: {payload.get('domain')}" \
            if payload.get("domain") else "DNS Enumerator"
        return f"{head} failed\n  Error: {payload.get('error') or 'unknown error'}"

    domain = payload["domain"]
    rm = payload["record_mapping"]
    rows = []

    rows.append(("Status", payload["status"]))
    rows.append(("Elapsed", f"{payload['elapsed_ms']} ms"))
    rows.append(("IPv4 (A)", ", ".join(rm["a"]) if rm["a"] else "(none)"))
    rows.append(("IPv6 (AAAA)",
                 ", ".join(rm["aaaa"]) if rm["aaaa"] else "(none)"))
    if rm["mx"]:
        if len(rm["mx"]) == 1 and rm["mx"][0]["exchange"] == ".":
            rows.append(("MX", "0 .  (null MX - no mail service)"))
        else:
            rows.append(("MX", ", ".join(
                f"{m['priority']} {m['exchange']}" for m in rm["mx"])))
    else:
        rows.append(("MX", "(none)"))
    rows.append(("Name servers",
                 ", ".join(rm["ns"]) if rm["ns"] else "(none)"))
    rows.append(("SPF", rm["txt"].get("spf") or "not published"))
    rows.append(("DMARC", rm["txt"].get("dmarc") or "not found"))
    tok = rm["txt"].get("verification_tokens") or []
    if tok:
        parts = []
        for t in tok:
            v = t.get("value", "")
            label = t.get("type", "token")
            parts.append(f"{label}={v}" if len(v) <= 48
                         else f"{label}={v[:45]}...")
        rows.append(("Verification tokens", "; ".join(parts)))
    cname = rm.get("cname")
    rows.append(("CNAME", cname if cname else "(none)"))
    ptr_hits = {ip: hosts for ip, hosts in (rm.get("ptr") or {}).items()
                if hosts}
    if ptr_hits:
        rows.append(("Reverse DNS", " | ".join(
            f"{ip} -> {', '.join(h)}" for ip, h in sorted(ptr_hits.items()))))

    lines = [f"DNS Enumerator: {domain}"]
    width = max(len(k) for k, _ in rows)
    for label, value in rows:
        lines.append(f"  {label:<{width}}  : {value}")

    # Discovery block
    dd = payload["subdomain_discovery"]
    lines.append("")
    lines.append("  Discovery")
    d_rows = []
    ct = dd.get("certificate_transparency", {})
    d_rows.append(("CT logs", _stage_text(
        ct, lambda b: f"{len(b.get('subdomains', []))} subdomain(s)")))
    passive = dd.get("passive_dns", {})
    d_rows.append(("Passive DNS", _stage_text(
        passive, lambda b: f"{len(b.get('subdomains', []))} subdomain(s)")))
    bf = dd.get("dictionary_bruteforce", {})
    d_rows.append(("Dictionary", _stage_text(
        bf, lambda b: f"{len(b.get('found', []))} host(s) resolved")))
    perm = dd.get("permutation_scan", {})
    d_rows.append(("Permutations", _stage_text(
        perm, lambda b: f"{len(b.get('found', []))} host(s) from "
                        f"{b.get('generated', 0)} candidates")))
    dw = max(len(k) for k, _ in d_rows)
    for label, value in d_rows:
        lines.append(f"    {label:<{dw}}  : {value}")

    # Asset intelligence block
    ai = payload["asset_intelligence"]
    lines.append("")
    lines.append("  Asset intelligence")
    a_rows = []
    wc = ai.get("wildcard_dns", {})
    a_rows.append(("Wildcard DNS",
                   "enabled - host results are filtered"
                   if wc.get("enabled") else "not detected"))
    hosts = ai.get("hosts", [])
    if hosts:
        shown = hosts[:12]
        txt = ", ".join(_host_label(h) for h in shown)
        extra = len(hosts) - len(shown)
        if extra:
            txt += f"  (+{extra} more)"
        a_rows.append(("Live hosts", txt))
    else:
        a_rows.append(("Live hosts", "(none resolved)"))
    axfr = ai.get("zone_transfer", {})
    if axfr.get("status") == "skipped":
        a_rows.append(("Zone transfer", "skipped"))
    elif axfr.get("vulnerable"):
        names = ", ".join(s["nameserver"] for s in axfr.get("servers", [])
                          if s.get("vulnerable"))
        a_rows.append(("Zone transfer", f"ALLOWED on {names} - RISK"))
    elif axfr.get("checked_servers"):
        a_rows.append(("Zone transfer",
                       f"refused on all {axfr['checked_servers']} "
                       f"name server(s)"))
    else:
        a_rows.append(("Zone transfer", "no name servers checked"))
    tk = ai.get("subdomain_takeover", {})
    if tk.get("status") == "skipped":
        a_rows.append(("Takeover", "skipped"))
    else:
        checks = tk.get("checks", [])
        vuln = sum(1 for c in checks if c["status"] == "vulnerable")
        if checks:
            a_rows.append(("Takeover",
                           f"{vuln} vulnerable of {len(checks)} checked"))
        else:
            a_rows.append(("Takeover", "no cloud-backed host(s) to check"))
    aw = max(len(k) for k, _ in a_rows)
    for label, value in a_rows:
        lines.append(f"    {label:<{aw}}  : {value}")

    findings = payload.get("findings") or []
    lines.append("")
    lines.append("  Findings")
    if findings:
        for f in findings:
            lines.append(f"    - {f}")
    else:
        lines.append("    - none")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI: python -m modules.network.dns_enumerator [--json] example.com [...]
# ---------------------------------------------------------------------------

def _read_wordlist(path):
    """Load newline-separated hostname labels from a file."""
    with open(path, encoding="utf-8") as fh:
        words = [ln.strip().lower() for ln in fh if ln.strip()]
    return words


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    flags = {"do_passive": True, "do_bruteforce": True,
             "do_permutations": True, "do_axfr": True, "do_takeover": True}
    want_json = False
    wordlist_path = None
    positional = []
    usage = ("Usage: python -m modules.network.dns_enumerator [--json] "
             "<domain> [--wordlist FILE] [--no-passive] [--no-bruteforce] "
             "[--no-permutations] [--no-axfr] [--no-takeover]")
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in ("-h", "--help"):
            print(__doc__.split("Run from the repo root:")[0])
            print(usage)
            return 0
        if arg in ("--json", "-j"):
            want_json = True
        elif arg in ("--no-passive", "--no-bruteforce", "--no-permutations",
                     "--no-axfr", "--no-takeover"):
            flags[arg.replace("--no-", "do_").replace("-", "_")] = False
        elif arg == "--wordlist":
            if i + 1 >= len(argv):
                print("--wordlist requires a file path", file=sys.stderr)
                return 2
            wordlist_path = argv[i + 1]
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

    wordlist = None
    if wordlist_path:
        try:
            wordlist = _read_wordlist(wordlist_path)
        except OSError as e:
            print(f"Cannot read wordlist '{wordlist_path}': {e}",
                  file=sys.stderr)
            return 2
        if not wordlist:
            print(f"Wordlist '{wordlist_path}' contains no labels",
                  file=sys.stderr)
            return 2

    payload = run(positional[0], wordlist=wordlist, **flags)
    if want_json:
        print(json.dumps(payload, indent=2))
    else:
        print(render(payload))
    return 0 if payload.get("status") != "error" else 1


if __name__ == "__main__":
    sys.exit(main())

