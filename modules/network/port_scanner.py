"""Port Scanner - modules/network/port_scanner.py
=================================================
TCP connect port scanning for OSINT exposure mapping:

  1) Core scanning        - TCP connect sweeps with open / closed / filtered
                            verdicts, bounded concurrency, host resolution
                            (IPv4 + IPv6), port selection (defaults or an
                            explicit list/range spec)
  2) Service intelligence - port -> service labeling, best-effort banner
                            grab on open ports, TLS certificate probe on
                            common TLS ports (verification status, issuer,
                            subject, SAN list, expiry window, cipher)
  3) Findings             - plaintext / legacy service flags, TLS hygiene
                            (untrusted / expired certificates), per-host
                            exposure summary + top-level verdict

Design notes
------------
* All network I/O runs through small seams (_resolve_host, _connect,
  _grab_banner, _tls_probe) so every stage is testable fully offline by
  monkeypatching them.
* Port scanning is ACTIVE against the target - only scan hosts you are
  authorized to test. Politeness is first-class: bounded concurrency, a
  per-connect timeout, and a fixed default port set (no full 65535-port
  sweep by default).
* Banner / TLS probes are time-boxed and best-effort: a silent or refused
  service yields no detail, never a failed run.

Run from the repo root:
  ./.venv/Scripts/python.exe -m modules.network.port_scanner example.com
  ./.venv/Scripts/python.exe -m modules.network.port_scanner 1.2.3.4 --ports "80,443,8000-9000"
  ./.venv/Scripts/python.exe -m modules.network.port_scanner example.com --json
"""

import concurrent.futures, errno, ipaddress, json, re, socket, ssl, sys
from datetime import datetime, timezone
from time import monotonic

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Curated default set: common web / mail / remote-admin / database services.
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587,
    636, 993, 995, 1433, 1521, 1723, 3306, 3389, 5432, 5900, 5985, 6379,
    8080, 8443, 8888, 9200, 27017,
]

SERVICE_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 443: "https", 445: "microsoft-ds", 465: "smtps",
    587: "submission", 636: "ldaps", 993: "imaps", 995: "pop3s",
    1433: "ms-sql", 1521: "oracle", 1723: "pptp", 3306: "mysql",
    3389: "ms-wbt-server", 5432: "postgresql", 5900: "vnc", 5985: "http",
    6379: "redis", 8080: "http-alt", 8443: "https-alt", 8888: "http-alt",
    9200: "elasticsearch", 27017: "mongodb",
}

# Ports whose native protocol is unencrypted (clear-text exposure signal).
PLAINTEXT_PORTS = {21, 23, 25, 80, 110, 143, 3306, 5432, 5900, 6379,
                   8080, 8888, 9200, 27017}

# Common TLS ports probed for a certificate when found open.
TLS_PORTS = {443, 465, 587, 636, 993, 995, 8443}

HOSTNAME_RE = re.compile(
    r"(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")

# ---------------------------------------------------------------------------
# Port specification parsing + target validation
# ---------------------------------------------------------------------------

def parse_ports(spec):
    """Parse a port spec like '22', '80,443' or '8000-9000' (mixed allowed).

    Raises ValueError on any invalid token or out-of-range value.
    """
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_s, _, hi_s = part.partition("-")
            try:
                lo, hi = int(lo_s), int(hi_s)
            except ValueError:
                raise ValueError(f"invalid port range '{part}'")
            if not (1 <= lo <= hi <= 65535):
                raise ValueError(f"invalid port range '{part}'")
            ports.update(range(lo, hi + 1))
        else:
            try:
                p = int(part)
            except ValueError:
                raise ValueError(f"invalid port '{part}'")
            if not 1 <= p <= 65535:
                raise ValueError(f"invalid port '{part}'")
            ports.add(p)
    if not ports:
        raise ValueError("empty port spec")
    return sorted(ports)


def normalize_target(target):
    """Strip and lowercase a CLI target; returns None when blank."""
    if not target:
        return None
    t = target.strip().lower()
    return t or None


def _is_ip(text):
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def validate_target(target):
    """Return an error message when target is neither IP nor hostname."""
    if _is_ip(target):
        return None
    if HOSTNAME_RE.fullmatch(target):
        return None
    return f"'{target}' is not a valid IP address or hostname"

# ---------------------------------------------------------------------------
# Network seams (monkeypatched in offline tests)
# ---------------------------------------------------------------------------

def _resolve_host(host, timeout=5.0):
    """Resolve a host to its IP list (IPv4 first, then IPv6)."""
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    seen, out = set(), []
    for _fam, _st, _pr, _cn, sockaddr in infos:
        ip = sockaddr[0]
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    if not out:
        raise socket.gaierror(f"no addresses found for '{host}'")
    return out


def _connect(ip, port, timeout):
    """Open a TCP connection to ip:port; returns the connected socket.

    Raises on failure: socket.timeout for timeouts (filtered), OSError /
    ConnectionRefusedError for refused connections (closed).
    """
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((ip, port))
        return sock
    except Exception:
        sock.close()
        raise


def _grab_banner(sock, timeout=1.5):
    """Best-effort passive banner read; returns cleaned text or None."""
    try:
        sock.settimeout(timeout)
        data = sock.recv(512)
        if not data:
            return None
        text = data.decode("latin-1", "replace")
        text = "".join(ch if ch.isprintable() else " " for ch in text)
        text = " ".join(text.split()).strip()

        return text[:160] or None
    except Exception:
        return None

def _cert_cn(entries):
    """Pull the commonName out of ssl.getpeercert()'s nested structure."""
    try:
        for group in entries:
            for key, val in group:
                if key == "commonName":
                    return val
    except TypeError:
        pass
    return None


def _classify_tls_error(msg):
    """Map an SSL verification message to a short human reason."""
    m = (msg or "").lower()
    if "expired" in m:
        return "certificate expired"
    if "self-signed" in m:
        return "self-signed certificate"
    if "mismatch" in m or "doesn't match" in m:
        return "hostname mismatch"
    if "unable to get local issuer" in m or "unable to verify" in m:
        return "untrusted issuer"
    return "certificate not trusted"


def _tls_probe(ip, port, hostname, timeout):
    """Strict TLS handshake against ip:port using SNI for hostname.

    Returns a dict (never raises): verified handshakes carry the parsed
    certificate fields; failed ones carry a classified verify_error plus
    the negotiated protocol/cipher from a lenient second handshake.
    """
    info = {"verified": False, "issuer": None, "subject": None,
            "san": [], "not_after": None, "version": None, "cipher": None,
            "verify_error": None, "expired": False}
    ctx = ssl.create_default_context()
    raw = None
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
        with ctx.wrap_socket(raw, server_hostname=hostname) as tls:
            info["version"] = tls.version()
            cipher = tls.cipher()
            info["cipher"] = cipher[0] if cipher else None
            cert = tls.getpeercert()
            if cert:
                info["verified"] = True
                info["issuer"] = _cert_cn(cert.get("issuer"))
                info["subject"] = _cert_cn(cert.get("subject"))
                info["san"] = sorted(
                    {v for _t, v in cert.get("subjectAltName", [])})
                not_after = cert.get("notAfter")
                info["not_after"] = not_after
                if not_after:
                    try:
                        expires = datetime.strptime(
                            not_after, "%b %d %H:%M:%S %Y GMT")
                        info["expired"] = (
                            datetime.now(timezone.utc).replace(tzinfo=None)
                            > expires)
                    except ValueError:
                        pass
    except ssl.SSLCertVerificationError as e:
        info["verify_error"] = _classify_tls_error(
            e.verify_message or str(e))
    except (ssl.SSLError, OSError) as e:
        info["verify_error"] = _classify_tls_error(str(e))
    finally:
        if raw is not None:
            try:
                raw.close()
            except OSError:
                pass
    # Lenient pass: capture protocol/cipher even when verification failed.
    if not info["verified"]:
        try:
            lctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            lctx.check_hostname = False
            lctx.verify_mode = ssl.CERT_NONE
            raw2 = socket.create_connection((ip, port), timeout=timeout)
            try:
                with lctx.wrap_socket(raw2, server_hostname=hostname) as tls:
                    info["version"] = tls.version()
                    cipher = tls.cipher()
                    info["cipher"] = cipher[0] if cipher else None
            except Exception:
                raw2.close()
        except Exception:
            pass
    return info

# ---------------------------------------------------------------------------
# Per-port scanning + parallel sweep
# ---------------------------------------------------------------------------

def _scan_port(ip, port, timeout, do_probe, server_hostname):
    """Connect to one port and classify it; never raises."""
    result = {"port": port,
              "service": SERVICE_NAMES.get(port, "unknown"),
              "state": "filtered", "banner": None, "tls": None}
    try:
        sock = _connect(ip, port, timeout)
    except (socket.timeout, TimeoutError):
        return result
    except ConnectionRefusedError:
        result["state"] = "closed"
        return result
    except OSError as e:
        # Refused or host/network unreachable => closed; anything else
        # (e.g. a dropped probe) is treated as filtered.
        if e.errno in (errno.ECONNREFUSED, errno.EHOSTUNREACH,
                       errno.ENETUNREACH):
            result["state"] = "closed"
        return result
    result["state"] = "open"
    try:
        if do_probe:
            if port in TLS_PORTS:
                result["tls"] = _tls_probe(ip, port, server_hostname, timeout)
            else:
                result["banner"] = _grab_banner(sock, timeout)
    finally:
        sock.close()
    return result


def _scan_all(ips, ports, timeout, workers, do_probe, server_hostname):
    """Concurrently sweep every (ip, port) pair; returns per-host results."""
    hosts = {ip: {"ip": ip, "open": [], "closed": 0, "filtered": 0}
             for ip in ips}
    tasks = [(ip, p) for ip in ips for p in ports]
    if not tasks:
        return list(hosts.values())
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        future_map = {ex.submit(_scan_port, ip, p, timeout, do_probe,
                                server_hostname): (ip, p)
                      for ip, p in tasks}
        for fut in concurrent.futures.as_completed(future_map):
            ip, port = future_map[fut]
            try:
                result = fut.result()
            except Exception:
                # defensive: a broken seam must not crash the whole run
                result = {"port": port, "service": "unknown",
                          "state": "filtered", "banner": None, "tls": None}
            if result["state"] == "open":
                hosts[ip]["open"].append(result)
            elif result["state"] == "closed":
                hosts[ip]["closed"] += 1
            else:
                hosts[ip]["filtered"] += 1
    for h in hosts.values():
        h["open"].sort(key=lambda r: r["port"])
    return list(hosts.values())

# ---------------------------------------------------------------------------
# Findings + orchestration: run()
# ---------------------------------------------------------------------------

def _build_findings(hosts, ports_scanned):
    """Aggregate actionable notes across all scanned hosts."""
    findings = []
    for h in hosts:
        plain = [o for o in h["open"] if o["port"] in PLAINTEXT_PORTS]
        if plain:
            labels = ", ".join(
                f"{o['service']} ({o['port']})" for o in plain)
            findings.append(
                f"{len(plain)} plaintext service(s) open on {h['ip']}: "
                f"{labels}")
        for o in h["open"]:
            tls = o.get("tls")
            if not tls:
                continue
            if tls.get("verify_error"):
                findings.append(
                    f"TLS certificate on {h['ip']}:{o['port']} not trusted "
                    f"- {tls['verify_error']}")
            elif tls.get("expired"):
                findings.append(
                    f"TLS certificate on {h['ip']}:{o['port']} is EXPIRED")
    total_open = sum(len(h["open"]) for h in hosts)
    if total_open == 0 and ports_scanned:
        findings.append(
            f"No open TCP port(s) found among {ports_scanned} scanned")
    return findings


def run(target, ports=None, timeout=2.0, workers=50, do_probe=True):
    """Full TCP scan of a host; returns the JSON payload.

    Payload shape mirrors the sibling modules:
      target -> status -> elapsed_ms -> resolution -> ports_scanned -> scan
      -> hosts -> findings -> summary
    """
    target = normalize_target(target)
    if target is None:
        return {"status": "error", "error": "No target provided."}
    err = validate_target(target)
    if err:
        return {"status": "error", "error": err}
    port_list = (list(DEFAULT_PORTS) if ports is None
                 else sorted(set(int(p) for p in ports)))
    if not port_list:
        return {"status": "error", "error": "No ports to scan."}
    start = monotonic()
    try:
        ips = _resolve_host(target)
    except socket.gaierror as e:
        return {"status": "error",
                "error": f"Cannot resolve '{target}': {e}"}
    # SNI / verification name: the domain when given, the IP otherwise.
    server_hostname = target
    hosts = _scan_all(ips, port_list, timeout, workers, do_probe,
                      server_hostname)
    findings = _build_findings(hosts, len(port_list))
    elapsed_ms = round((monotonic() - start) * 1000)
    total_open = sum(len(h["open"]) for h in hosts)
    total_closed = sum(h["closed"] for h in hosts)
    total_filtered = sum(h["filtered"] for h in hosts)
    summary = (f"{target}: {len(ips)} address(es), {len(port_list)} "
               f"port(s) scanned - {total_open} open, {total_closed} "
               f"closed, {total_filtered} filtered")
    return {
        "target": target,
        "status": "ok",
        "elapsed_ms": elapsed_ms,
        "resolution": {"ips": ips},
        "ports_scanned": len(port_list),
        "scan": {"ports": port_list, "timeout": timeout,
                 "workers": workers, "do_probe": do_probe},
        "hosts": hosts,
        "findings": findings,
        "summary": summary,
    }

# ---------------------------------------------------------------------------
# Human-readable renderer (same presentation layer as the siblings)
# ---------------------------------------------------------------------------

def _open_detail(o):
    """One-line description for an open port entry."""
    if o.get("tls"):
        t = o["tls"]
        if t.get("verified"):
            parts = ["TLS verified"]
            if t.get("issuer"):
                parts.append(f"issuer CN={t['issuer']}")
            if t.get("not_after"):
                parts.append(f"valid to {t['not_after']}")
            text = ", ".join(parts)
            return text + "  [EXPIRED]" if t.get("expired") else text
        return "TLS NOT trusted - " + (t.get("verify_error") or "unknown")
    banner = o.get("banner")
    return f"banner: {banner}" if banner else "open (no banner)"


def render(payload):
    """Render a run() payload as a readable report (default CLI output)."""
    if payload.get("status") == "error":
        head = (f"Port Scanner: {payload.get('target')}"
                if payload.get("target") else "Port Scanner")
        return (f"{head} failed" + chr(10) + f"  Error: {payload.get('error') or 'unknown error'}")

    rows = [("Status", payload["status"]),
            ("Elapsed", f"{payload['elapsed_ms']} ms"),
            ("Addresses", ", ".join(payload["resolution"]["ips"])),
            ("Ports", f"{payload['ports_scanned']} scanned "
                      f"(timeout {payload['scan']['timeout']}s, "
                      f"{payload['scan']['workers']} workers)")]
    for h in payload["hosts"]:
        rows.append((f"Host {h['ip']}",
                     f"{len(h['open'])} open, {h['closed']} closed, "
                     f"{h['filtered']} filtered"))

    lines = [f"Port Scanner: {payload['target']}"]
    width = max(len(k) for k, _ in rows)
    for label, value in rows:
        lines.append(f"  {label:<{width}}  : {value}")

    opened = [(h, o) for h in payload["hosts"] for o in h["open"]]
    lines.append("")
    lines.append("  Open ports")
    if opened:
        addr_w = max(len(f"{h['ip']}:{o['port']}") for h, o in opened)
        for h, o in opened:
            addr = f"{h['ip']}:{o['port']}"
            lines.append(f"    {addr:<{addr_w}}  {o['service']:<12} "
                         f"{_open_detail(o)}")
    else:
        lines.append("    (none)")

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
# CLI: python -m modules.network.port_scanner [--json] <target> [...]
# ---------------------------------------------------------------------------

def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    want_json = False
    ports_spec = None
    timeout = 2.0
    workers = 50
    do_probe = True
    positional = []
    usage = ("Usage: python -m modules.network.port_scanner [--json] "
             "<target> [--ports SPEC] [--timeout SEC] [--workers N] "
             "[--no-probe]")
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in ("-h", "--help"):
            print(__doc__.split("Run from the repo root:")[0])
            print(usage)
            return 0
        if arg in ("--json", "-j"):
            want_json = True
        elif arg == "--ports":
            if i + 1 >= len(argv):
                print("--ports requires a spec like '80,443,8000-9000'",
                      file=sys.stderr)
                return 2
            ports_spec = argv[i + 1]
            i += 1
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
        elif arg == "--workers":
            if i + 1 >= len(argv):
                print("--workers requires a positive integer",
                      file=sys.stderr)
                return 2
            try:
                workers = int(argv[i + 1])
            except ValueError:
                print(f"Invalid --workers '{argv[i + 1]}'",
                      file=sys.stderr)
                return 2
            if workers < 1:
                print("--workers must be at least 1", file=sys.stderr)
                return 2
            i += 1
        elif arg == "--no-probe":
            do_probe = False
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
        print("One target at a time.", file=sys.stderr)
        print(usage)
        return 2

    ports = None
    if ports_spec:
        try:
            ports = parse_ports(ports_spec)
        except ValueError as e:
            print(f"Invalid --ports spec: {e}", file=sys.stderr)
            return 2

    payload = run(positional[0], ports=ports, timeout=timeout,
                  workers=workers, do_probe=do_probe)
    if want_json:
        print(json.dumps(payload, indent=2))
    else:
        print(render(payload))
    return 0 if payload.get("status") != "error" else 1


if __name__ == "__main__":
    sys.exit(main())
