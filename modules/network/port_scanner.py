"""Port Scanner - modules/network/port_scanner.py
=================================================
TCP + UDP exposure mapping for OSINT assessment.

  1) Core scanning        - TCP connect sweeps and UDP probes with
                            open / closed / filtered / open|filtered
                            verdicts, host expansion (IP, hostname, CIDR,
                            dash range, comma list, @file), IPv4 + IPv6,
                            port selection (defaults, list/range, presets)
  2) Traffic control      - rate ceiling, burst allowance, per-attempt
                            jitter, randomised port order, per-port
                            retries, host liveness pre-check
  3) Service intelligence - passive banner + ACTIVE protocol probe for
                            version extraction (HTTP, SSH, FTP, SMTP,
                            IMAP, POP3, Redis, MySQL, PostgreSQL, SMB,
                            LDAP, VNC), TLS certificate probe and hygiene
  4) Host fingerprinting  - TCP/IP stack signature (TTL, window, options
                            order) with an explicit low-confidence fallback
                            when raw sockets are not permitted
  5) Findings + output    - plaintext/legacy flags, TLS hygiene, per-host
                            exposure verdicts, text and nmap-compatible XML

Design notes
------------
* All network I/O goes through named seams: _resolve_host, _connect_tcp,
  _grab_banner, _service_probe, _tls_probe, _udp_probe, _os_probe,
  _host_alive. Every stage is therefore testable fully offline by
  monkeypatching one function, and NOTHING else here touches a socket.
* If you split this file later, those seams are the cut lines. They are the
  only functions that open a socket or send a probe, so extracting
  _service_probe into its own module, or the whole UDP path into
  udp_scan.py, is a mechanical move with no behaviour change.
* Port scanning is ACTIVE against the target - only scan hosts you are
  authorized to test. Politeness is first-class and enforceable: a default
  rate cap, a port ceiling, jitter, and --skip-hostdown so dead addresses
  cost one packet instead of 65k.
* Probes are time-boxed and best-effort: a silent, refused or hung service
  yields no detail, never a failed run.

Run from the repo root:
  ./.venv/Scripts/python.exe -m modules.network.port_scanner example.com
  ./.venv/Scripts/python.exe -m modules.network.port_scanner 1.2.3.4 --ports "80,443"
  ./.venv/Scripts/python.exe -m modules.network.port_scanner 10.0.0.0/24 --skip-hostdown
  ./.venv/Scripts/python.exe -m modules.network.port_scanner example.com --protocol both
  ./.venv/Scripts/python.exe -m modules.network.port_scanner example.com --xml out.xml
  ./.venv/Scripts/python.exe -m modules.network.port_scanner targets.txt --ports top
"""

import concurrent.futures, ctypes, errno, ipaddress, json, os, random, re
import socket, ssl, struct, sys, threading, xml.etree.ElementTree as ET
from datetime import datetime, timezone
from time import monotonic, sleep, time

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587,
    636, 993, 995, 1433, 1521, 1723, 3306, 3389, 5432, 5900, 5985, 6379,
    8080, 8443, 8888, 9200, 27017,
]

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 5900,
    6379, 8080, 8443, 27017,
]

FULL_RANGE_PORTS = None  # sentinel: means 1-65535

DEFAULT_UDP_PORTS = [53, 123, 161, 162, 389, 500, 1900, 5353]

SERVICE_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
    80: "http", 110: "pop3", 111: "rpcbind", 123: "ntp", 135: "msrpc",
    137: "netbios-ns", 139: "netbios-ssn", 143: "imap", 161: "snmp",
    162: "snmptrap", 389: "ldap", 443: "https", 445: "microsoft-ds",
    465: "smtps", 500: "isakmp", 587: "submission", 636: "ldaps",
    993: "imaps", 995: "pop3s", 1433: "ms-sql", 1521: "oracle",
    1723: "pptp", 1900: "ssdp", 2049: "nfs", 3306: "mysql",
    3389: "ms-wbt-server", 5000: "upnp", 5432: "postgresql",
    5900: "vnc", 5985: "http", 6379: "redis", 8000: "http-alt",
    8080: "http-alt", 8443: "https-alt", 8888: "http-alt",
    9200: "elasticsearch", 27017: "mongodb",
}

PLAINTEXT_PORTS = {21, 23, 25, 80, 110, 143, 3306, 5432, 5900, 6379,
                   8080, 8888, 9200, 27017}

TLS_PORTS = {443, 465, 587, 636, 993, 995, 8443}

# Ports that speak HTTP even though the well-known port is not 80.
HTTPISH_PORTS = {80, 443, 591, 8000, 8008, 8080, 8081, 8443, 8888, 9200,
                 5000, 5985, 5986, 9180}

HOSTNAME_RE = re.compile(
    r"(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")

PRESETS = {"top": TOP_PORTS, "quick": DEFAULT_PORTS,
           "standard": DEFAULT_PORTS, "full": FULL_RANGE_PORTS}

MAX_PORTS_DEFAULT = 4096
MAX_HOSTS_DEFAULT = 256          # a /16 is a typo until proven otherwise
BANNER_TIMEOUT = 0.5
PROBE_TIMEOUT = 1.5

UDP_VERDICT_ON_TIMEOUT = "open|filtered"

# ---------------------------------------------------------------------------
# UDP protocol probes
# ---------------------------------------------------------------------------

def _dns_version_bind_query():
    labels = b""
    for part in ("version", "bind"):
        labels += bytes([len(part)]) + part.encode("ascii")
    header = b"\x00\x1d\x00\x00\x10\x00\x03\x00\x00\x00\x00\x00\x00"
    return header + labels + b"\x00" + b"\x00\x10\x00\x01"


def _ssdp_msearch():
    return (b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n'
            b'MAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n')


def _ntp_monlist():
    return b"\x17\x00\x03\x2a" + b"\x00" * 12 + b"\x00\x06"


def _snmp_get_sysdescr():
    oid = bytes.fromhex("2b06010401805f0000")
    pdu = (b"\xa0\x24\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00"
           b"\x30\x0e\x30\x0c\x06\x0a" + oid + b"\x05\x00")
    return b"\x30" + bytes([len(pdu) + 4]) + b"\x02\x01\x01\x04\x06public" + pdu


def _netbios_name_query():
    """NetBIOS name service wildcard query."""
    name = b'*' + bytes(15)
    encoded = b''
    for ch in name:
        encoded += bytes([0x41 + ((ch >> 4) & 0x0F),
                          0x41 + (ch & 0x0F)])
    header = bytes.fromhex("82e5") + bytes(6) + bytes.fromhex("00210001")
    middle = bytes.fromhex("000000000100")
    tail = bytes(18) + bytes.fromhex("00200001")
    return header + middle + encoded + tail


def _ldap_root_dse():
    return b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00"


UDP_PROBES = {
    53: _dns_version_bind_query, 123: _ntp_monlist,
    161: _snmp_get_sysdescr, 162: _snmp_get_sysdescr,
    389: _ldap_root_dse, 1900: _ssdp_msearch, 5353: _ssdp_msearch,
}

# ---------------------------------------------------------------------------
# Active service probes. A banner alone gives you "ssh"; only a version
# probe turns that into "OpenSSH 8.9p1", which is the difference between a
# useful finding and a port number.
# ---------------------------------------------------------------------------

_SSH_RE = re.compile(r"^SSH-[\d.]+-([^\r\n]+)")
_BANNER220_RE = re.compile(r"^220[- ]([^\r\n]{1,80})")
_SMB_RE = re.compile(rb"\xffSMB\x40")
_SMB_VER = {"\x01": "SMB1", "\x02": "SMB2", "\x03": "SMB3"}
_REDIS_RE = re.compile(r"redis_version:([^\r\n]+)")
_SERVER_RE = re.compile(r"(?im)^server:\s*([^\r\n]+)")
_SERVER2_RE = re.compile(r"(?im)^x-powered-by:\s*([^\r\n]+)")
_POSTGRES_RE = re.compile(rb"E\x00\x00\x00.[0-9A-F]")
_MYSQL_AUTH = re.compile(rb"\x00\x00\x00\x0a")


def _probe_http(sock, timeout, banner=None):
    """Minimal GET; the Server and X-Powered-By headers carry the version."""
    host = sock.getpeername()[0] if _has_peername(sock) else "target"
    req = (f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: probe\r\n"
           f"Connection: close\r\n\r\n").encode("ascii", "replace")
    sock.sendall(req)
    raw = _recv_all(sock, timeout)
    head = raw.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
    for rx in (_SERVER_RE, _SERVER2_RE):
        m = rx.search(head)
        if m:
            return m.group(1).strip()
    status = head.split("\r\n", 1)[0].strip()
    return status or None


def _probe_redis(sock, timeout, banner=None):
    """Redis speaks inline: INFO returns the version in one round trip."""
    sock.sendall(b"INFO server\r\n")
    raw = _recv_all(sock, timeout)
    m = _REDIS_RE.search(raw.decode("latin-1", "replace"))
    if m:
        return "Redis " + m.group(1).strip()
    return "Redis" if raw.startswith(b"$") or raw.startswith(b"+") else None


def _probe_mysql(sock, timeout, banner=None):
    """The server speaks first, and the greeting already carries the version.

    ``banner`` is the greeting already consumed by the scanner: reading it
    again would wait forever for a second one this protocol never sends. It
    is passed as RAW bytes, because the printable-character filter used for
    display would corrupt the binary handshake.
    """
    if isinstance(banner, bytes):
        raw = banner
    elif isinstance(banner, str):
        raw = banner.encode("latin-1", "replace")
    else:
        raw = _recv_all(sock, timeout)
    if len(raw) > 5 and raw[4] == 0x0A:
        payload = raw[5:].split(b"\x00", 1)[0]
        try:
            return "MySQL " + payload.decode("ascii", "replace")
        except Exception:
            return "MySQL"
    if _MYSQL_AUTH.search(raw):
        return "MySQL"
    return None


def _probe_postgres(sock, timeout, banner=None):
    """SSLRequest; an 'S' or 'N' answer confirms PostgreSQL before auth."""
    sock.sendall(struct.pack("!ii", 8, 80877103))
    raw = _recv_all(sock, timeout)
    if not raw:
        return None
    if raw[:1] in (b"S", b"N"):
        return "PostgreSQL (ssl=%s)" % ("yes" if raw[:1] == b"S" else "no")
    if _POSTGRES_RE.search(raw):
        return "PostgreSQL"
    return None


def _probe_imap(sock, timeout, banner=None):
    sock.sendall(b"a001 CAPABILITY\r\n")
    raw = _recv_all(sock, timeout).decode("latin-1", "replace")
    for line in raw.split("\r\n"):
        if line.startswith(("* CAPABILITY", "a001 OK")):
            return line.strip("* ")[:80] or "IMAP"
    return "IMAP" if raw else None


def _probe_pop3(sock, timeout, banner=None):
    sock.sendall(b"CAPA\r\n")
    raw = _recv_all(sock, timeout).decode("latin-1", "replace")
    if "CAPA" in raw or "OK" in raw:
        return "POP3"
    return None


def _probe_smb(sock, timeout, banner=None):
    """SMB1 negotiate dialect request; the answer names the dialect."""
    dialect = b"\xffSMB\x72\x00\x00\x00\x5c\x00\x00\x00\x00\x00\x00\x00" \
              b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
              b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
              b"\x00\x00\x00\x00"
    sock.sendall(dialect)
    raw = _recv_all(sock, timeout)
    if _SMB_RE.search(raw) and len(raw) > 70:
        return "SMB (dialect 0x%02x)" % raw[69]
    return None


def _probe_vnc(sock, timeout, banner=None):
    return banner or None


def _probe_ldap(sock, timeout, banner=None):
    sock.sendall(_ldap_root_dse())
    raw = _recv_all(sock, timeout)
    return "LDAP" if raw[:1] == b"0" else None


def _has_peername(sock):
    try:
        return bool(sock.getpeername())
    except OSError:
        return False


def _recv_all(sock, timeout, limit=8192):
    """Read until the peer stops or the limit is hit; never raises."""
    sock.settimeout(timeout)
    out = b""
    try:
        while len(out) < limit:
            chunk = sock.recv(min(2048, limit - len(out)))
            if not chunk:
                break
            out += chunk
    except (socket.timeout, TimeoutError):
        pass
    except OSError:
        pass
    return out


# Probe registry keyed by service name, so an unusual port that still speaks
# HTTP is still probed as HTTP.
SERVICE_PROBES = {
    "http": _probe_http, "https": _probe_http, "http-alt": _probe_http,
    "https-alt": _probe_http, "redis": _probe_redis, "mysql": _probe_mysql,
    "postgresql": _probe_postgres, "imap": _probe_imap, "imaps": _probe_imap,
    "pop3": _probe_pop3, "pop3s": _probe_pop3,
    "microsoft-ds": _probe_smb, "vnc": _probe_vnc, "ldap": _probe_ldap,
    "ldaps": _probe_ldap,
}


def _version_from_banner(banner, service):
    """Pull a version out of a banner we already received for free."""
    if not banner:
        return None
    text = banner.strip()
    if service == "ssh":
        m = _SSH_RE.match(text)
        return m.group(1) if m else None
    if service in ("ftp", "smtp", "submission", "smtps"):
        m = _BANNER220_RE.match(text)
        return m.group(1) if m else None
    return None


# ---------------------------------------------------------------------------
# Host fingerprinting
#
# A raw SYN probe is the accurate path and needs root/admin. Without it the
# guess is made from banners and is reported as such - a confident-sounding
# OS guess with no evidence behind it is worse than an honest unknown.
# ---------------------------------------------------------------------------

OS_SIGNATURES = (
    # ttl, window, options-order, family
    (64, 65535, (2, 4, 1, 3), "Linux 2.6+ / *BSD"),
    (64, 65535, (2, 4, 1, 3, 34), "Linux 3.x+ / *BSD"),
    (64, 5840, (2, 4, 1, 3), "Linux 2.4"),
    (64, 16384, (2, 4, 1, 3), "Linux 2.2"),
    (128, 65535, (2, 4, 1, 3), "Windows Server 2019+ / 10"),
    (128, 65535, (2, 4, 1, 3, 34), "Windows 7+"),
    (128, 8192, (2, 4, 1, 3, 34), "Windows 2000-2003"),
    (128, 65535, (2, 1, 3, 4), "Windows XP SP2"),
    (255, 65535, (2, 4, 1, 3), "macOS / iOS"),
    (255, 65535, (2, 4, 1, 3, 34), "macOS / iOS (recent)"),
)


def _raw_socket_available():
    if os.name == "nt":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0 if hasattr(os, "geteuid") else False


def _checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def _parse_synack(raw):
    """Pull ttl / window / option-order out of a raw SYN+ACK reply.

    Pure function on bytes so it can be tested without a raw socket.
    """
    if len(raw) < 40:
        return None
    ihl = (raw[0] & 0x0F) * 4
    if ihl < 20 or len(raw) < ihl + 20:
        return None
    ttl = raw[8]
    proto = raw[9]
    if proto != 6:
        return None
    tcp = raw[ihl:]
    window = struct.unpack("!H", tcp[14:16])[0]
    doff = (tcp[12] >> 4) * 4
    opt_bytes = tcp[20:doff]
    order = []
    k = 0
    while k < len(opt_bytes):
        kind = opt_bytes[k]
        if kind == 0:                 # End of Option List
            break
        order.append(kind)
        # NOP is one byte; every other option carries its own length in the
        # second byte. Guessing 2 bytes here mis-parses MSS (4) and WScale
        # (3) and turns a clean signature into nonsense.
        if kind == 1:
            k += 1
        else:
            k += opt_bytes[k + 1] if k + 1 < len(opt_bytes) else 1
    return {"ttl": ttl, "window": window, "options": tuple(order)}


def _match_signature(sig, spec):
    if not spec:
        return None
    ttl, window, options, name = sig
    if spec["ttl"] != ttl:
        return None
    if window and window != spec["window"]:
        return None
    if options and spec["options"] and spec["options"] != options:
        return None
    return name


def _guess_from_banners(entries):
    """Low-confidence OS guess from what the services already told us."""
    joined = " ".join(
        (e.get("version") or "") + " " + (e.get("banner") or "")
        for e in entries if e).lower()
    if "microsoft" in joined or "iis" in joined or "windows" in joined:
        return "Windows (from banner)"
    if "openbsd" in joined or "freebsd" in joined:
        return "*BSD (from banner)"
    if "linux" in joined or "ubuntu" in joined or "debian" in joined:
        return "Linux (from banner)"
    if "darwin" in joined or "macos" in joined:
        return "macOS (from banner)"
    return None


# ---------------------------------------------------------------------------
# Port spec, target spec, validation
# ---------------------------------------------------------------------------

def parse_ports(spec):
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
            if not (1 <= lo <= 65535 and 1 <= hi <= 65535):
                raise ValueError(f"invalid port range '{part}': "
                                 f"both ends must be 1-65535")
            if lo > hi:
                raise ValueError(f"invalid port range '{part}': "
                                 f"{lo} is above {hi}")
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


def _is_ip(text):
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def validate_target(target):
    if _is_ip(target):
        return None
    if HOSTNAME_RE.fullmatch(target):
        return None
    return f"'{target}' is not a valid IP address or hostname"


def _expand_dash_range(text):
    """'10.0.0.1-10.0.0.20' or '10.0.0.1-20' -> list of addresses."""
    lo_s, _, hi_s = text.partition("-")
    lo_s, hi_s = lo_s.strip(), hi_s.strip()
    try:
        lo = ipaddress.ip_address(lo_s)
    except ValueError:
        raise ValueError(f"invalid address '{lo_s}'")
    if not lo.version == 4:
        raise ValueError(f"address ranges are IPv4 only: '{text}'")
    if "." in hi_s:
        try:
            hi = ipaddress.ip_address(hi_s)
        except ValueError:
            raise ValueError(f"invalid address '{hi_s}'")
    else:
        try:
            hi = ipaddress.ip_address(f"{lo_s.rsplit('.', 1)[0]}.{int(hi_s)}")
        except ValueError:
            raise ValueError(f"invalid range end '{hi_s}'")
    if int(hi) < int(lo):
        raise ValueError(f"range '{text}' ends before it starts")
    return [str(ipaddress.IPv4Address(n))
            for n in range(int(lo), int(hi) + 1)]


def expand_targets(spec, max_hosts=MAX_HOSTS_DEFAULT):
    """Turn one target spec into a list of literal IP strings.

    Accepts a hostname, an IP, a CIDR, a dash range, a comma list of any of
    those, or '@file' with one per line. Hostnames are returned as-is and
    resolved later, so a name never has to resolve to expand a CIDR.
    """
    if spec.startswith("@"):
        path = spec[1:]
        try:
            with open(path, "r") as fh:
                lines = [ln.strip() for ln in fh]
        except OSError as e:
            raise ValueError(f"cannot read '{path}': {e}")
        lines = [ln for ln in lines if ln and not ln.startswith("#")]
        if not lines:
            raise ValueError(f"'{path}' has no targets")
        return expand_targets(",".join(lines), max_hosts)

    out = []
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "/" in chunk:
            try:
                net = ipaddress.ip_network(chunk, strict=False)
            except ValueError as e:
                raise ValueError(f"invalid CIDR '{chunk}': {e}")
            if net.num_addresses > max_hosts:
                raise ValueError(
                    f"'{chunk}' is {net.num_addresses} addresses, over "
                    f"--max-hosts {max_hosts}")
            hosts = net.hosts() if net.num_addresses > 2 else net
            out.extend(str(h) for h in hosts)
        elif "-" in chunk and chunk.count(".") >= 2 and _is_ip(
                chunk.partition("-")[0].strip()):
            out.extend(_expand_dash_range(chunk))
        else:
            err = validate_target(chunk.lower())
            if err:
                raise ValueError(err)
            out.append(chunk.lower())
    if not out:
        raise ValueError("empty target spec")
    if len(out) > max_hosts:
        raise ValueError(f"{len(out)} targets exceeds --max-hosts "
                         f"{max_hosts}")
    return out


def normalize_target(target):
    if not target:
        return None
    t = target.strip().lower()
    return t or None


def apply_preset(name):
    if name not in PRESETS:
        raise ValueError(f"unknown preset '{name}': "
                         f"{', '.join(sorted(PRESETS))}")
    ports = PRESETS[name]
    return list(range(1, 65536)) if ports is FULL_RANGE_PORTS else list(ports)


# ---------------------------------------------------------------------------
# Network seams
# ---------------------------------------------------------------------------

def _resolve_host(host, timeout=5.0):
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


def _family_of(ip):
    return socket.AF_INET6 if ":" in ip else socket.AF_INET


def _connect_tcp(ip, port, timeout):
    sock = socket.socket(_family_of(ip), socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((ip, port))
        return sock
    except BaseException:
        sock.close()
        raise


def _grab_banner(sock, timeout=BANNER_TIMEOUT):
    try:
        sock.settimeout(timeout)
        data = sock.recv(512)
        if not data:
            return None
        return _clean_text(data)
    except (socket.timeout, TimeoutError):
        return None
    except OSError:
        return None


def _read_raw_banner(sock, timeout=BANNER_TIMEOUT):
    """Read the greeting WITHOUT the printable-character filter.

    _grab_banner is text-oriented: it replaces every non-printable byte with
    a space, which is right for a banner you are going to show and wrong for
    a binary protocol packet. MySQL's handshake carries its version in bytes
    that the filter destroys, so the greeting for those services is read
    raw and the cleaned-up text is derived only for display.
    """
    try:
        sock.settimeout(timeout)
        return sock.recv(512)
    except (socket.timeout, TimeoutError):
        return b""
    except OSError:
        return b""


def _clean_text(raw):
    if not raw:
        return None
    text = raw.decode("latin-1", "replace")
    text = "".join(ch if ch.isprintable() else " " for ch in text)
    return " ".join(text.split()).strip()[:160] or None


# Server-speaks-first protocols whose greeting is binary.
BINARY_GREETING_SERVICES = {"mysql"}


def _service_probe(sock, port, service, timeout, banner=None):
    """Active protocol probe; returns a version string or None.

    ``banner`` is whatever the passive grab already read. A protocol that
    greets first (MySQL, VNC) would otherwise be probed for a second
    greeting it never sends, and its version would always come back empty.
    """
    probe = SERVICE_PROBES.get(service)
    if probe is None and port in HTTPISH_PORTS:
        probe = _probe_http
    if probe is None:
        return None
    try:
        value = probe(sock, timeout, banner)
    except (socket.timeout, TimeoutError):
        return None
    except OSError:
        return None
    except TypeError:
        try:
            value = probe(sock, timeout)
        except Exception:
            return None
    except Exception:
        return None
    return value.strip() if isinstance(value, str) and value.strip() else None


def _cert_cn(entries):
    try:
        for group in entries:
            for key, val in group:
                if key == "commonName":
                    return val
    except TypeError:
        pass
    return None


def _classify_tls_error(msg):
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


def _verify_message(exc):
    """Human text for a cert failure, on any Python version.

    ``verify_message`` only exists on 3.11+. Reading it unguarded raises
    AttributeError on 3.10, turning "certificate is not trusted" into a
    lost finding.
    """
    parts = []
    for attr in ("verify_message", "reason"):
        value = getattr(exc, attr, None)
        if value:
            parts.append(str(value))
    if not parts:
        parts = [a for a in getattr(exc, "args", ()) if isinstance(a, str)]
    return " ".join(parts) or str(exc)


def _tls_handshake(ip, port, hostname, timeout, verified):
    if verified:
        ctx = ssl.create_default_context()
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection((ip, port), timeout=timeout)
    try:
        with ctx.wrap_socket(raw, server_hostname=hostname) as tls:
            return {"version": tls.version(),
                    "cipher": (tls.cipher() or (None,))[0],
                    "cert": tls.getpeercert() if verified else None}
    finally:
        try:
            raw.close()
        except OSError:
            pass


def _tls_probe(ip, port, hostname, timeout, deep=True):
    info = {"verified": False, "issuer": None, "subject": None, "san": [],
            "not_after": None, "version": None, "cipher": None,
            "verify_error": None, "expired": False}
    try:
        first = _tls_handshake(ip, port, hostname, timeout, verified=True)
        info["version"] = first["version"]
        info["cipher"] = first["cipher"]
        cert = first["cert"]
        if cert:
            info["verified"] = True
            info["issuer"] = _cert_cn(cert.get("issuer"))
            info["subject"] = _cert_cn(cert.get("subject"))
            info["san"] = sorted({v for _t, v in
                                   cert.get("subjectAltName", [])})
            not_after = cert.get("notAfter")
            info["not_after"] = not_after
            if not_after:
                try:
                    expires = datetime.strptime(not_after,
                                                 "%b %d %H:%M:%S %Y GMT")
                    info["expired"] = (
                        datetime.now(timezone.utc).replace(tzinfo=None)
                        > expires)
                except ValueError:
                    pass
        return info
    except ssl.SSLCertVerificationError as e:
        info["verify_error"] = _classify_tls_error(_verify_message(e))
    except (ssl.SSLError, OSError) as e:
        info["verify_error"] = _classify_tls_error(str(e))
    if not deep:
        return info
    try:
        lenient = _tls_handshake(ip, port, hostname, timeout, verified=False)
        info["version"] = info["version"] or lenient["version"]
        info["cipher"] = info["cipher"] or lenient["cipher"]
    except (ssl.SSLError, OSError):
        pass
    return info


def _udp_probe(ip, port, timeout, payload=b""):
    sock = socket.socket(_family_of(ip), socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.send(payload or b"\x00")
        try:
            data = sock.recv(2048)
            return ("open", data[:256])
        except ConnectionRefusedError:
            return ("closed", None)
        except (socket.timeout, TimeoutError):
            return (UDP_VERDICT_ON_TIMEOUT, None)
        except OSError:
            return ("filtered", None)
    except OSError:
        return ("filtered", None)
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _host_alive(ips, timeout):
    for ip in ips:
        for port in (80, 443, 22):
            try:
                sock = _connect_tcp(ip, port, timeout)
            except (socket.timeout, TimeoutError, OSError):
                continue
            else:
                sock.close()
                return True
    return False


def _os_probe(ip, port, timeout):
    """TCP/IP stack fingerprint. Returns (os_name, method, confidence).

    Method is 'syn' when a raw SYN-ACK was read, 'banner' when the guess came
    out of service banners, or None when there is nothing to go on.
    """
    if _raw_socket_available():
        try:
            spec = _synack_signature(ip, port, timeout)
        except OSError:
            spec = None
        if spec:
            name = _match_signature_iter(spec)
            if name:
                return name, "syn", "high"
            return (f"unknown (ttl={spec['ttl']} win={spec['window']} "
                    f"opts={list(spec['options'])})", "syn", "low")
    return None, None, None


def _synack_signature(ip, port, timeout):
    """Raw SYN probe. Needs root/admin; returns parsed SYN-ACK or None.

    Separated from _os_probe so the packet-building side can be exercised
    with a fake raw socket, and so the caller can degrade cleanly.
    """
    if ":" in ip:
        return None
    src_ip = "127.0.0.1"
    try:
        probe_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe_sock.connect((ip, 9))
        src_ip = probe_sock.getsockname()[0]
        probe_sock.close()
    except OSError:
        src_ip = "0.0.0.0"

    local = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    local.settimeout(timeout)
    local.bind(("0.0.0.0", 0))
    local_port = local.getsockname()[1]
    dst = socket.inet_aton(ip)
    src = socket.inet_aton(src_ip)

    tcp = struct.pack("!HHIIBBHHH", local_port, port, 0x12345678, 0, 0x50, 0x02,
                      0xFFFF, 0, 0)
    pseudo = src + dst + struct.pack("!BBH", 0, 6,
                                    len(tcp)) + tcp
    tcp = tcp[:16] + struct.pack("!H", _checksum(pseudo)) + tcp[18:]
    ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0x4000,
                         64, 6, 0, src, dst)
    ip_hdr = ip_hdr[:10] + struct.pack("!H", _checksum(ip_hdr)) + ip_hdr[12:]
    local.sendto(ip_hdr + tcp, (ip, port))

    raw = local.recv(2048)
    local.close()
    return _parse_synack(raw)


def _match_signature_iter(spec):
    for sig in OS_SIGNATURES:
        name = _match_signature(sig, spec)
        if name:
            return name
    return None


# ---------------------------------------------------------------------------
# Traffic control
# ---------------------------------------------------------------------------

class _Pacer:
    """Hold a ports-per-second ceiling with an optional burst allowance.

    A token bucket, not a metronome: ``rate`` is the sustained rate and
    ``min_rate`` is how many starts may happen back to back before the
    limiter engages. jitter spreads each delay by a fraction of the base
    interval so the spacing is not metronomic.
    """

    def __init__(self, rate=0.0, jitter=0.0, min_rate=0, rng=None):
        self.rate = float(rate or 0.0)
        self.jitter = max(0.0, float(jitter or 0.0))
        self.burst = max(0, int(min_rate or 0))
        self._rng = rng or random
        self._lock = threading.Lock()
        self._tokens = float(self.burst)
        self._last = monotonic()

    def _refill(self):
        now = monotonic()
        if self.rate > 0:
            self._tokens = min(float(self.burst),
                               self._tokens + (now - self._last) * self.rate)
        self._last = now

    def wait(self):
        if self.rate <= 0:
            return
        interval = 1.0 / self.rate
        with self._lock:
            self._refill()
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return
            owed = (1.0 - self._tokens) * interval
        if self.jitter:
            owed += self._rng.uniform(-self.jitter * interval,
                                      self.jitter * interval)
        if owed > 0:
            sleep(owed)


def order_ports(ports, shuffle=False, rng=None):
    ports = list(ports)
    if shuffle:
        (rng or random).shuffle(ports)
    return ports


# ---------------------------------------------------------------------------
# Per-port scanning + sweeps
# ---------------------------------------------------------------------------

def _scan_tcp_port(ip, port, timeout, do_probe, do_tls, deep_tls,
                   server_hostname, retries):
    result = {"port": port, "service": SERVICE_NAMES.get(port, "unknown"),
              "state": "filtered", "banner": None, "version": None,
              "tls": None, "product": None, "extrainfo": None}
    sock = None
    for _ in range(max(1, retries)):
        try:
            sock = _connect_tcp(ip, port, timeout)
            break
        except (socket.timeout, TimeoutError):
            return result
        except ConnectionRefusedError:
            result["state"] = "closed"
            return result
        except OSError as e:
            if e.errno in (errno.ECONNREFUSED, errno.EHOSTUNREACH,
                           errno.ENETUNREACH):
                result["state"] = "closed"
            return result
        except Exception:
            return result
    if sock is None:
        return result
    result["state"] = "open"
    version = None
    try:
        if do_probe:
            if do_tls and port in TLS_PORTS:
                result["tls"] = _tls_probe(ip, port, server_hostname, timeout,
                                           deep=deep_tls)
                result["banner"] = _grab_banner(sock, BANNER_TIMEOUT)
            elif result["service"] in BINARY_GREETING_SERVICES:
                # binary greeting: keep the raw bytes for the probe, derive a
                # readable string for display only
                raw = _read_raw_banner(sock, BANNER_TIMEOUT)
                result["banner"] = _clean_text(raw)
                version = _service_probe(sock, port, result["service"],
                                         min(timeout, PROBE_TIMEOUT),
                                         banner=raw)
            else:
                result["banner"] = _grab_banner(sock, BANNER_TIMEOUT)
                version = _version_from_banner(result["banner"],
                                               result["service"])
                if version is None:
                    version = _service_probe(sock, port, result["service"],
                                             min(timeout, PROBE_TIMEOUT),
                                             banner=result["banner"])
            # every branch above can produce a version; storing it here is
            # what keeps a binary-greeting service from computing one and
            # dropping it on the floor
            if version:
                result["version"] = version
                product, _, ver = version.partition(" ")
                result["product"] = product or None
                result["extrainfo"] = ver or None
    except Exception:
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return result


def _scan_udp_port(ip, port, timeout):
    factory = UDP_PROBES.get(port)
    payload = b""
    if factory is not None:
        try:
            payload = factory()
        except Exception:
            payload = b""
    verdict, reply = _udp_probe(ip, port, timeout, payload)
    result = {"port": port, "service": SERVICE_NAMES.get(port, "unknown"),
              "state": verdict, "banner": None, "version": None, "tls": None,
              "product": None, "extrainfo": None, "reply": None,
              "probe": bool(factory)}
    if reply:
        text = reply.decode("latin-1", "replace")
        text = "".join(ch if ch.isprintable() else " " for ch in text)
        result["reply"] = " ".join(text.split()).strip()[:160] or None
        result["version"] = result["reply"]
    return result


def _sweep(tasks, worker, workers, pacer):
    if not tasks:
        return []
    results = [None] * len(tasks)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {}
        for idx, args in enumerate(tasks):
            if pacer is not None:
                pacer.wait()
            futures[ex.submit(worker, *args)] = idx
        for fut in concurrent.futures.as_completed(futures):
            idx = futures[fut]
            try:
                results[idx] = fut.result()
            except Exception:
                results[idx] = None
    return results


def _scan_tcp(ips, ports, timeout, workers, do_probe, do_tls, deep_tls,
              server_hostname, retries, pacer):
    hosts = {ip: {"ip": ip, "open": [], "closed": 0, "filtered": 0}
             for ip in ips}
    tasks = [(ip, p) for ip in ips for p in ports]

    def worker(ip, port):
        return _scan_tcp_port(ip, port, timeout, do_probe, do_tls, deep_tls,
                              server_hostname, retries)

    for (ip, port), result in zip(tasks, _sweep(tasks, worker, workers, pacer)):
        if not result:
            hosts[ip]["filtered"] += 1
        elif result["state"] == "open":
            hosts[ip]["open"].append(result)
        elif result["state"] == "closed":
            hosts[ip]["closed"] += 1
        else:
            hosts[ip]["filtered"] += 1
    for h in hosts.values():
        h["open"].sort(key=lambda r: r["port"])
    return list(hosts.values())


def _scan_udp(ips, ports, timeout, workers, pacer):
    hosts = {ip: {"ip": ip, "open": [], "closed": 0, "filtered": 0,
                  "udp_open": 0, "udp_open_filtered": 0}
             for ip in ips}
    tasks = [(ip, p) for ip in ips for p in ports]

    def worker(ip, port):
        return _scan_udp_port(ip, port, timeout)

    for (ip, port), result in zip(tasks, _sweep(tasks, worker, workers, pacer)):
        if not result:
            hosts[ip]["filtered"] += 1
            continue
        state = result["state"]
        if state == "open":
            hosts[ip]["open"].append(result)
            hosts[ip]["udp_open"] += 1
        elif state == "closed":
            hosts[ip]["closed"] += 1
        else:
            hosts[ip]["filtered"] += 1
            if state == UDP_VERDICT_ON_TIMEOUT:
                hosts[ip]["udp_open_filtered"] += 1
    for h in hosts.values():
        h["open"].sort(key=lambda r: r["port"])
    return list(hosts.values())


# --------------------------------------------------------------------------
# Findings + orchestration
# --------------------------------------------------------------------------

def _build_findings(hosts, ports_scanned, protocol):
    findings = []
    for h in hosts:
        plain = [o for o in h["open"] if o["port"] in PLAINTEXT_PORTS]
        if plain:
            labels = ", ".join(f"{o['service']} ({o['port']})" for o in plain)
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
        if h.get("udp_open_filtered"):
            findings.append(
                f"{h['udp_open_filtered']} UDP port(s) on {h['ip']} "
                f"silently dropped the probe: open|filtered, not confirmed")
        versions = [o for o in h["open"] if o.get("version")]
        if versions:
            known = ", ".join(
                f"{o['service']} {o['version']}" for o in versions[:6])
            findings.append(f"{len(versions)} service(s) version-identified "
                            f"on {h['ip']}: {known}")
        if h.get("os"):
            findings.append(f"Host {h['ip']} looks like {h['os']} "
                            f"(via {h.get('os_method')}, "
                            f"{h.get('os_confidence')} confidence)")
    total_open = sum(len(h["open"]) for h in hosts)
    if total_open == 0 and ports_scanned:
        findings.append(f"No open {protocol.upper()} port(s) found among "
                        f"{ports_scanned} scanned")
    return findings


def scan_target(target, **kw):
    """Scan one target (IP or hostname). Returns the payload for that host."""
    ips = _resolve_host(target)
    return scan_ips(ips, target, **kw)


def scan_ips(ips, label="", **kw):
    """Scan a pre-resolved IP list. The unit every other path funnels into."""
    protocol = (kw.get("protocol") or "tcp").lower()
    ports = kw.get("ports")
    udp_ports = kw.get("udp_ports")
    timeout = kw.get("timeout", 2.0)
    workers = kw.get("workers", 50)
    do_probe = kw.get("do_probe", True)
    do_tls = kw.get("do_tls", True)
    deep_tls = kw.get("deep_tls", True)
    retries = kw.get("retries", 1)
    skip_hostdown = kw.get("skip_hostdown", False)
    fingerprint = kw.get("os_fingerprint", False)
    pacer = kw.get("pacer")
    rng = kw.get("rng") or random
    shuffle = kw.get("shuffle", False)

    if protocol == "both":
        tcp_list = list(ports or DEFAULT_PORTS)
        udp_list = list(udp_ports if udp_ports is not None
                        else DEFAULT_UDP_PORTS)
    elif protocol == "udp":
        tcp_list = []
        udp_list = list(udp_ports if udp_ports is not None
                        else DEFAULT_UDP_PORTS)
    else:
        tcp_list = list(ports or DEFAULT_PORTS)
        udp_list = []

    start = monotonic()
    skipped = False
    if skip_hostdown:
        try:
            alive = _host_alive(ips, min(timeout, 1.5))
        except Exception:
            alive = True
        skipped = not alive

    scan_ports = tcp_list if protocol == "tcp" else (
        udp_list if protocol == "udp" else tcp_list + udp_list)
    hosts = []
    if not skipped:
        if tcp_list:
            hosts = _scan_tcp(ips, order_ports(tcp_list, shuffle, rng), timeout,
                              workers, do_probe, do_tls, deep_tls, label or
                              ips[0], retries, pacer)
        if udp_list:
            udp_hosts = _scan_udp(ips, order_ports(udp_list, shuffle, rng),
                                  timeout, workers, pacer)
            merged = {h["ip"]: h for h in hosts}
            for h in udp_hosts:
                if h["ip"] in merged:
                    tgt = merged[h["ip"]]
                    tgt["open"].extend(h["open"])
                    tgt["closed"] += h["closed"]
                    tgt["filtered"] += h["filtered"]
                    tgt["udp_open"] = h["udp_open"]
                    tgt["udp_open_filtered"] = h["udp_open_filtered"]
                    tgt["open"].sort(key=lambda r: r["port"])
                else:
                    merged[h["ip"]] = h
            hosts = list(merged.values())
        if fingerprint:
            for h in hosts:
                guess, method, conf = _os_probe(h["ip"], 80, min(timeout, 2.0))
                if not guess:
                    guess = _guess_from_banners(h["open"])
                    method = "banner" if guess else None
                    conf = "low" if guess else None
                if guess:
                    h["os"] = guess
                    h["os_method"] = method
                    h["os_confidence"] = conf

    return {
        "target": label,
        "status": "skipped" if skipped else "ok",
        "elapsed_ms": round((monotonic() - start) * 1000),
        "resolution": {"ips": ips},
        "ports_scanned": len(scan_ports),
        "scan": {"ports": scan_ports, "tcp_ports": len(tcp_list),
                 "udp_ports": len(udp_list), "timeout": timeout,
                 "workers": workers, "do_probe": do_probe, "do_tls": do_tls,
                 "retries": retries,
                 "rate": kw.get("rate", 0.0),
                 "jitter": kw.get("jitter", 0.0),
                 "shuffle": shuffle},
        "hosts": hosts,
    }


def run(target, ports=None, timeout=2.0, workers=50, do_probe=True,
        protocol="tcp", udp_ports=None, rate=0.0, jitter=0.0, shuffle=False,
        retries=1, do_tls=True, deep_tls=True, skip_hostdown=False,
        seed=None, os_fingerprint=False, min_rate=None):
    """Full scan; returns the JSON payload.

    Payload shape mirrors the sibling modules:
      target -> status -> elapsed_ms -> resolution -> ports_scanned -> scan
      -> hosts -> findings -> summary
    """
    target = normalize_target(target)
    if target is None:
        return {"status": "error", "error": "No target provided."}
    if protocol not in ("tcp", "udp", "both"):
        return {"status": "error",
                "error": f"unknown protocol '{protocol}': tcp, udp, both"}

    # expand_targets validates each piece, and the whole spec may legitimately
    # be a comma list / CIDR that is not itself a hostname.
    start = monotonic()
    try:
        targets = expand_targets(target)
    except ValueError as e:
        return {"status": "error", "error": str(e)}

    rng = random.Random(seed) if seed is not None else random
    burst = (int(min_rate) if min_rate else kw_burst(rate))
    pacer = _Pacer(rate=rate, jitter=jitter, min_rate=burst, rng=rng)
    hosts = []
    resolved = []
    errors = []
    any_skipped = False
    for one in targets:
        try:
            payload = scan_target(
                one, ports=ports, udp_ports=udp_ports, protocol=protocol,
                timeout=timeout, workers=workers, do_probe=do_probe,
                do_tls=do_tls, deep_tls=deep_tls, retries=retries,
                skip_hostdown=skip_hostdown, os_fingerprint=os_fingerprint,
                pacer=pacer, rng=rng, shuffle=shuffle,
                rate=rate, jitter=jitter)
        except socket.gaierror as e:
            errors.append(f"cannot resolve '{one}': {e}")
            continue
        resolved.extend(payload["resolution"]["ips"])
        hosts.extend(payload["hosts"])
        any_skipped = any_skipped or payload["status"] == "skipped"

    scan_ports = ports if ports is not None else (
        udp_ports if protocol == "udp" else DEFAULT_PORTS)
    findings = _build_findings(hosts, len(scan_ports), protocol)
    total_open = sum(len(h["open"]) for h in hosts)
    total_closed = sum(h["closed"] for h in hosts)
    total_filtered = sum(h["filtered"] for h in hosts)
    status = "ok"
    if not hosts and errors:
        status = "error"
    elif any_skipped and not any(h["open"] for h in hosts):
        status = "skipped"
    summary = (f"{target}: {len(targets)} target(s), {len(resolved)} "
               f"address(es), {len(scan_ports)} {protocol} port(s) "
               f"scanned - {total_open} open, {total_closed} closed, "
               f"{total_filtered} filtered")
    out = {
        "target": target,
        "status": status,
        "elapsed_ms": round((monotonic() - start) * 1000),
        "resolution": {"ips": resolved, "targets": targets},
        "ports_scanned": len(scan_ports),
        "scan": {"ports": scan_ports, "tcp_ports": len(ports or []),
                 "udp_ports": len(udp_ports or []), "timeout": timeout,
                 "workers": workers, "do_probe": do_probe, "do_tls": do_tls,
                 "rate": rate, "jitter": jitter, "shuffle": shuffle,
                 "retries": retries},
        "hosts": hosts,
        "findings": findings,
        "summary": summary,
    }
    if errors:
        out["errors"] = errors
    return out


def kw_burst(rate):
    """Default burst allowance: a quarter of the sustained rate, at least 1."""
    if not rate:
        return 0
    return max(1, int(rate / 4))


# ---------------------------------------------------------------------------
# nmap-compatible XML
# ---------------------------------------------------------------------------

_NMAP_STATE = {"open": "open", "closed": "closed",
               "filtered": "filtered",
               UDP_VERDICT_ON_TIMEOUT: "open|filtered"}


def _xml_bool(v):
    return "1" if v else "0"


def render_xml(payload, cmdline="port_scanner"):
    """Render a run() payload as nmap-compatible XML.

    Same element names and attribute vocabulary nmap emits, so an existing
    consumer (Metasploit, a SIEM parser, a custom report) can read it
    without a special case. This is what makes the output reusable instead
    of only readable.
    """
    start = payload.get("elapsed_ms", 0) / 1000.0
    root = ET.Element("nmaprun", {
        "scanner": "port_scanner", "args": cmdline,
        "start": str(int(time()) - int(start)),
        "version": "1.0", "outputxml": "3.13"})
    ET.SubElement(root, "verbose", {"level": "0"})
    ET.SubElement(root, "debugging", {"level": "0"})

    for h in payload.get("hosts") or []:
        host = ET.SubElement(root, "host", {
            "starttime": str(int(time()) - int(start)),
            "endtime": str(int(time()))})
        ET.SubElement(host, "status", {"state": "up", "reason": "syn-ack"})
        addr_type = "ipv6" if ":" in h["ip"] else "ipv4"
        ET.SubElement(host, "address", {"addr": h["ip"], "addrtype": addr_type})

        extra = []
        if h.get("os"):
            ET.SubElement(host, "osmatch", {"name": h["os"],
                                            "accuracy": "100" if
                                            h.get("os_confidence") == "high"
                                            else "85",
                                            "method": h.get("os_method",
                                                            "banner")})
        ports_el = ET.SubElement(host, "ports")
        buckets = {}
        for o in h["open"]:
            buckets.setdefault("open", []).append(o)
        for count_key, tag in (("closed", "closed"), ("filtered", "filtered")):
            if h.get(count_key):
                extra.append((tag, h[count_key]))
        for tag, count in extra:
            ep = ET.SubElement(ports_el, "extraports", {"state": tag,
                                                        "count": str(count)})
            ET.SubElement(ep, "extrareasons", {"reason": "resets",
                                               "count": str(count)})
        for o in h["open"]:
            is_udp = o.get("probe") is not None
            proto = "udp" if is_udp else "tcp"
            pel = ET.SubElement(ports_el, "port", {"protocol": proto,
                                                   "portid": str(o["port"])})
            ET.SubElement(pel, "state", {
                "state": _NMAP_STATE.get(o["state"], o["state"]),
                "reason": "udp-response" if is_udp else "syn-ack",
                "reason_ttl": "64"})
            attrs = {"name": o["service"], "method": "probed"
                     if o.get("version") else "table",
                     "conf": "10"}
            if o.get("product"):
                attrs["product"] = o["product"]
            if o.get("extrainfo"):
                attrs["extrainfo"] = o["extrainfo"]
            ET.SubElement(pel, "service", attrs)
        ET.SubElement(host, "times", {"srtt": "1000", "rttvar": "1000",
                                      "to": "100000"})

    total_open = sum(len(h["open"]) for h in payload.get("hosts") or [])
    total_closed = sum(h["closed"] for h in payload.get("hosts") or [])
    total_filtered = sum(h["filtered"] for h in payload.get("hosts") or [])
    runstats = ET.SubElement(root, "runstats")
    ET.SubElement(runstats, "finished", {
        "time": str(int(start * 1000)), "timestr": datetime.now().isoformat(),
        "elapsed": f"{start:.2f}", "summary": payload.get("summary", ""),
        "exit": "success"})
    ET.SubElement(runstats, "hosts", {
        "up": str(len(payload.get("hosts") or [])), "down": "0",
        "total": str(len(payload.get("hosts") or []))})
    ET.SubElement(runstats, "ports", {"open": str(total_open),
                                      "closed": str(total_closed),
                                      "filtered": str(total_filtered)})
    ET.indent(root, space="  ")
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + \
        ET.tostring(root, encoding="unicode")


# ---------------------------------------------------------------------------
# Human-readable renderer
# ---------------------------------------------------------------------------

def _open_detail(o):
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
    if o.get("version"):
        return o["version"]
    if o.get("reply"):
        return f"reply: {o['reply']}"
    if o.get("state") == UDP_VERDICT_ON_TIMEOUT:
        return "no reply (open|filtered)"
    banner = o.get("banner")
    return f"banner: {banner}" if banner else "open (no banner)"


def render(payload):
    if payload.get("status") == "error":
        head = (f"Port Scanner: {payload.get('target')}"
                if payload.get("target") else "Port Scanner")
        return (f"{head} failed" + chr(10) +
                f"  Error: {payload.get('error') or 'unknown error'}")

    rows = [("Status", payload["status"]),
            ("Elapsed", f"{payload['elapsed_ms']} ms"),
            ("Addresses", ", ".join(payload["resolution"]["ips"])),
            ("Ports", f"{payload['ports_scanned']} scanned "
                      f"(timeout {payload['scan']['timeout']}s, "
                      f"{payload['scan']['workers']} workers, "
                      f"rate {payload['scan'].get('rate') or 'unlimited'}/s)")]
    for h in payload["hosts"]:
        rows.append((f"Host {h['ip']}",
                     f"{len(h['open'])} open, {h['closed']} closed, "
                     f"{h['filtered']} filtered"
                     + (f", os: {h['os']}" if h.get("os") else "")))

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

    for e in payload.get("errors") or []:
        lines.append("")
        lines.append(f"  Error: {e}")

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
# CLI
# ---------------------------------------------------------------------------

_USAGE = """Usage: python -m modules.network.port_scanner [flags] <target>

  Target may be a hostname, an IP, a CIDR (10.0.0.0/24), a dash range
  (10.0.0.1-20), a comma list of any of those, or @file with one per line.

  --json, -j            emit the raw payload as JSON
  --xml FILE            write nmap-compatible XML
  --ports SPEC          '22', '80,443' or '8000-9000' (mixed allowed)
  --preset NAME         top | quick | standard | full
  --max-ports N         refuse a port list larger than N (default 4096)
  --yes-full-sweep      allow more than --max-ports ports
  --max-hosts N         refuse a target list larger than N (default 256)
  --protocol P          tcp (default) | udp | both
  --udp-ports SPEC      UDP port list when --protocol is udp/both
  --timeout SEC         per-attempt connect timeout (default 2.0)
  --workers N           concurrent sockets (default 50)
  --rate N              cap starts at N ports/second (0 = unlimited)
  --min-rate N          allow N back-to-back starts before the cap bites
  --jitter F            spread each delay by +/-F of the interval (0-1)
  --shuffle             randomise port order within the budget
  --retries N           attempts per port before calling it filtered
  --no-probe            skip banner and version probes
  --no-tls              do not probe TLS certificates
  --quick-tls           one TLS handshake, no detail pass
  --skip-hostdown       skip a host that answers nothing
  --os                  fingerprint the host stack (needs root/admin)
  --seed N              make --shuffle and --jitter reproducible
  --help, -h            this message
"""


def _need_value(argv, i, flag, cast, label):
    if i + 1 >= len(argv):
        raise ValueError(f"{flag} requires {label}")
    raw = argv[i + 1]
    try:
        return cast(raw)
    except (TypeError, ValueError):
        raise ValueError(f"Invalid {flag} '{raw}'")


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    o = {"want_json": False, "xml": None, "ports_spec": None,
         "udp_spec": None, "preset": None, "max_ports": MAX_PORTS_DEFAULT,
         "yes_full": False, "max_hosts": MAX_HOSTS_DEFAULT,
         "protocol": "tcp", "timeout": 2.0, "workers": 50, "rate": 0.0,
         "min_rate": None, "jitter": 0.0, "shuffle": False, "retries": 1,
         "do_probe": True, "do_tls": True, "deep_tls": True,
         "skip_hostdown": False, "os_fingerprint": False, "seed": None}
    positional = []
    i = 0
    while i < len(argv):
        arg = argv[i]
        try:
            if arg in ("-h", "--help"):
                print(_USAGE)
                return 0
            if arg in ("--json", "-j"):
                o["want_json"] = True
            elif arg == "--xml":
                o["xml"] = _need_value(argv, i, "--xml", str, "a filename")
                i += 1
            elif arg == "--ports":
                o["ports_spec"] = _need_value(argv, i, "--ports", str,
                                              "a spec like '80,443'")
                i += 1
            elif arg == "--udp-ports":
                o["udp_spec"] = _need_value(argv, i, "--udp-ports", str,
                                            "a spec like '53,123'")
                i += 1
            elif arg == "--preset":
                o["preset"] = _need_value(argv, i, "--preset", str,
                                          "a preset name")
                i += 1
            elif arg == "--protocol":
                o["protocol"] = _need_value(argv, i, "--protocol", str,
                                            "tcp, udp or both").lower()
                i += 1
            elif arg == "--max-ports":
                o["max_ports"] = _need_value(argv, i, "--max-ports", int,
                                             "a number")
                i += 1
            elif arg == "--max-hosts":
                o["max_hosts"] = _need_value(argv, i, "--max-hosts", int,
                                             "a number")
                i += 1
            elif arg == "--timeout":
                o["timeout"] = _need_value(argv, i, "--timeout", float,
                                           "seconds")
                i += 1
            elif arg == "--workers":
                o["workers"] = _need_value(argv, i, "--workers", int,
                                           "a positive integer")
                if o["workers"] < 1:
                    raise ValueError("--workers must be at least 1")
                i += 1
            elif arg == "--rate":
                o["rate"] = _need_value(argv, i, "--rate", float,
                                        "ports per second")
                if o["rate"] < 0:
                    raise ValueError("--rate cannot be negative")
                i += 1
            elif arg == "--min-rate":
                o["min_rate"] = _need_value(argv, i, "--min-rate", int,
                                            "a positive integer")
                if o["min_rate"] < 1:
                    raise ValueError("--min-rate must be at least 1")
                i += 1
            elif arg == "--jitter":
                o["jitter"] = _need_value(argv, i, "--jitter", float,
                                          "a fraction")
                if not 0 <= o["jitter"] <= 1:
                    raise ValueError("--jitter must be between 0 and 1")
                i += 1
            elif arg == "--retries":
                o["retries"] = _need_value(argv, i, "--retries", int,
                                           "a positive integer")
                if o["retries"] < 1:
                    raise ValueError("--retries must be at least 1")
                i += 1
            elif arg == "--seed":
                o["seed"] = _need_value(argv, i, "--seed", int, "a number")
                i += 1
            elif arg == "--yes-full-sweep":
                o["yes_full"] = True
            elif arg == "--shuffle":
                o["shuffle"] = True
            elif arg == "--no-probe":
                o["do_probe"] = False
            elif arg == "--no-tls":
                o["do_tls"] = False
            elif arg == "--quick-tls":
                o["deep_tls"] = False
            elif arg == "--skip-hostdown":
                o["skip_hostdown"] = True
            elif arg == "--os":
                o["os_fingerprint"] = True
            elif arg.startswith("-"):
                print(f"Unknown option: {arg}", file=sys.stderr)
                print(_USAGE, file=sys.stderr)
                return 2
            else:
                positional.append(arg)
        except ValueError as e:
            print(str(e), file=sys.stderr)
            return 2
        i += 1

    if not positional:
        print(_USAGE)
        return 1
    if len(positional) > 1:
        print("One target at a time (comma-separate them instead).",
              file=sys.stderr)
        print(_USAGE, file=sys.stderr)
        return 2

    ports = None
    if o["ports_spec"]:
        try:
            ports = parse_ports(o["ports_spec"])
        except ValueError as e:
            print(f"Invalid --ports spec: {e}", file=sys.stderr)
            return 2
    udp_ports = None
    if o["udp_spec"]:
        try:
            udp_ports = parse_ports(o["udp_spec"])
        except ValueError as e:
            print(f"Invalid --udp-ports spec: {e}", file=sys.stderr)
            return 2

    if o["preset"] and ports:
        print("--preset and --ports are two ways to pick the same list: "
              "pick one.", file=sys.stderr)
        return 2
    if o["preset"]:
        try:
            ports = apply_preset(o["preset"])
        except ValueError as e:
            print(str(e), file=sys.stderr)
            return 2

    if ports is not None and len(ports) > o["max_ports"] and not o["yes_full"]:
        print(f"{len(ports)} ports exceeds --max-ports {o['max_ports']}. "
              f"Narrow the range, raise the ceiling with --max-ports, or "
              f"pass --yes-full-sweep if the target is yours and you mean "
              f"it.", file=sys.stderr)
        return 2

    payload = run(positional[0], ports=ports, timeout=o["timeout"],
                  workers=o["workers"], do_probe=o["do_probe"],
                  protocol=o["protocol"], udp_ports=udp_ports,
                  rate=o["rate"], min_rate=o["min_rate"], jitter=o["jitter"],
                  shuffle=o["shuffle"], retries=o["retries"],
                  do_tls=o["do_tls"], deep_tls=o["deep_tls"],
                  skip_hostdown=o["skip_hostdown"], seed=o["seed"],
                  os_fingerprint=o["os_fingerprint"])

    if o["xml"]:
        cmdline = " ".join(["port_scanner"] + list(argv))
        try:
            with open(o["xml"], "w", encoding="utf-8") as fh:
                fh.write(render_xml(payload, cmdline))
        except OSError as e:
            print(f"Cannot write '{o['xml']}': {e}", file=sys.stderr)
            return 2
        print(f"XML written to {o['xml']}")

    if o["want_json"]:
        print(json.dumps(payload, indent=2))
    else:
        print(render(payload))
    return 0 if payload.get("status") in ("ok", "skipped") else 1


if __name__ == "__main__":
    sys.exit(main())