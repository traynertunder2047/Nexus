"""Offline tests for the port scanner seams. No sockets, no network.

Every test monkeypatches a named seam, which is the point of keeping the
I/O isolated: the whole module is exercisable on a laptop in flight mode.

Run from the repo root:

    python -m pytest tests/test_port_scanner.py -q

The repo has no CI yet, so please run this after pulling. It needs only
pytest and takes under a second: no network, no privileges, no fixtures.
"""

import socket
import ssl
import struct
import sys
import types

import pytest

# Imported as a package member: the module uses a relative import
# (..usage), which needs its parent packages on sys.path -- run from the
# repo root (python -m pytest) as the docstring says.
import modules.network.port_scanner as ps


# --------------------------------------------------------------------------
# port spec parsing
# --------------------------------------------------------------------------

def test_range_rejects_port_zero():
    # regression: '0-100' used to be accepted and scanned port 0
    with pytest.raises(ValueError, match="both ends must be"):
        ps.parse_ports("0-100")


def test_range_rejects_inverted():
    with pytest.raises(ValueError, match="is above"):
        ps.parse_ports("80-22")


def test_range_rejects_over_65535():
    with pytest.raises(ValueError):
        ps.parse_ports("1-70000")


def test_single_port_rejects_zero():
    with pytest.raises(ValueError):
        ps.parse_ports("0")


def test_mixed_spec_parses():
    assert ps.parse_ports("22,80,8000-8002") == [22, 80, 8000, 8001, 8002]


# --------------------------------------------------------------------------
# presets
# --------------------------------------------------------------------------

def test_preset_top_is_small():
    assert len(ps.apply_preset("top")) == len(ps.TOP_PORTS)


def test_preset_full_is_whole_range():
    assert ps.apply_preset("full") == list(range(1, 65536))


def test_unknown_preset_lists_options():
    with pytest.raises(ValueError, match="top"):
        ps.apply_preset("nope")


# --------------------------------------------------------------------------
# TCP classification
# --------------------------------------------------------------------------

def _patch_connect(monkeypatch, behaviour):
    def fake(ip, port, timeout):
        return behaviour(port)
    monkeypatch.setattr(ps, "_connect_tcp", fake)


def test_tcp_refused_is_closed(monkeypatch):
    def boom(port):
        raise ConnectionRefusedError()
    _patch_connect(monkeypatch, boom)
    r = ps._scan_tcp_port("1.2.3.4", 80, 1.0, False, False, False, "h", 1)
    assert r["state"] == "closed"


def test_tcp_timeout_is_filtered(monkeypatch):
    def timeout(port):
        raise socket.timeout()
    _patch_connect(monkeypatch, timeout)
    r = ps._scan_tcp_port("1.2.3.4", 80, 1.0, False, False, False, "h", 1)
    assert r["state"] == "filtered"


def test_tcp_open_without_probe(monkeypatch):
    class Sock:
        def close(self):
            pass
    _patch_connect(monkeypatch, lambda port: Sock())
    r = ps._scan_tcp_port("1.2.3.4", 22, 1.0, False, False, False, "h", 1)
    assert r["state"] == "open"
    assert r["service"] == "ssh"


def test_banner_uses_its_own_short_timeout(monkeypatch):
    # regression: a banner recv used to inherit the full connect timeout
    seen = {}

    class Sock:
        def settimeout(self, t):
            seen["t"] = t
        def recv(self, n):
            raise socket.timeout()
        def close(self):
            pass

    ps._grab_banner(Sock())
    assert seen["t"] == ps.BANNER_TIMEOUT
    assert ps.BANNER_TIMEOUT < 1.0


def test_banner_swallows_oserror():
    class Sock:
        def settimeout(self, t):
            pass
        def recv(self, n):
            raise OSError("reset")
        def close(self):
            pass

    assert ps._grab_banner(Sock()) is None


def test_retries_gives_up_and_stays_filtered(monkeypatch):
    calls = []

    def timeout(port):
        calls.append(port)
        raise socket.timeout()
    _patch_connect(monkeypatch, timeout)
    r = ps._scan_tcp_port("1.2.3.4", 80, 1.0, False, False, False, "h", 3)
    assert r["state"] == "filtered"
    assert len(calls) == 1     # timeouts are not retried, they are answers


# --------------------------------------------------------------------------
# UDP classification
# --------------------------------------------------------------------------

def test_udp_reply_is_open(monkeypatch):
    monkeypatch.setattr(ps, "_udp_probe",
                        lambda ip, p, t, pl: ("open", b"VERSION"))
    r = ps._scan_udp_port("1.2.3.4", 53, 1.0)
    assert r["state"] == "open"
    assert r["reply"] == "VERSION"


def test_udp_icmp_refused_is_closed(monkeypatch):
    monkeypatch.setattr(ps, "_udp_probe",
                        lambda ip, p, t, pl: ("closed", None))
    r = ps._scan_udp_port("1.2.3.4", 53, 1.0)
    assert r["state"] == "closed"


def test_udp_silence_is_not_reported_as_open(monkeypatch):
    # the important one: a firewalled port is not proof of a live service
    monkeypatch.setattr(ps, "_udp_probe",
                        lambda ip, p, t, pl: (ps.UDP_VERDICT_ON_TIMEOUT, None))
    r = ps._scan_udp_port("1.2.3.4", 161, 1.0)
    assert r["state"] == ps.UDP_VERDICT_ON_TIMEOUT
    assert r["state"] != "open"


def test_udp_probe_factory_is_used():
    captured = {}
    orig = ps._udp_probe

    def fake(ip, port, timeout, payload):
        captured["payload"] = payload
        return ("open", b"x")
    try:
        ps._udp_probe = fake
        ps._scan_udp_port("1.2.3.4", 53, 1.0)
    finally:
        ps._udp_probe = orig
    assert captured["payload"], "port 53 must send a real DNS query"


def test_dns_probe_is_wellformed():
    q = ps._dns_version_bind_query()
    assert q[0:2] == b"\x00\x1d"          # length prefix
    assert b"version" in q and b"bind" in q


def test_ssdp_probe_is_http():
    assert ps._ssdp_msearch().startswith(b"M-SEARCH * HTTP/1.1")


# --------------------------------------------------------------------------
# TLS
# --------------------------------------------------------------------------

def test_verify_message_survives_missing_attribute():
    # Python 3.10 has no .verify_message; reading it blind killed the finding
    exc = ssl.SSLCertVerificationError("self-signed certificate")
    assert ps._verify_message(exc) == "self-signed certificate"


def test_verify_message_prefers_311_attribute():
    exc = ssl.SSLCertVerificationError("cert")
    exc.verify_message = "hostname mismatch"
    assert ps._verify_message(exc) == "hostname mismatch"


def test_verified_handshake_is_a_single_connection(monkeypatch):
    # regression: every untrusted cert used to cost two handshakes
    calls = []

    def fake(ip, port, hostname, timeout, verified):
        calls.append(verified)
        if verified:
            raise ssl.SSLCertVerificationError("self-signed certificate")
        return {"version": "TLSv1.3", "cipher": "X", "cert": None}

    monkeypatch.setattr(ps, "_tls_handshake", fake)
    info = ps._tls_probe("1.2.3.4", 443, "h", 1.0, deep=False)
    assert calls == [True]
    assert info["verify_error"] == "self-signed certificate"


def test_tls_detail_pass_is_opt_in(monkeypatch):
    calls = []

    def fake(ip, port, hostname, timeout, verified):
        calls.append(verified)
        if verified:
            raise ssl.SSLCertVerificationError("expired")
        return {"version": "TLSv1.2", "cipher": "Y", "cert": None}

    monkeypatch.setattr(ps, "_tls_handshake", fake)
    info = ps._tls_probe("1.2.3.4", 443, "h", 1.0, deep=True)
    assert calls == [True, False]
    assert info["cipher"] == "Y"


def test_tls_never_raises(monkeypatch):
    def boom(*a, **k):
        raise ssl.SSLError("handshake failure")
    monkeypatch.setattr(ps, "_tls_handshake", boom)
    info = ps._tls_probe("1.2.3.4", 443, "h", 1.0)
    assert info["verified"] is False
    assert info["verify_error"]


# --------------------------------------------------------------------------
# traffic control
# --------------------------------------------------------------------------

def test_pacer_is_a_noop_when_unlimited():
    p = ps._Pacer(rate=0)
    p.wait()
    p.wait()


def test_pacer_spaces_starts(monkeypatch):
    slept = []
    clock = {"t": 100.0}
    monkeypatch.setattr(ps, "monotonic", lambda: clock["t"])

    def fake_sleep(d):
        slept.append(d)
        clock["t"] += d
    monkeypatch.setattr(ps, "sleep", fake_sleep)

    p = ps._Pacer(rate=10.0)      # 100ms apart
    for _ in range(3):
        p.wait()
    # rate is the whole point: at 10/s three starts cannot be back to back
    assert sum(slept) > 0.2


def test_jitter_stays_within_bounds(monkeypatch):
    monkeypatch.setattr(ps, "sleep", lambda d: None)
    p = ps._Pacer(rate=10.0, jitter=0.5)
    assert p.jitter == 0.5
    assert ps.main(["x", "--jitter", "5"]) == 2


def test_shuffle_is_reproducible_with_seed():
    a = ps.order_ports([1, 2, 3, 4, 5], shuffle=True, rng=__import__("random").Random(7))
    b = ps.order_ports([1, 2, 3, 4, 5], shuffle=True, rng=__import__("random").Random(7))
    assert a == b
    assert sorted(a) == [1, 2, 3, 4, 5]


def test_order_ports_keeps_order_when_pinned():
    assert ps.order_ports([3, 1, 2], shuffle=False) == [3, 1, 2]


# --------------------------------------------------------------------------
# host discovery
# --------------------------------------------------------------------------

def test_host_alive_true(monkeypatch):
    class S:
        def close(self):
            pass
    monkeypatch.setattr(ps, "_connect_tcp", lambda ip, p, t: S())
    assert ps._host_alive(["1.2.3.4"], 0.1) is True


def test_host_alive_false(monkeypatch):
    def boom(ip, p, t):
        raise socket.timeout()
    monkeypatch.setattr(ps, "_connect_tcp", boom)
    assert ps._host_alive(["1.2.3.4"], 0.1) is False


# --------------------------------------------------------------------------
# orchestration
# --------------------------------------------------------------------------

def _stub_resolve(monkeypatch, ips=("1.2.3.4",)):
    monkeypatch.setattr(ps, "_resolve_host", lambda h, timeout=5.0: list(ips))


def test_run_rejects_unknown_protocol(monkeypatch):
    _stub_resolve(monkeypatch)
    out = ps.run("example.com", protocol="carrier-pigeon")
    assert out["status"] == "error"


def test_run_requires_target():
    assert ps.run("")["status"] == "error"
    assert ps.run("  ")["status"] == "error"


def test_run_rejects_bad_hostname():
    assert ps.run("not a host")["status"] == "error"


def test_run_merges_tcp_and_udp(monkeypatch):
    _stub_resolve(monkeypatch)
    monkeypatch.setattr(ps, "_scan_tcp", lambda *a, **k: [
        {"ip": "1.2.3.4", "open": [], "closed": 1, "filtered": 0}])
    monkeypatch.setattr(ps, "_scan_udp", lambda *a, **k: [
        {"ip": "1.2.3.4", "open": [{"port": 53, "service": "domain",
                                    "state": "open", "banner": None,
                                    "tls": None, "reply": "ok",
                                    "probe": True}],
         "closed": 0, "filtered": 0, "udp_open": 1, "udp_open_filtered": 0}])
    out = ps.run("example.com", ports=[80], protocol="both", udp_ports=[53])
    assert out["status"] == "ok"
    assert out["scan"]["tcp_ports"] == 1
    assert out["scan"]["udp_ports"] == 1
    assert out["hosts"][0]["udp_open"] == 1


def test_run_skips_down_host(monkeypatch):
    _stub_resolve(monkeypatch)
    monkeypatch.setattr(ps, "_host_alive", lambda ips, t: False)
    out = ps.run("example.com", ports=[80], skip_hostdown=True)
    assert out["status"] == "skipped"
    assert out["hosts"] == []


def test_run_reports_unresolvable_target(monkeypatch):
    def boom(h, timeout=5.0):
        raise socket.gaierror("nope")
    monkeypatch.setattr(ps, "_resolve_host", boom)
    out = ps.run("does-not-exist.invalid", ports=[80])
    assert out["status"] == "error"
    assert out["errors"]


def test_run_does_not_skip_when_probe_breaks(monkeypatch):
    _stub_resolve(monkeypatch)

    def boom(ips, t):
        raise RuntimeError("probe exploded")
    monkeypatch.setattr(ps, "_host_alive", boom)
    monkeypatch.setattr(ps, "_scan_tcp", lambda *a, **k: [
        {"ip": "1.2.3.4", "open": [], "closed": 1, "filtered": 0}])
    out = ps.run("example.com", ports=[80], skip_hostdown=True)
    assert out["status"] == "ok"


def test_sweep_survives_a_raising_worker():
    def worker(ip, port):
        if port == 2:
            raise RuntimeError("boom")
        return {"port": port, "state": "closed"}
    out = ps._sweep([("1.1.1.1", 1), ("1.1.1.1", 2), ("1.1.1.1", 3)],
                    worker, 2, None)
    assert out[1] is None
    assert out[0]["state"] == "closed"
    assert out[2]["state"] == "closed"


def test_findings_call_out_open_filtered_udp():
    hosts = [{"ip": "1.2.3.4", "open": [], "closed": 0, "filtered": 3,
              "udp_open": 0, "udp_open_filtered": 3}]
    f = ps._build_findings(hosts, 3, "udp")
    assert any("open|filtered" in x for x in f)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def test_cli_refuses_huge_range():
    rc = ps.main(["1.2.3.4", "--ports", "1-65535"])
    assert rc == 2


def test_cli_allows_huge_range_with_flag(monkeypatch):
    seen = {}

    def fake_run(t, **k):
        seen.update(k)
        return {"target": t, "status": "ok", "elapsed_ms": 1,
                "resolution": {"ips": []}, "ports_scanned": 1,
                "scan": {"timeout": 2.0, "workers": 1, "rate": 0},
                "hosts": [], "findings": [], "summary": "done"}
    monkeypatch.setattr(ps, "run", fake_run)
    assert ps.main(["1.2.3.4", "--ports", "1-65535", "--yes-full-sweep"]) == 0
    assert len(seen["ports"]) == 65535


def test_cli_forwards_max_hosts(monkeypatch):
    seen = {}

    def fake_run(t, **k):
        seen.update(k)
        return {"target": t, "status": "ok", "elapsed_ms": 1,
                "resolution": {"ips": []}, "ports_scanned": 1,
                "scan": {"timeout": 2.0, "workers": 1, "rate": 0},
                "hosts": [], "findings": [], "summary": "done"}
    monkeypatch.setattr(ps, "run", fake_run)
    assert ps.main(["1.2.3.4", "--max-hosts", "77"]) == 0
    assert seen["max_hosts"] == 77


def test_cli_max_hosts_applies_to_expansion(capsys):
    assert ps.main(["10.0.0.0/24", "--ports", "80", "--max-hosts", "10"]) == 1
    assert "over --max-hosts 10" in capsys.readouterr().out


def test_cli_no_probe_warns_when_tls_flags_are_inert(monkeypatch, capsys):
    monkeypatch.setattr(ps, "run", lambda t, **k: {
        "target": t, "status": "ok", "elapsed_ms": 1,
        "resolution": {"ips": []}, "ports_scanned": 1,
        "scan": {"timeout": 2.0, "workers": 1, "rate": 0},
        "hosts": [], "findings": [], "summary": "done"})
    for flag in ("--no-tls", "--quick-tls"):
        capsys.readouterr()
        assert ps.main(["1.2.3.4", "--no-probe", flag]) == 0
        assert "no effect with --no-probe" in capsys.readouterr().err


def test_cli_no_probe_warns_udp_port_scope(monkeypatch, capsys):
    monkeypatch.setattr(ps, "run", lambda t, **k: {
        "target": t, "status": "ok", "elapsed_ms": 1,
        "resolution": {"ips": []}, "ports_scanned": 1,
        "scan": {"timeout": 2.0, "workers": 1, "rate": 0},
        "hosts": [], "findings": [], "summary": "done"})
    assert ps.main(["1.2.3.4", "--no-probe", "--protocol", "udp"]) == 0
    assert "still probed" in capsys.readouterr().err


def test_cli_refuses_preset_and_ports_together():
    assert ps.main(["1.2.3.4", "--ports", "80", "--preset", "top"]) == 2


def test_cli_rejects_zero_workers():
    assert ps.main(["1.2.3.4", "--workers", "0"]) == 2


def test_cli_rejects_non_positive_timeout():
    for value in ("0", "-1", "nan", "inf"):
        assert ps.main(["1.2.3.4", "--timeout", value]) == 2


def test_cli_rejects_excessive_workers():
    assert ps.main(["1.2.3.4", "--workers", "51"]) == 2


def test_cli_rejects_invalid_max_hosts():
    for value in ("0", "-3"):
        assert ps.main(["1.2.3.4", "--max-hosts", value]) == 2


def test_run_rejects_non_positive_timeout():
    out = ps.run("example.com", ports=[80], timeout=0)
    assert out["status"] == "error"
    assert "--timeout must be greater than 0" in out["error"]


def test_run_rejects_excessive_workers():
    out = ps.run("example.com", ports=[80], workers=51)
    assert out["status"] == "error"
    assert "--workers must be between 1 and 50" in out["error"]


def test_run_rejects_invalid_max_hosts():
    out = ps.run("example.com", ports=[80], max_hosts=0)
    assert out["status"] == "error"
    assert "--max-hosts must be at least 1" in out["error"]


def test_cli_rejects_negative_rate():
    assert ps.main(["1.2.3.4", "--rate", "-1"]) == 2


def test_cli_requires_target():
    assert ps.main([]) == 1


def test_cli_rejects_two_targets():
    assert ps.main(["a.com", "b.com"]) == 2


def test_cli_rejects_unknown_flag():
    assert ps.main(["1.2.3.4", "--wat"]) == 2


def test_cli_help_exits_zero():
    assert ps.main(["--help"]) == 0


# --------------------------------------------------------------------------
# target expansion
# --------------------------------------------------------------------------

def test_expand_cidr():
    assert ps.expand_targets("10.0.0.0/30") == \
        ["10.0.0.1", "10.0.0.2"]


def test_expand_cidr_32_is_single():
    assert ps.expand_targets("10.0.0.7/32") == ["10.0.0.7"]


def test_expand_dash_range():
    assert ps.expand_targets("10.0.0.1-3") == \
        ["10.0.0.1", "10.0.0.2", "10.0.0.3"]


def test_expand_dash_range_full():
    assert ps.expand_targets("10.0.0.1-10.0.0.3") == \
        ["10.0.0.1", "10.0.0.2", "10.0.0.3"]


def test_expand_dash_range_rejects_backwards():
    with pytest.raises(ValueError, match="ends before"):
        ps.expand_targets("10.0.0.9-10.0.0.2")


def test_expand_comma_mixes_forms():
    out = ps.expand_targets("example.com,10.0.0.1-2")
    assert "example.com" in out and "10.0.0.1" in out


def test_expand_respects_max_hosts():
    with pytest.raises(ValueError, match="max-hosts"):
        ps.expand_targets("10.0.0.0/16", max_hosts=64)


def test_expand_rejects_garbage():
    with pytest.raises(ValueError):
        ps.expand_targets("not a host!!")


def test_expand_from_file(tmp_path):
    p = tmp_path / "t.txt"
    p.write_text("# comment\nexample.com\n10.0.0.5\n\n")
    assert ps.expand_targets("@" + str(p)) == ["example.com", "10.0.0.5"]


def test_expand_missing_file():
    with pytest.raises(ValueError, match="cannot read"):
        ps.expand_targets("@nope.txt")


# --------------------------------------------------------------------------
# service version detection
# --------------------------------------------------------------------------

class _FakeSock:
    def __init__(self, resp=b"", sent=None):
        self._resp = resp
        self.sent = sent or []
        self.timeout = None

    def sendall(self, b):
        self.sent.append(b)

    def send(self, b):
        self.sent.append(b)

    def recv(self, n):
        return self._resp

    def settimeout(self, t):
        self.timeout = t

    def getpeername(self):
        return ("10.0.0.1", 80)

    def close(self):
        pass


def test_version_from_ssh_banner():
    v = ps._version_from_banner("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3", "ssh")
    assert v == "OpenSSH_8.9p1 Ubuntu-3"


def test_version_from_ftp_banner():
    assert "3.0.5" in (ps._version_from_banner(
        "220 (vsFTPd 3.0.5)", "ftp") or "")


def test_version_from_smtp_banner():
    assert "Postfix" in (ps._version_from_banner(
        "220 mail ESMTP Postfix", "smtp") or "")


def test_banner_without_version_returns_none():
    assert ps._version_from_banner("random text", "ssh") is None


def test_http_probe_reads_server_header():
    resp = (b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n"
            b"X-Powered-By: PHP/8.2.1\r\n\r\n")
    s = _FakeSock(resp)
    assert ps._probe_http(s, 1.0) == "nginx/1.24.0"
    assert s.sent and s.sent[0].startswith(b"GET /")


def test_http_probe_falls_back_to_x_powered_by():
    resp = b"HTTP/1.1 200 OK\r\nX-Powered-By: Express\r\n\r\n"
    assert ps._probe_http(_FakeSock(resp), 1.0) == "Express"


def test_redis_probe_reads_version():
    resp = b"$100\r\nredis_version:7.2.4\r\nredis_mode:standalone\r\n"
    assert ps._probe_redis(_FakeSock(resp), 1.0) == "Redis 7.2.4"


def test_mysql_probe_reads_handshake():
    resp = b"\x0a\x00\x00\x00\x0a8.0.35\x00"
    assert ps._probe_mysql(_FakeSock(resp), 1.0) == "MySQL 8.0.35"


def test_postgres_probe_detects_ssl_answer():
    assert "ssl=yes" in (ps._probe_postgres(_FakeSock(b"S"), 1.0) or "")


def test_service_probe_never_raises():
    class Boom:
        def settimeout(self, t):
            pass
        def sendall(self, b):
            raise RuntimeError("boom")
        def close(self):
            pass
    assert ps._service_probe(Boom(), 80, "http", 1.0) is None


def test_version_lands_on_result(monkeypatch):
    class Sock:
        def close(self):
            pass
    monkeypatch.setattr(ps, "_connect_tcp", lambda ip, p, t: Sock())
    monkeypatch.setattr(ps, "_grab_banner", lambda s, t=None: "SSH-2.0-OpenSSH_9.0")
    r = ps._scan_tcp_port("1.2.3.4", 22, 1.0, True, False, False, "h", 1)
    assert r["version"] == "OpenSSH_9.0"


def test_httpish_port_gets_http_probe(monkeypatch):
    seen = []

    def fake(sock, timeout):
        seen.append(1)
        return "nginx/1.25.0"
    monkeypatch.setattr(ps, "_service_probe", fake)
    assert ps.SERVICE_PROBES.get("http-alt") is not None


# --------------------------------------------------------------------------
# OS fingerprinting
# --------------------------------------------------------------------------

def _tcp_options(kinds):
    """Build a real TCP option block: right lengths, padded to 32 bits."""
    out = b""
    for k in kinds:
        if k == 1:                       # NOP
            out += b"\x01"
        elif k == 2:                     # MSS: kind + len + 2-byte value
            out += b"\x02\x04\x05\xb4"
        elif k == 3:                     # Window Scale
            out += b"\x03\x03\x07\x00\x00"
        elif k == 4:                     # SACK Permitted
            out += b"\x04\x02"
        elif k == 34:                    # Timestamps
            out += b"\x22\x0a" + bytes(8)
    while len(out) % 4:
        out += b"\x01"
    return out


def _synack(ttl=64, window=65535, opts=(2, 4, 1, 3)):
    opt_bytes = _tcp_options(opts)
    # data offset counts 32-bit words of the WHOLE tcp header, base included
    offset_byte = ((20 + len(opt_bytes)) // 4) << 4
    tcp = (b"\x00\x00\x00\x00"                  # ports
           + b"\x00" * 8                        # seq + ack
           + bytes([offset_byte, 0x12])         # data offset, SYN|ACK
           + struct.pack("!H", window)
           + b"\x00\x00\x00\x00"                # checksum, urgent
           + opt_bytes)
    return (struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0, ttl,
                        6, 0, b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02") + tcp)


def test_parse_synack_extracts_stack():
    spec = ps._parse_synack(_synack())
    assert spec["ttl"] == 64
    assert spec["window"] == 65535
    assert spec["options"] == (2, 4, 1, 3)


def test_parse_synack_rejects_garbage():
    assert ps._parse_synack(b"\x00" * 10) is None
    assert ps._parse_synack(b"") is None


def test_parse_synack_rejects_non_tcp():
    raw = bytearray(_synack())
    raw[9] = 1                      # ICMP
    assert ps._parse_synack(bytes(raw)) is None


def test_signature_matches_linux():
    spec = ps._parse_synack(_synack(64, 65535, (2, 4, 1, 3, 34)))
    assert "Linux" in ps._match_signature_iter(spec)


def test_signature_matches_windows():
    spec = ps._parse_synack(_synack(128, 65535, (2, 4, 1, 3, 34)))
    name = ps._match_signature_iter(spec)
    assert name and "Windows" in name


def test_signature_matches_mac():
    spec = ps._parse_synack(_synack(255, 65535, (2, 4, 1, 3)))
    assert "macOS" in (ps._match_signature_iter(spec) or "")


def test_unknown_stack_is_reported_not_guessed():
    spec = ps._parse_synack(_synack(37, 1234, (2,)))
    assert ps._match_signature_iter(spec) is None


def test_os_probe_without_privileges_is_honest(monkeypatch):
    monkeypatch.setattr(ps, "_raw_socket_available", lambda: False)
    name, method, conf = ps._os_probe("1.2.3.4", 80, 1.0)
    assert name is None and method is None


def test_os_probe_uses_banner_fallback(monkeypatch):
    monkeypatch.setattr(ps, "_raw_socket_available", lambda: False)
    entries = [{"version": "Microsoft IIS http.sys"}]
    assert "Windows" in (ps._guess_from_banners(entries) or "")


def test_banner_guess_returns_none_without_evidence():
    assert ps._guess_from_banners([{"version": "nginx"}]) is None


def test_os_guess_is_labelled_low_confidence(monkeypatch):
    monkeypatch.setattr(ps, "_raw_socket_available", lambda: False)
    monkeypatch.setattr(ps, "_resolve_host", lambda h, timeout=5.0: ["1.2.3.4"])
    monkeypatch.setattr(ps, "_scan_tcp", lambda *a, **k: [
        {"ip": "1.2.3.4",
         "open": [{"port": 80, "service": "http", "state": "open",
                   "banner": None, "version": "Microsoft IIS", "tls": None,
                   "product": None, "extrainfo": None}],
         "closed": 0, "filtered": 0}])
    out = ps.scan_ips(["1.2.3.4"], "x", ports=[80], os_fingerprint=True)
    assert out["hosts"][0]["os_confidence"] == "low"


# --------------------------------------------------------------------------
# XML output
# --------------------------------------------------------------------------

def test_xml_is_wellformed():
    import xml.etree.ElementTree as ET
    payload = {"hosts": [{"ip": "1.2.3.4", "open": [
        {"port": 80, "service": "http", "state": "open",
         "version": "nginx/1.24.0", "product": "nginx",
         "extrainfo": "1.24.0", "tls": None, "probe": None}],
        "closed": 2, "filtered": 1, "os": "Linux 3.x+ / *BSD"}],
        "elapsed_ms": 1234, "summary": "test"}
    xml = ps.render_xml(payload)
    root = ET.fromstring(xml)
    assert root.tag == "nmaprun"
    assert root.find("./host/address").get("addr") == "1.2.3.4"


def test_xml_carries_service_version():
    import xml.etree.ElementTree as ET
    payload = {"hosts": [{"ip": "1.2.3.4", "open": [
        {"port": 22, "service": "ssh", "state": "open",
         "version": "OpenSSH_9.0", "product": "OpenSSH_9.0",
         "extrainfo": None, "tls": None, "probe": None}],
        "closed": 0, "filtered": 0}], "elapsed_ms": 1, "summary": ""}
    root = ET.fromstring(ps.render_xml(payload))
    svc = root.find(".//service")
    assert svc.get("product") == "OpenSSH_9.0"
    assert svc.get("method") == "probed"


def test_xml_extraports_counts():
    import xml.etree.ElementTree as ET
    payload = {"hosts": [{"ip": "1.2.3.4", "open": [], "closed": 5,
                          "filtered": 2}], "elapsed_ms": 1, "summary": ""}
    root = ET.fromstring(ps.render_xml(payload))
    extra = root.find(".//extraports")
    assert extra.get("state") == "closed" and extra.get("count") == "5"


def test_xml_maps_udp_verdict():
    import xml.etree.ElementTree as ET
    payload = {"hosts": [{"ip": "1.2.3.4", "open": [
        {"port": 53, "service": "domain", "state": ps.UDP_VERDICT_ON_TIMEOUT,
         "version": None, "product": None, "extrainfo": None, "tls": None,
         "probe": True}], "closed": 0, "filtered": 0}],
        "elapsed_ms": 1, "summary": ""}
    root = ET.fromstring(ps.render_xml(payload))
    assert root.find(".//port").get("protocol") == "udp"
    assert root.find(".//state").get("state") == "open|filtered"


def test_xml_declares_ipv6():
    import xml.etree.ElementTree as ET
    payload = {"hosts": [{"ip": "::1", "open": [], "closed": 0,
                          "filtered": 0}], "elapsed_ms": 1, "summary": ""}
    root = ET.fromstring(ps.render_xml(payload))
    assert root.find("./host/address").get("addrtype") == "ipv6"


def test_cli_writes_xml(tmp_path, monkeypatch):
    out = tmp_path / "o.xml"
    monkeypatch.setattr(ps, "run", lambda t, **k: {
        "target": t, "status": "ok", "elapsed_ms": 1,
        "resolution": {"ips": ["1.2.3.4"]}, "ports_scanned": 1,
        "scan": {"timeout": 2.0, "workers": 1, "rate": 0},
        "hosts": [], "findings": [], "summary": "s"})
    assert ps.main(["1.2.3.4", "--xml", str(out)]) == 0
    assert out.exists() and "nmaprun" in out.read_text()


# --------------------------------------------------------------------------
# burst limiting
# --------------------------------------------------------------------------

def test_pacer_burst_allows_back_to_back(monkeypatch):
    slept = []
    monkeypatch.setattr(ps, "sleep", lambda d: slept.append(d))
    p = ps._Pacer(rate=10.0, min_rate=5)
    for _ in range(5):
        p.wait()
    assert slept == []          # the burst covers all five


def test_pacer_burst_then_throttle(monkeypatch):
    slept = []
    monkeypatch.setattr(ps, "sleep", lambda d: slept.append(d))
    p = ps._Pacer(rate=10.0, min_rate=2)
    for _ in range(6):
        p.wait()
    assert len(slept) >= 3


def test_default_burst_is_quarter_of_rate():
    assert ps.kw_burst(40) == 10
    assert ps.kw_burst(0) == 0
    assert ps.kw_burst(2) == 1


def test_cli_rejects_min_rate_zero():
    assert ps.main(["1.2.3.4", "--min-rate", "0"]) == 2


def test_run_forwards_min_rate(monkeypatch):
    seen = {}
    monkeypatch.setattr(ps, "_Pacer",
                        lambda **k: seen.update(k) or type("P", (), {
                            "wait": lambda self: None})())
    monkeypatch.setattr(ps, "scan_target", lambda *a, **k: {
        "status": "ok",
        "resolution": {"ips": ["1.2.3.4"]}, "hosts": []})
    ps.run("1.2.3.4", ports=[80], rate=40.0, min_rate=7)
    assert seen["min_rate"] == 7


def test_run_forwards_max_hosts(monkeypatch):
    seen = {}
    monkeypatch.setattr(ps, "expand_targets",
                        lambda t, m=256: seen.update(max_hosts=m) or [t])
    monkeypatch.setattr(ps, "scan_target", lambda *a, **k: {
        "status": "ok",
        "resolution": {"ips": ["1.2.3.4"]}, "hosts": []})
    assert ps.run("1.2.3.4", ports=[80], max_hosts=123)["status"] == "ok"
    assert seen["max_hosts"] == 123


def test_cli_json_path(monkeypatch, capsys):
    monkeypatch.setattr(ps, "run", lambda t, **k: {
        "target": t, "status": "ok", "elapsed_ms": 5,
        "resolution": {"ips": ["1.2.3.4"]}, "ports_scanned": 1,
        "scan": {"timeout": 2.0, "workers": 1, "rate": 0},
        "hosts": [], "findings": [], "summary": "done"})
    assert ps.main(["1.2.3.4", "--json"]) == 0
    assert '"status": "ok"' in capsys.readouterr().out