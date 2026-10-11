import errno
import json
import socket

import pytest

import modules.network.port_scanner as ps


class FakeSock:
    """Minimal stand-in for a connected TCP socket."""

    def __init__(self, banner=b""):
        self._banner = banner

    def settimeout(self, timeout):
        pass

    def recv(self, n):
        if not self._banner:
            raise socket.timeout("no data")
        data, self._banner = self._banner[:n], self._banner[n:]
        return data

    def close(self):
        pass


def make_connect(spec):
    """Build a fake _connect: dict port -> banner bytes (open), anything
    else raises ConnectionRefusedError (closed). Raise socket.timeout
    first when the port maps to the special value None (filtered)."""
    def fake(ip, port, timeout):
        if port in spec and spec[port] is None:
            raise socket.timeout("filtered")
        if port in spec:
            return FakeSock(spec[port])
        raise ConnectionRefusedError(errno.ECONNREFUSED, "refused")
    return fake


def patch_scan(monkeypatch, spec, ips=("93.184.216.34",)):
    """Patch the seams so a run() is fully offline."""
    monkeypatch.setattr(ps, "_resolve_host",
                        lambda host, timeout=5.0: list(ips))
    monkeypatch.setattr(ps, "_connect", make_connect(spec))
    monkeypatch.setattr(ps, "_tls_probe",
                        lambda *a: {"verified": False, "issuer": None,
                                    "subject": None, "san": [],
                                    "not_after": None, "version": None,
                                    "cipher": None, "verify_error": None,
                                    "expired": False})


# --- port spec parsing ----------------------------------------------------

def test_parse_ports_single_and_list():
    assert ps.parse_ports("22") == [22]
    assert ps.parse_ports("80,443,22") == [22, 80, 443]


def test_parse_ports_ranges_and_mixed():
    assert ps.parse_ports("8000-8002") == [8000, 8001, 8002]
    assert ps.parse_ports("22, 80, 443, 8000-8001") == [22, 80, 443, 8000, 8001]


def test_parse_ports_dedupes_and_sorts():
    assert ps.parse_ports("443,80,443,80") == [80, 443]


def test_parse_ports_invalid():
    with pytest.raises(ValueError):
        ps.parse_ports("0")
    with pytest.raises(ValueError):
        ps.parse_ports("65536")
    with pytest.raises(ValueError):
        ps.parse_ports("5000-2000")
    with pytest.raises(ValueError):
        ps.parse_ports("abc")
    with pytest.raises(ValueError):
        ps.parse_ports("")

# --- run() validation + resolution ---------------------------------------

def test_run_no_target():
    out = ps.run(None)
    assert out["status"] == "error"
    assert "No target" in out["error"]


def test_run_invalid_target():
    out = ps.run("not a host!")
    assert out["status"] == "error"
    assert "not a valid IP address or hostname" in out["error"]


def test_run_resolution_failure(monkeypatch):
    def boom(host, timeout=5.0):
        raise socket.gaierror("no such host")
    monkeypatch.setattr(ps, "_resolve_host", boom)
    out = ps.run("nonexistent.invalid")
    assert out["status"] == "error"
    assert "Cannot resolve" in out["error"]


def test_run_payload_shape(monkeypatch):
    patch_scan(monkeypatch, {22: b"SSH-2.0-OpenSSH_8.9p1 Ubuntu",
                             80: b"", 443: b""})
    out = ps.run("example.com", ports=[22, 80, 443])
    assert out["status"] == "ok"
    assert out["target"] == "example.com"
    assert set(out) >= {"target", "status", "elapsed_ms", "resolution",
                        "ports_scanned", "scan", "hosts", "findings",
                        "summary"}
    assert out["ports_scanned"] == 3
    assert out["resolution"]["ips"] == ["93.184.216.34"]
    assert out["scan"]["ports"] == [22, 80, 443]


def test_default_ports_used_when_none(monkeypatch):
    patch_scan(monkeypatch, {})
    out = ps.run("example.com")
    assert out["ports_scanned"] == len(ps.DEFAULT_PORTS)
    assert out["scan"]["ports"] == ps.DEFAULT_PORTS


# --- verdict classification ----------------------------------------------

def test_scan_verdicts_open_closed_filtered(monkeypatch):
    patch_scan(monkeypatch, {22: b"SSH-2.0-OpenSSH", 443: None})
    out = ps.run("example.com", ports=[22, 80, 443])
    host = out["hosts"][0]
    assert any(o["port"] == 22 and o["state"] == "open"
               for o in host["open"])
    assert host["closed"] == 1     # 80 refused
    assert host["filtered"] == 1   # 443 timed out


def test_open_port_carries_banner(monkeypatch):
    patch_scan(monkeypatch, {22: b"SSH-2.0-OpenSSH_8.9p1 Ubuntu"})
    out = ps.run("example.com", ports=[22])
    entry = out["hosts"][0]["open"][0]
    assert entry["state"] == "open"
    assert entry["service"] == "ssh"
    assert "SSH-2.0-OpenSSH" in entry["banner"]
    assert entry["tls"] is None


def test_open_port_no_banner(monkeypatch):
    patch_scan(monkeypatch, {8080: b""})
    out = ps.run("example.com", ports=[8080])
    entry = out["hosts"][0]["open"][0]
    assert entry["state"] == "open"
    assert entry["service"] == "http-alt"
    assert entry["banner"] is None


def test_tls_port_uses_tls_probe(monkeypatch):
    tls_info = {"verified": True, "issuer": "Cloudflare Inc ECC CA-3",
                "subject": "example.com", "san": ["example.com"],
                "not_after": "Aug 13 23:59:59 2027 GMT", "version": "TLSv1.3",
                "cipher": "TLS_AES_128_GCM_SHA256", "verify_error": None,
                "expired": False}
    monkeypatch.setattr(ps, "_resolve_host",
                        lambda host, timeout=5.0: ["93.184.216.34"])
    monkeypatch.setattr(ps, "_connect", make_connect({443: b""}))
    monkeypatch.setattr(ps, "_tls_probe", lambda *a: dict(tls_info))
    out = ps.run("example.com", ports=[443])
    entry = out["hosts"][0]["open"][0]
    assert entry["tls"]["verified"] is True
    assert entry["tls"]["issuer"] == "Cloudflare Inc ECC CA-3"
    assert entry["banner"] is None


def test_multi_ip_target_scan(monkeypatch):
    ips = ("93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946")
    patch_scan(monkeypatch, {22: b"banner"}, ips=ips)
    out = ps.run("example.com", ports=[22, 80])
    assert len(out["hosts"]) == 2
    assert {h["ip"] for h in out["hosts"]} == set(ips)
    assert all(len(h["open"]) == 1 for h in out["hosts"])

# --- findings ------------------------------------------------------------

def test_finding_plaintext_services(monkeypatch):
    patch_scan(monkeypatch, {21: b"220 FTP ready", 23: b"telnet"})
    out = ps.run("example.com", ports=[21, 23])
    joined = " ".join(out["findings"])
    assert "plaintext" in joined
    assert "ftp (21)" in joined and "telnet (23)" in joined


def test_finding_no_open_ports(monkeypatch):
    patch_scan(monkeypatch, {})
    out = ps.run("example.com", ports=[22, 80, 443])
    assert any("No open TCP port" in f for f in out["findings"])


def test_finding_tls_untrusted(monkeypatch):
    monkeypatch.setattr(ps, "_resolve_host",
                        lambda host, timeout=5.0: ["93.184.216.34"])
    monkeypatch.setattr(ps, "_connect", make_connect({443: b""}))
    monkeypatch.setattr(ps, "_tls_probe",
                        lambda *a: {"verified": False, "issuer": None,
                                    "subject": None, "san": [],
                                    "not_after": None, "version": "TLSv1.3",
                                    "cipher": None,
                                    "verify_error": "self-signed certificate",
                                    "expired": False})
    out = ps.run("example.com", ports=[443])
    assert any("not trusted - self-signed certificate" in f
               for f in out["findings"])


def test_no_finding_for_verified_tls(monkeypatch):
    monkeypatch.setattr(ps, "_resolve_host",
                        lambda host, timeout=5.0: ["93.184.216.34"])
    monkeypatch.setattr(ps, "_connect", make_connect({443: b""}))
    monkeypatch.setattr(ps, "_tls_probe",
                        lambda *a: {"verified": True, "issuer": "ACME CA",
                                    "subject": "example.com", "san": [],
                                    "not_after": None, "version": "TLSv1.3",
                                    "cipher": "TLS_AES_128_GCM_SHA256",
                                    "verify_error": None, "expired": False})
    out = ps.run("example.com", ports=[443])
    assert not any("TLS" in f for f in out["findings"])


# --- renderer ------------------------------------------------------------

def test_render_human(monkeypatch):
    patch_scan(monkeypatch, {22: b"SSH-2.0-OpenSSH_8.9p1"})
    out = ps.run("example.com", ports=[22, 80])
    text = ps.render(out)
    assert "Port Scanner: example.com" in text
    assert "Status" in text and "ok" in text
    assert "Open ports" in text
    assert "93.184.216.34:22" in text
    assert "banner: SSH-2.0-OpenSSH" in text


def test_render_error():
    text = ps.render({"status": "error", "target": "x.invalid",
                      "error": "Cannot resolve"})
    assert "failed" in text
    assert "Cannot resolve" in text


# --- CLI ---------------------------------------------------------------

def test_main_json_output(monkeypatch, capsys):
    patch_scan(monkeypatch, {22: b"banner"})
    code = ps.main(["--json", "example.com", "--ports", "22"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "ok"
    assert payload["ports_scanned"] == 1


def test_main_no_args():
    assert ps.main([]) == 1


def test_main_unknown_flag():
    assert ps.main(["--bogus", "example.com"]) == 2


def test_main_invalid_ports_spec():
    assert ps.main(["example.com", "--ports", "99999"]) == 2


def test_main_too_many_targets():
    assert ps.main(["a.com", "b.com"]) == 2


def test_main_resolution_error_exit(monkeypatch):
    def boom(host, timeout=5.0):
        raise socket.gaierror("no such host")
    monkeypatch.setattr(ps, "_resolve_host", boom)
    assert ps.main(["nonexistent.invalid"]) == 1
