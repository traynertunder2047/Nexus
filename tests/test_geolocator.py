import json
import os

import requests

import modules.network.geolocator as gl


def sample(**overrides):
    """Synthetic ip-api success response with realistic defaults."""
    data = {
        "status": "success",
        "query": "8.8.8.8",
        "country": "United States",
        "countryCode": "US",
        "region": "CA",
        "regionName": "California",
        "city": "Mountain View",
        "zip": "94043",
        "lat": 37.751,
        "lon": -97.822,
        "timezone": "America/Los_Angeles",
        "isp": "Google LLC",
        "org": "Google LLC",
        "as": "AS15169 Google LLC",
        "asname": "Google LLC",
        "reverse": "dns.google",
        "mobile": False,
        "proxy": False,
        "hosting": True,
    }
    data.update(overrides)
    return data


def patch_lookup(monkeypatch, data=None, exc=None):
    """Patch the seam to return data, or to raise exc (None means clean)."""
    if exc is not None:
        def boom(*a, **k):
            raise exc
        monkeypatch.setattr(gl, "_lookup", boom)
    else:
        monkeypatch.setattr(gl, "_lookup", lambda *a, **k: data)


# --- validation -----------------------------------------------------------

def test_validate_ip_ok():
    assert gl.validate_ip("8.8.8.8") is None
    assert gl.validate_ip("2001:4860:4860::8888") is None


def test_validate_ip_rejects():
    assert "not a valid" in gl.validate_ip("not-an-ip")
    assert "No IP address" in gl.validate_ip("")
    assert "No IP address" in gl.validate_ip(None)


# --- run() ---------------------------------------------------------------

def test_run_success_payload(monkeypatch):
    patch_lookup(monkeypatch, sample())
    out = gl.run("8.8.8.8")
    assert out["status"] == "ok"
    assert out["ip"] == "8.8.8.8"
    assert set(out) >= {"ip", "status", "elapsed_ms", "lookup", "geo",
                        "network", "findings", "summary"}
    assert out["geo"]["country"] == "United States"
    assert out["geo"]["city"] == "Mountain View"
    assert out["geo"]["latitude"] == 37.751
    assert out["network"]["asn"] == "AS15169"
    assert out["network"]["as_name"] == "Google LLC"
    assert out["network"]["isp"] == "Google LLC"
    assert out["network"]["reverse_dns"] == "dns.google"
    assert out["lookup"]["provider"] == "ip-api"
    assert out["lookup"]["endpoint"] == gl._endpoint()


def test_run_findings_from_flags(monkeypatch):
    patch_lookup(monkeypatch, sample(hosting=True, proxy=True, mobile=True))
    out = gl.run("8.8.8.8")
    joined = " ".join(out["findings"])
    assert "hosting / cloud provider" in joined
    assert "proxy / VPN" in joined
    assert "mobile / cellular" in joined


def test_run_no_findings_when_clean(monkeypatch):
    patch_lookup(monkeypatch, sample(hosting=False, proxy=False,
                                     mobile=False))
    out = gl.run("8.8.8.8")
    assert out["findings"] == []


def test_run_summary_mentions_place_and_isp(monkeypatch):
    patch_lookup(monkeypatch, sample())
    out = gl.run("8.8.8.8")
    assert "Mountain View" in out["summary"]
    assert "Google LLC" in out["summary"]


def test_run_invalid_ip(monkeypatch):
    patch_lookup(monkeypatch, sample())  # seam must not be reached
    out = gl.run("banana")
    assert out["status"] == "error"
    assert "not a valid" in out["error"]


def test_run_no_ip(monkeypatch):
    patch_lookup(monkeypatch, sample())
    out = gl.run(None)
    assert out["status"] == "error"
    assert "No IP address" in out["error"]


def test_run_api_fail_reserved_range(monkeypatch):
    patch_lookup(monkeypatch, {"status": "fail",
                               "message": "reserved range",
                               "query": "127.0.0.1"})
    out = gl.run("127.0.0.1")
    assert out["status"] == "error"
    assert "reserved range" in out["error"]


def test_run_transport_error(monkeypatch):
    patch_lookup(monkeypatch, exc=requests.RequestException("boom"))
    out = gl.run("8.8.8.8")
    assert out["status"] == "error"
    assert "Lookup failed" in out["error"]


def test_run_returns_ok_when_flags_absent(monkeypatch):
    patch_lookup(monkeypatch, sample(proxy=None, hosting=None, mobile=None))
    out = gl.run("8.8.8.8")
    assert out["status"] == "ok"
    assert out["network"]["proxy"] is False


# --- endpoint override ----------------------------------------------------

def test_endpoint_default_and_env_override(monkeypatch):
    # default is the HTTP free tier unless the environment says otherwise
    monkeypatch.delenv("IP_API_URL", raising=False)
    assert gl._endpoint() == "http://ip-api.com/json/"
    # free-tier https://ip-api.com/... is auto-corrected to http (free tier is HTTP-only)
    monkeypatch.setenv("IP_API_URL", "https://ip-api.com/json/")
    assert gl._endpoint() == "http://ip-api.com/json/"
    monkeypatch.setenv("IP_API_URL", "https://paid.example/json/")
    assert gl._endpoint() == "https://paid.example/json/"
    monkeypatch.delenv("IP_API_URL", raising=False)
    assert gl._endpoint() == "http://ip-api.com/json/"

# --- renderer ------------------------------------------------------------

def test_render_human(monkeypatch):
    patch_lookup(monkeypatch, sample())
    out = gl.run("8.8.8.8")
    text = gl.render(out)
    assert "Geolocator: 8.8.8.8" in text
    assert "United States" in text
    assert "AS15169" in text
    assert "Mountain View" in text
    assert "Findings" in text


def test_render_error():
    text = gl.render({"status": "error", "ip": "8.8.8.8",
                      "error": "Lookup failed: boom"})
    assert "failed" in text
    assert "Lookup failed: boom" in text


# --- CLI ---------------------------------------------------------------

def test_main_json_output(monkeypatch, capsys):
    patch_lookup(monkeypatch, sample())
    code = gl.main(["--json", "8.8.8.8"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "ok"
    assert payload["ip"] == "8.8.8.8"


def test_main_no_args():
    assert gl.main([]) == 1


def test_main_unknown_flag():
    assert gl.main(["--bogus", "8.8.8.8"]) == 2


def test_main_too_many_ips():
    assert gl.main(["8.8.8.8", "1.1.1.1"]) == 2


def test_main_invalid_ip_exit(monkeypatch):
    patch_lookup(monkeypatch, sample())  # seam must not be reached
    assert gl.main(["banana"]) == 1


def test_main_transport_error_exit(monkeypatch):
    patch_lookup(monkeypatch, exc=requests.RequestException("offline"))
    assert gl.main(["8.8.8.8"]) == 1
