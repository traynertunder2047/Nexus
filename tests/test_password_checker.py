import requests

from modules.identity.password_checker import (
    _keccak_512,
    _parse_char,
    run,
    safe_result,
)
from conftest import FakeResponse

# Known original-Keccak-512 digest of "test" (validated against the
# XposedOrNot/Keccak test vectors; differs from NIST SHA3-512).
KNOWN_TEST_DIGEST = (
    "1e2e9fc2002b002d75198b7503210c05a1baac4560916a3c6d93bcce3a50d7f00"
    "fd395bf1647b9abb8d1afcc9c76c289b0c9383ba386a956da4b38934417789e"
)


def test_keccak_512_matches_known_vector():
    assert _keccak_512(b"test") == KNOWN_TEST_DIGEST


def test_run_sends_only_local_prefix(monkeypatch):
    # The requested URL must carry only the 10-char prefix, never the password.
    captured = {}

    def fake_get(url, **kwargs):
        captured["url"] = url
        return FakeResponse(404, json_data={"Error": "Not found"})

    monkeypatch.setattr(requests, "get", fake_get)
    run("test")
    assert captured["url"].endswith(KNOWN_TEST_DIGEST[:10])


def test_run_404_returns_safe_result(monkeypatch):
    monkeypatch.setattr(
        requests, "get", lambda *a, **k: FakeResponse(404, {"Error": "Not found"})
    )
    res = run("test")
    assert res["exposed"] is False
    assert res["count"] == 0
    assert res["summary"] == "Password not found in known breaches."


def test_run_found_breach(monkeypatch):
    payload = {
        "SearchPassAnon": {
            "anon": "1234567890",
            "char": "D:4;A:4;S:0;L:8",
            "count": "35434",
            "wordlist": 0,
        }
    }
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse(200, payload))
    res = run("test")
    assert res["exposed"] is True
    assert res["count"] == 35434
    assert res["characteristics"] == {"digits": 4, "alpha": 4, "special": 0, "length": 8}
    assert "do NOT reuse" in res["summary"]


def test_run_connection_error(monkeypatch):
    def boom(*a, **k):
        raise requests.RequestException("down")

    monkeypatch.setattr(requests, "get", boom)
    res = run("test")
    assert "error" in res
    assert "Failed to connect" in res["error"]


def test_parse_char():
    assert _parse_char("D:0;A:4;S:0;L:4") == {"digits": 0, "alpha": 4, "special": 0, "length": 4}
    assert _parse_char("") is None
    assert _parse_char(None) is None


def test_safe_result_shape():
    res = safe_result("abc")
    assert res["hash_prefix"] == "abc"
    assert res["exposed"] is False
