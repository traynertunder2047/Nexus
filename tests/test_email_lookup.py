import requests

from modules.identity.email_lookup import run
from conftest import FakeResponse


def test_low_suspicion(monkeypatch):
    payload = {
        "reputation": "none",
        "suspicious": False,
        "references": 1,
        "details": {"blacklisted": False, "sources": []},
    }
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse(200, payload))
    res = run("good@example.com")
    assert "error" not in res
    assert res["email"] == "good@example.com"
    assert res["summary"] == "Low Suspicion"
    assert res["reputation"] == "none"


def test_suspicious(monkeypatch):
    payload = {
        "reputation": "high",
        "suspicious": True,
        "references": 4,
        "details": {"blacklisted": True, "credentials_leaked": True, "sources": ["x"]},
    }
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse(200, payload))
    res = run("bad@example.com")
    assert res["summary"] == "High Risk / Phishing History"
    assert res["flags"]["credentials_leaked"] is True


def test_error_status_401(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse(401, {}))
    res = run("x@example.com")
    assert "error" in res
    assert "key" in res["error"].lower()


def test_invalid_email_format():
    res = run("not-an-email")
    assert "error" in res


def test_connection_failure(monkeypatch):
    def boom(*a, **k):
        raise requests.RequestException("down")

    monkeypatch.setattr(requests, "get", boom)
    res = run("x@example.com")
    assert "error" in res
