import requests

from modules.identity.breach_checker import run, not_found_result
from conftest import FakeResponse


def test_breach_found_flattens_nested_list(monkeypatch):
    payload = {
        "status": "success",
        "email": "victim@example.com",
        "breaches": [["Breach1", "Breach2"], ["Breach2", "Breach3"]],
    }
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse(200, payload))
    res = run("Victim@Example.com")
    assert "error" not in res
    assert res["breached"] is True
    # deduplicated while keeping order
    assert res["breaches"] == ["Breach1", "Breach2", "Breach3"]
    assert res["breach_count"] == 3


def test_not_found_via_200_error_field(monkeypatch):
    payload = {"Error": "Not found", "email": None}
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse(200, payload))
    res = run("clean@example.com")
    assert res["breached"] is False
    assert res["breach_count"] == 0
    assert res["summary"] == "No breaches found for this email."


def test_404_status_returns_not_found(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse(404, {}))
    res = run("clean@example.com")
    assert res["breached"] is False


def test_429_rate_limited(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse(429, {}))
    res = run("x@example.com")
    assert "error" in res
    assert "Rate limit" in res["error"]


def test_invalid_email_format():
    assert "error" in run("nope")


def test_connection_failure(monkeypatch):
    def boom(*a, **k):
        raise requests.RequestException("down")

    monkeypatch.setattr(requests, "get", boom)
    res = run("x@example.com")
    assert "Failed to connect" in res["error"]


def test_not_found_result_shape():
    res = not_found_result("x@example.com")
    assert res["breached"] is False
    assert res["breaches"] == []
