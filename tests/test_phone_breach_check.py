import requests

import modules.identity.phone_breach_check as pbc
from conftest import FakeResponse

PIPELINE_OK = {
    "status": "success",
    "search_keys": {"e164": "+12025550123", "msisdn": "12025550123"},
    "metadata": {"country": "United States", "carrier": "Unknown"},
    "database_hits": [],
}


def test_breached(monkeypatch):
    monkeypatch.setenv("LEAK_LOOKUP_API_KEY", "test-key")
    monkeypatch.setattr(
        pbc, "search_phone_pipeline", lambda *a, **k: PIPELINE_OK
    )
    payload = {"error": "false", "message": {"BreachOne": [], "BreachTwo": [{}]}}
    monkeypatch.setattr(requests, "post", lambda *a, **k: FakeResponse(200, payload))
    res = pbc.run("(202) 555-0123")
    assert res["phone"] == "+12025550123"
    assert res["breached"] is True
    assert res["breaches"] == ["BreachOne", "BreachTwo"]
    assert res["breach_count"] == 2


def test_not_found(monkeypatch):
    monkeypatch.setenv("LEAK_LOOKUP_API_KEY", "test-key")
    monkeypatch.setattr(
        pbc, "search_phone_pipeline", lambda *a, **k: PIPELINE_OK
    )
    monkeypatch.setattr(
        requests, "post", lambda *a, **k: FakeResponse(200, {"error": "false", "message": {}})
    )
    res = pbc.run("(202) 555-0123")
    assert res["breached"] is False
    assert res["summary"] == "No breaches found for this phone number."


def test_invalid_phone_returns_error(monkeypatch):
    monkeypatch.setattr(
        pbc,
        "search_phone_pipeline",
        lambda *a, **k: {"status": "error", "message": "Invalid phone number structure."},
    )
    res = pbc.run("999")
    assert res["status"] == "error"
    assert res["error"] == "Invalid phone number structure."
    assert res["query"] == {"phone": "999", "provider": "leak-lookup"}


def test_missing_api_key(monkeypatch):
    monkeypatch.delenv("LEAK_LOOKUP_API_KEY", raising=False)
    monkeypatch.setattr(pbc, "search_phone_pipeline", lambda *a, **k: PIPELINE_OK)
    res = pbc.run("(202) 555-0123")
    assert "error" in res
    assert "LEAK_LOOKUP_API_KEY" in res["error"]


def test_http_error_status(monkeypatch):
    monkeypatch.setenv("LEAK_LOOKUP_API_KEY", "test-key")
    monkeypatch.setattr(pbc, "search_phone_pipeline", lambda *a, **k: PIPELINE_OK)
    monkeypatch.setattr(requests, "post", lambda *a, **k: FakeResponse(401, {}))
    res = pbc.run("(202) 555-0123")
    assert "error" in res
    assert "Unauthorized" in res["error"]
