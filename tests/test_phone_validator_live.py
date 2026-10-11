import modules.identity.phone_validator as pv


class FakeResp:
    """Minimal requests.Response stand-in (independent of conftest's)."""

    def __init__(self, status_code, payload=None, headers=None):
        self.status_code = status_code
        self._payload = payload
        self.headers = headers or {}

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise pv.requests.HTTPError(f"HTTP {self.status_code}")


VERI_OK = {
    "status": "success",
    "phone": "+13475550123",
    "phone_valid": True,
    "phone_type": "mobile",
    "phone_region": "New York",
    "country": "United States",
    "country_code": "US",
    "country_prefix": "1",
    "international_number": "+1 347-555-0123",
    "local_number": "(347) 555-0123",
    "e164": "+13475550123",
    "carrier": "T-Mobile",
}


# ---------------------------------------------------------------------------
# Auto / gating semantics
# ---------------------------------------------------------------------------


def test_no_key_no_live_block(monkeypatch):
    monkeypatch.delenv("VERIPHONE_API_KEY", raising=False)

    def boom(*a, **k):
        raise AssertionError("must not call the network")

    monkeypatch.setattr(pv, "_veriphone_lookup", boom)
    res = pv.run("+393451234567")
    assert res["status"] == "ok"
    assert "live" not in res


def test_key_env_enables_live(monkeypatch):
    monkeypatch.setenv("VERIPHONE_API_KEY", "test-key")
    monkeypatch.setattr(
        pv, "_veriphone_lookup", lambda *a, **k: FakeResp(200, VERI_OK)
    )
    res = pv.run("+13475550123")
    assert res["live"]["provider"] == "veriphone"
    assert res["live"]["carrier"] == "T-Mobile"
    assert res["live"]["phone_type"] == "mobile"


def test_explicit_key_overrides_env(monkeypatch):
    monkeypatch.setenv("VERIPHONE_API_KEY", "env-key")
    seen = {}

    def spy(e164, api_key, timeout=10):
        seen["key"] = api_key
        return FakeResp(200, VERI_OK)

    monkeypatch.setattr(pv, "_veriphone_lookup", spy)
    pv.run("+13475550123", VERIPHONE_API_KEY="explicit-key")
    assert seen["key"] == "explicit-key"


# ---------------------------------------------------------------------------
# Offline carrier enrichment
# ---------------------------------------------------------------------------


def test_live_carrier_fills_offline_unknown(monkeypatch):
    # US number: offline carrier is Unknown (NA portability), live fills it
    monkeypatch.setenv("VERIPHONE_API_KEY", "test-key")
    monkeypatch.setattr(
        pv, "_veriphone_lookup", lambda *a, **k: FakeResp(200, VERI_OK)
    )
    res = pv.run("+13475550123")
    assert res["metadata"]["carrier"] == "T-Mobile"
    assert any("Veriphone" in f for f in res["findings"])


def test_offline_carrier_not_overwritten(monkeypatch):
    # IT number: offline says Vodafone; live must NOT replace it
    monkeypatch.setenv("VERIPHONE_API_KEY", "test-key")
    monkeypatch.setattr(
        pv,
        "_veriphone_lookup",
        lambda *a, **k: FakeResp(200, {**VERI_OK, "carrier": "Someone Else"}),
    )
    res = pv.run("+393451234567")
    assert res["metadata"]["carrier"] == "Vodafone"
    assert res["live"]["carrier"] == "Someone Else"


# ---------------------------------------------------------------------------
# Failure containment — offline result always stands
# ---------------------------------------------------------------------------


def test_forced_live_without_key_is_contained(monkeypatch):
    monkeypatch.delenv("VERIPHONE_API_KEY", raising=False)
    res = pv.run("+393451234567", live=True)
    assert res["status"] == "ok"  # offline result stands
    assert "VERIPHONE_API_KEY" in res["live"]["error"]
    assert any("Live lookup failed" in f for f in res["findings"])


def test_live_401_contained(monkeypatch):
    monkeypatch.setenv("VERIPHONE_API_KEY", "bad-key")
    monkeypatch.setattr(
        pv, "_veriphone_lookup", lambda *a, **k: FakeResp(401, {})
    )
    res = pv.run("+393451234567", live=True)
    assert res["status"] == "ok"
    assert "invalid or missing API key" in res["live"]["error"]


def test_live_402_contained(monkeypatch):
    monkeypatch.setenv("VERIPHONE_API_KEY", "test-key")
    monkeypatch.setattr(
        pv, "_veriphone_lookup", lambda *a, **k: FakeResp(402, {})
    )
    res = pv.run("+393451234567", live=True)
    assert "insufficient credits" in res["live"]["error"]


def test_live_429_surfaces_retry_after(monkeypatch):
    monkeypatch.setenv("VERIPHONE_API_KEY", "test-key")
    monkeypatch.setattr(
        pv,
        "_veriphone_lookup",
        lambda *a, **k: FakeResp(429, {}, headers={"Retry-After": "7"}),
    )
    res = pv.run("+393451234567", live=True)
    assert "Retry-After: 7s" in res["live"]["error"]


def test_live_500_contained(monkeypatch):
    monkeypatch.setenv("VERIPHONE_API_KEY", "test-key")
    monkeypatch.setattr(
        pv, "_veriphone_lookup", lambda *a, **k: FakeResp(500, {})
    )
    res = pv.run("+393451234567", live=True)
    assert "HTTP 500" in res["live"]["error"]


def test_live_bad_json_contained(monkeypatch):
    monkeypatch.setenv("VERIPHONE_API_KEY", "test-key")
    monkeypatch.setattr(
        pv, "_veriphone_lookup", lambda *a, **k: FakeResp(200, None)
    )
    res = pv.run("+393451234567", live=True)
    assert "invalid JSON" in res["live"]["error"]


def test_live_error_status_contained(monkeypatch):
    monkeypatch.setenv("VERIPHONE_API_KEY", "test-key")
    monkeypatch.setattr(
        pv,
        "_veriphone_lookup",
        lambda *a, **k: FakeResp(
            200, {"status": "error", "code": 400, "message": "BadRequest thing"}
        ),
    )
    res = pv.run("+393451234567", live=True)
    assert "BadRequest thing" in res["live"]["error"]


def test_live_transport_error_contained(monkeypatch):
    monkeypatch.setenv("VERIPHONE_API_KEY", "test-key")

    def raise_conn(*a, **k):
        raise pv.requests.ConnectionError("no route to host")

    monkeypatch.setattr(pv, "_veriphone_lookup", raise_conn)
    res = pv.run("+393451234567", live=True)
    assert res["status"] == "ok"
    assert "Veriphone request failed" in res["live"]["error"]


# ---------------------------------------------------------------------------
# Credit-burn guard: legacy pipeline must never go live
# ---------------------------------------------------------------------------


def test_search_phone_pipeline_never_live(monkeypatch):
    monkeypatch.setenv("VERIPHONE_API_KEY", "test-key")

    def boom(*a, **k):
        raise AssertionError("breach pipeline must not spend Veriphone credits")

    monkeypatch.setattr(pv, "_veriphone_lookup", boom)
    res = pv.search_phone_pipeline("+393451234567", "IT")
    assert res["status"] == "success"
    assert "live" not in res


# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------


def test_render_shows_live_block(monkeypatch):
    monkeypatch.setenv("VERIPHONE_API_KEY", "test-key")
    monkeypatch.setattr(
        pv, "_veriphone_lookup", lambda *a, **k: FakeResp(200, VERI_OK)
    )
    out = pv.render(pv.run("+13475550123"))
    assert "Live      : veriphone" in out
    assert "T-Mobile" in out


def test_render_shows_live_failure(monkeypatch):
    res = pv.run("+393451234567", live=True)  # no key
    out = pv.render(res)
    assert "Live      : failed" in out
