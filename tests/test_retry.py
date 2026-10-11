import pytest
import requests

import modules.identity.helpers as h
import modules.identity.xon as xon
import modules.identity.email_lookup as el
import modules.identity.phone_breach_check as pbc
import modules.identity.password_checker as pc
from conftest import FakeResponse


class R:
    """Tiny response double carrying a status code + headers (+ optional JSON)."""

    def __init__(self, status_code, headers=None, json_data=None):
        self.status_code = status_code
        self.headers = headers or {}
        self._json = json_data if json_data is not None else {}
        self.text = ""
        self.content = b""

    def json(self):
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")


# ---------------------------------------------------------------------------
# Core semantics
# ---------------------------------------------------------------------------


def test_success_on_first_call_no_sleep():
    calls = []

    def fn():
        calls.append(1)
        return R(200)

    out = h.request_with_retries(fn, sleep=lambda s: calls.append(f"sleep {s}"))
    assert out.status_code == 200
    assert len(calls) == 1  # no sleeps on the happy path


def test_no_sleep_on_success_with_patched_env(monkeypatch):
    monkeypatch.setenv("RETRY_BACKOFF", "0")
    monkeypatch.setenv("RETRY_MAX_SLEEP", "0")
    out = h.request_with_retries(lambda: R(200), sleep=h.time.sleep)
    assert out.status_code == 200


def test_retry_on_429_then_success():
    seq = [R(429, {"Retry-After": "5"}), R(200)]
    sleeps = []
    out = h.request_with_retries(
        lambda: seq.pop(0), sleep=sleeps.append, attempts=2, max_sleep=60
    )
    assert out.status_code == 200
    assert sleeps == [5.0]  # Retry-After honored exactly (explicit cap above it)


def test_retry_on_503_then_success_exponential():
    seq = [R(503), R(503), R(200)]
    sleeps = []
    out = h.request_with_retries(
        lambda: seq.pop(0), sleep=sleeps.append, attempts=2, backoff=2.0, max_sleep=100
    )
    assert out.status_code == 200
    assert sleeps == [2.0, 4.0]  # backoff * 2^attempt


def test_attempts_exhausted_returns_last_response():
    seq = [R(429), R(429), R(429)]
    out = h.request_with_retries(lambda: seq.pop(0), sleep=lambda s: None, attempts=1)
    assert out.status_code == 429  # caller still maps it to its error payload


def test_permanent_4xx_never_retried():
    calls = []

    def fn():
        calls.append(1)
        return R(404)

    out = h.request_with_retries(fn, sleep=lambda s: calls.append("sleep"))
    assert out.status_code == 404
    assert calls == [1]


def test_transport_exception_retried_then_raised():
    calls = []

    def always_down():
        calls.append(1)
        raise requests.ConnectionError("no route")

    with pytest.raises(requests.ConnectionError):
        h.request_with_retries(always_down, sleep=lambda s: None, attempts=2)
    assert len(calls) == 3  # initial + 2 retries


def test_transport_exception_recovers(monkeypatch):
    state = {"n": 0}

    def flaky():
        state["n"] += 1
        if state["n"] == 1:
            raise requests.ConnectionError("blip")
        return R(200)

    out = h.request_with_retries(flaky, sleep=lambda s: None, attempts=2)
    assert out.status_code == 200


def test_retry_after_capped_at_max_sleep():
    seq = [R(429, {"Retry-After": "9999"}), R(200)]
    sleeps = []
    h.request_with_retries(lambda: seq.pop(0), sleep=sleeps.append, attempts=2, max_sleep=7)
    assert sleeps == [7.0]


def test_retry_after_http_date_form():
    seq = [R(429, {"Retry-After": "Wed, 21 Oct 2015 07:28:00 GMT"}), R(200)]
    sleeps = []
    # Past date → unparseable wait → falls back to backoff (explicit here);
    # the zero-sleep guard means wait=0.0 never calls sleep at all.
    out = h.request_with_retries(
        lambda: seq.pop(0), sleep=sleeps.append, attempts=2, backoff=0.0, max_sleep=60
    )
    assert out.status_code == 200
    assert sleeps == []


def test_retry_after_non_numeric_garbage_falls_back():
    seq = [R(429, {"Retry-After": "soon"}), R(200)]
    sleeps = []
    h.request_with_retries(
        lambda: seq.pop(0),
        sleep=sleeps.append,
        attempts=2,
        backoff=1.5,
        max_sleep=100,
    )
    assert sleeps == [1.5]


def test_zero_attempts_single_call():
    calls = []

    def fn():
        calls.append(1)
        return R(503)

    out = h.request_with_retries(fn, sleep=lambda s: None, attempts=0)
    assert out.status_code == 503
    assert len(calls) == 1


# ---------------------------------------------------------------------------
# Wiring: module seams actually retry
# ---------------------------------------------------------------------------


def test_xon_request_xon_retries(monkeypatch):
    seq = [R(429), R(200)]
    monkeypatch.setattr(
        xon.requests, "get", lambda *a, **k: seq.pop(0)
    )
    out = xon.request_xon("https://api.xposedornot.com/v1/check-email/x@y.com")
    assert out.status_code == 200


def test_email_lookup_retries(monkeypatch):
    seq = [R(503), R(200)]
    monkeypatch.setattr(
        el.requests, "get", lambda *a, **k: seq.pop(0)
    )
    out = el._lookup("someone@example.com")
    assert out.status_code == 200


def test_phone_breach_retries(monkeypatch):
    seq = [R(502), R(200)]
    monkeypatch.setattr(
        pbc.requests, "post", lambda *a, **k: seq.pop(0)
    )
    out = pbc._lookup("12025550123", api_key="k")
    assert out.status_code == 200


def test_password_checker_inherits_xon_retry(monkeypatch):
    # password_checker's seam goes through xon.request_xon → retries inherited
    seq = [R(429), R(404, json_data={"Error": "Not found"})]
    monkeypatch.setattr(
        xon.requests, "get", lambda *a, **k: seq.pop(0)
    )
    res = pc.run("test")
    assert res["exposed"] is False  # second call's 404 → safe result


def test_veriphone_stage_retries(monkeypatch):
    import modules.identity.phone_validator as pv

    seq = [
        R(429),
        R(200, json_data={"status": "success", "carrier": "T-Mobile"}),
    ]
    monkeypatch.setattr(pv.requests, "get", lambda *a, **k: seq.pop(0))
    monkeypatch.setenv("VERIPHONE_API_KEY", "k")
    res = pv.run("+13475550123")
    assert res["live"]["carrier"] == "T-Mobile"
