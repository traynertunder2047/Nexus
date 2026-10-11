import requests

import modules.identity.social_linker as sl
from conftest import FakeResponse


def _get_calls(monkeypatch, responder):
    """Patch requests.get with `responder`; return the list of call kwargs."""
    calls = []

    def fake_get(url, **kwargs):
        calls.append({"url": url, **kwargs})
        return responder(url)

    monkeypatch.setattr(requests, "get", fake_get)
    return calls


# ---------------------------------------------------------------------------
# 1) Retries: 429 then success
# ---------------------------------------------------------------------------

def test_429_is_retried_and_recovers(monkeypatch):
    responses = [FakeResponse(429, text="slow down"), FakeResponse(200, text="<html>hi</html>")]

    calls = _get_calls(monkeypatch, lambda u: responses.pop(0))
    res = sl.check_site("GitHub", "https://github.com/foo", username="foo")
    assert res["exists"] is True
    assert len(calls) == 2  # first attempt got 429, retry succeeded


def test_retry_then_permanent_404_is_not_found(monkeypatch):
    responses = [FakeResponse(500, text="oops"), FakeResponse(404, text="")]

    calls = _get_calls(monkeypatch, lambda u: responses.pop(0))
    res = sl.check_site("GitHub", "https://github.com/foo", username="foo")
    assert res["exists"] is False
    assert len(calls) == 2  # retried once on 500, then permanent 404


def test_retries_exhausted_maps_to_unknown(monkeypatch):
    calls = _get_calls(monkeypatch, lambda u: FakeResponse(503, text="down"))

    res = sl.check_site("GitHub", "https://github.com/foo", username="foo")
    assert res["exists"] is None
    assert res["tag"] == "UNKNOWN (HTTP 503)"
    # default RETRY_ATTEMPTS=2 -> initial + 2 retries = 3 calls
    assert len(calls) == 3


def test_400_is_never_retried(monkeypatch):
    calls = _get_calls(monkeypatch, lambda u: FakeResponse(400, text=""))

    res = sl.check_site("GitHub", "https://github.com/foo", username="foo")
    assert res["exists"] is None
    assert res["tag"] == "UNKNOWN (HTTP 400)"
    assert len(calls) == 1  # permanent status: no retry


def test_retry_after_header_is_honored(monkeypatch):
    sleeps = []
    responses = [FakeResponse(429, text="", headers={"Retry-After": "7"}),
                 FakeResponse(200, text="<html>ok</html>")]

    import modules.identity.helpers as h
    real = h.request_with_retries

    def recording(fn, **kwargs):
        kwargs["sleep"] = sleeps.append
        kwargs["max_sleep"] = 60  # override the suite's RETRY_MAX_SLEEP=0 cap
        return real(fn, **kwargs)

    monkeypatch.setattr(sl, "request_with_retries", recording)
    calls = _get_calls(monkeypatch, lambda u: responses.pop(0))
    res = sl.check_site("GitHub", "https://github.com/foo", username="foo")
    assert res["exists"] is True
    assert sleeps == [7.0]
    assert len(calls) == 2


def test_transport_error_exhaustion_maps_to_error_result(monkeypatch):
    def boom(url, **kwargs):
        raise requests.ConnectionError("refused")

    monkeypatch.setattr(requests, "get", boom)
    res = sl.check_site("GitHub", "https://github.com/foo", username="foo")
    assert res["exists"] is None
    assert res["tag"] == "ERROR (request failed)"
    assert "refused" in res["note"]


# ---------------------------------------------------------------------------
# 2) Proxy propagation
# ---------------------------------------------------------------------------

def test_proxies_reach_requests_get(monkeypatch):
    proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

    calls = _get_calls(monkeypatch, lambda u: FakeResponse(200, text="<html>x</html>"))
    sl.check_site("GitHub", "https://github.com/foo", username="foo", proxies=proxies)
    assert calls[0]["proxies"] == proxies


def test_no_proxies_by_default(monkeypatch):
    calls = _get_calls(monkeypatch, lambda u: FakeResponse(200, text="<html>x</html>"))
    sl.check_site("GitHub", "https://github.com/foo", username="foo")
    assert calls[0].get("proxies") is None


def test_run_falls_back_to_env_proxy(monkeypatch):
    captured = {}

    def fake_resolve(username=None, platforms=None, timeout=10, proxies=None, use_cache=True):
        captured["proxies"] = proxies
        return {"error": "stop"}

    monkeypatch.setenv("SOCIAL_LINKER_PROXY", "socks5://127.0.0.1:9050")
    monkeypatch.setattr(sl, "resolve_entity", fake_resolve)
    sl.run("foo")
    assert captured["proxies"] == {"http": "socks5://127.0.0.1:9050",
                                   "https": "socks5://127.0.0.1:9050"}


def test_explicit_proxies_beat_env(monkeypatch):
    captured = {}
    explicit = {"http": "http://explicit:1", "https": "http://explicit:1"}

    def fake_resolve(username=None, platforms=None, timeout=10, proxies=None, use_cache=True):
        captured["proxies"] = proxies
        return {"error": "stop"}

    monkeypatch.setenv("SOCIAL_LINKER_PROXY", "http://env:2")
    monkeypatch.setattr(sl, "resolve_entity", fake_resolve)
    sl.run("foo", proxies=explicit)
    assert captured["proxies"] == explicit


# ---------------------------------------------------------------------------
# 3) Negative-result cache
# ---------------------------------------------------------------------------

def setup_function(fn=None):
    sl.clear_cache()


def teardown_function(fn=None):
    sl.clear_cache()


def test_negative_result_is_cached(monkeypatch):
    calls = _get_calls(monkeypatch, lambda u: FakeResponse(404, text=""))
    # Two platforms, both miss.
    sl.resolve_entity("nobody", platforms=["GitHub", "Steam"])
    first_calls = len(calls)
    assert first_calls == 2

    # Same scan again: both answers come from cache, no new HTTP.
    res = sl.resolve_entity("nobody", platforms=["GitHub", "Steam"])
    assert len(calls) == first_calls
    assert res["profile_count"] == 0
    by_name = {p["name"]: p for p in res["profiles"]}
    assert by_name["GitHub"]["cached"] is True
    assert by_name["GitHub"]["exists"] is False


def test_positive_and_unknown_results_are_not_cached(monkeypatch):
    state = {"n": 0}

    def responder(url):
        state["n"] += 1
        if state["n"] == 1:
            return FakeResponse(200, text="<html>profile here</html>")  # found
        return FakeResponse(403, text="blocked")  # unknown

    _get_calls(monkeypatch, responder)
    sl.resolve_entity("somebody", platforms=["GitHub", "X"])
    assert state["n"] == 2

    # GitHub (found) and X (403 unknown) must be re-probed — neither is cached.
    sl.resolve_entity("somebody", platforms=["GitHub", "X"])
    assert state["n"] == 4


def test_cached_entry_respects_ttl(monkeypatch):
    import modules.identity.social_linker as mod

    calls = _get_calls(monkeypatch, lambda u: FakeResponse(404, text=""))
    mod.resolve_entity("gone", platforms=["GitHub"], ttl=60)
    assert len(calls) == 1

    # Age the entry past its TTL, then the site must be probed again.
    key = mod._cache_key("https://github.com/gone")
    expiry, result = mod._NEG_CACHE[key]
    mod._NEG_CACHE[key] = (mod._time.monotonic() - 1, result)
    mod.resolve_entity("gone", platforms=["GitHub"], ttl=60)
    assert len(calls) == 2


def test_clear_cache_forces_reprobe(monkeypatch):
    calls = _get_calls(monkeypatch, lambda u: FakeResponse(404, text=""))
    sl.resolve_entity("fresh", platforms=["GitHub"])
    sl.clear_cache()
    sl.resolve_entity("fresh", platforms=["GitHub"])
    assert len(calls) == 2


def test_use_cache_false_skips_cache(monkeypatch):
    calls = _get_calls(monkeypatch, lambda u: FakeResponse(404, text=""))
    sl.resolve_entity("nocache", platforms=["GitHub"], use_cache=False)
    sl.resolve_entity("nocache", platforms=["GitHub"], use_cache=False)
    assert len(calls) == 2
    # and nothing was stored
    assert sl._NEG_CACHE == {}


def test_cache_is_per_url(monkeypatch):
    calls = _get_calls(monkeypatch, lambda u: FakeResponse(404, text=""))
    sl.resolve_entity("usera", platforms=["GitHub"])
    # A different username has a different URL -> must be probed live.
    sl.resolve_entity("userb", platforms=["GitHub"])
    assert len(calls) == 2


# ---------------------------------------------------------------------------
# 4) best_candidate removal / legacy key compat
# ---------------------------------------------------------------------------

def test_resolved_username_kept_for_compat(monkeypatch):
    # resolve_entity no longer carries resolved_username (vestigial best_candidate
    # removal); run() re-adds it for backward compatibility of the unified payload.
    calls = _get_calls(monkeypatch, lambda u: FakeResponse(200, text="<html>hi</html>"))
    payload = sl.run("found_user", platforms=["GitHub"])
    assert payload["resolved_username"] == "found_user"


def test_run_payload_still_unified(monkeypatch):
    calls = _get_calls(monkeypatch, lambda u: FakeResponse(200, text="<html>hi</html>"))
    payload = sl.run("found_user", platforms=["GitHub"])
    assert payload["status"] == "ok"
    assert payload["query"] == {"username": "found_user", "provider": "social_linker"}
    assert payload["findings"] == ["Found on GitHub: https://github.com/found_user"]
    assert payload["elapsed_ms"] >= 0


# ---------------------------------------------------------------------------
# 5) CLI flags
# ---------------------------------------------------------------------------

def test_cli_no_cache_flag(monkeypatch, capsys):
    calls = _get_calls(monkeypatch, lambda u: FakeResponse(404, text=""))
    rc = sl.main(["--json", "--no-cache", "ghost"])
    assert rc == 0  # no_data status
    out = capsys.readouterr().out
    assert '"status": "no_data"' in out
    assert len(calls) == len(sl.SOCIAL_MEDIA)  # every site probed live


def test_cli_proxy_flag_reaches_run(monkeypatch):
    captured = {}

    def fake_run(username, **kwargs):
        captured.update(kwargs)
        return {"status": "no_data", "username": username, "findings": [],
                "summary": "none", "profiles": [], "profile_count": 0,
                "unverified_count": 0, "confidence": 0, "elapsed_ms": 1,
                "query": {"username": username, "provider": "social_linker"}}

    monkeypatch.setattr(sl, "run", fake_run)
    rc = sl.main(["--proxy", "socks5://127.0.0.1:9050", "ghost"])
    assert rc == 0
    assert captured["proxies"] == {"http": "socks5://127.0.0.1:9050",
                                   "https": "socks5://127.0.0.1:9050"}
    assert captured["use_cache"] is True


def test_cli_requires_proxy_value(capsys):
    rc = sl.main(["--proxy"])
    assert rc == 2
