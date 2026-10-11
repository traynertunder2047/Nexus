import requests

from modules.identity import social_linker as sl
from conftest import FakeResponse


def _gh_ctx():
    return {"name": "GitHub", "url": "https://github.com/foo"}


def test_404_means_not_found(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse(404))
    res = sl.check_site("GitHub", "https://github.com/foo", username="foo")
    assert res["exists"] is False
    assert res["tag"] == "NOT FOUND (404)"


def test_200_plain_site_is_found(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse(200, text="<html>Hi</html>"))
    res = sl.check_site("GitHub", "https://github.com/foo", username="foo")
    assert res["exists"] is True
    assert res["tag"] == "FOUND"


def test_soft404_via_missing_marker(monkeypatch):
    # Steam treats pages it cannot find as HTTP 200 with a marker.
    text = "The specified profile could not be found."
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse(200, text=text))
    res = sl.check_site("Steam", "https://steamcommunity.com/id/foo", username="foo")
    assert res["exists"] is False
    assert res["tag"] == "NOT FOUND (soft 404)"


def test_soft404_username_not_in_page(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse(200, text="<html>No match here</html>"))
    res = sl.check_site("Twitch", "https://www.twitch.tv/foo", username="foo")
    assert res["exists"] is False


def test_ambiguous_soft404_possible_site(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse(200, text="<html>x</html>"))
    res = sl.check_site("Pinterest", "https://www.pinterest.com/foo/", username="foo")
    assert res["exists"] is None  # 200 is ambiguous on Pinterest
    assert res["tag"] == "UNKNOWN (200 ambiguous)"


def test_blocked_999(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse(999, text=""))
    res = sl.check_site("LinkedIn", "https://www.linkedin.com/in/foo", username="foo")
    assert res["exists"] is None
    assert "blocked" in res["tag"].lower()


def test_redirect_to_login_wall(monkeypatch):
    resp = FakeResponse(302, text="")
    resp.headers["Location"] = "https://x.com/login"
    monkeypatch.setattr(requests, "get", lambda *a, **k: resp)
    res = sl.check_site("X", "https://x.com/foo", username="foo")
    assert res["exists"] is None
    assert res["tag"] == "UNKNOWN (login wall)"


def test_api_probe_tiktok(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse(200, json_data={}))
    site = {
        "name": "TikTok",
        "url": "https://www.tiktok.com/@foo",
        "api_url": "https://www.tiktok.com/oembed?url=https://www.tiktok.com/@foo",
    }
    res = sl.check_site("TikTok", "https://www.tiktok.com/@foo", username="foo", site_config=site)
    assert res["exists"] is True
    assert res["tag"] == "FOUND (API)"


def test_request_error_recorded(monkeypatch):
    def boom(*a, **k):
        raise requests.RequestException("timeout")

    monkeypatch.setattr(requests, "get", boom)
    res = sl.check_site("GitHub", "https://github.com/foo", username="foo")
    assert res["exists"] is None
    assert res["tag"] == "ERROR (request failed)"


def test_resolve_entity_requires_username():
    assert "error" in sl.resolve_entity(username=None)
    assert "error" in sl.resolve_entity(username="   ")


def test_resolve_entity_unknown_platform():
    res = sl.resolve_entity("foo", platforms=["NotARealSite"])
    assert "error" in res
    assert "Unknown platform" in res["error"]


def test_resolve_entity_no_profiles_found(monkeypatch):
    # Every probed site returns 404 -> nothing confirmed.
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse(404))
    res = sl.resolve_entity("nobodyhome", platforms=["GitHub", "Steam"])
    assert res["profile_count"] == 0
    assert "No profiles found" in res["summary"]
