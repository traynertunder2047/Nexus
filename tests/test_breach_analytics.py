import requests

from modules.identity.breach_analytics import (
    _flatten_industries,
    _parse_yearwise,
    _parse_exposed_data,
    run,
)
from conftest import FakeResponse


def _payload(**overrides):
    data = {
        "BreachMetrics": {
            "risk": [{"risk_label": "High", "risk_score": 80}],
            "passwords_strength": [
                {"EasyToCrack": 3, "PlainText": 1, "StrongHash": 5, "Unknown": 0}
            ],
            "industry": [[["elec", 5], ["mini", 2]]],
            "yearwise_details": [{"y2015": 1, "y2007": 0, "y2010": 4}],
            "xposed_data": [
                {
                    "children": [
                        {
                            "name": "Personal Info",
                            "children": [
                                {"name": "data_email", "value": 2},
                                {"name": "data_phone", "value": 1},
                            ],
                        }
                    ]
                }
            ],
        },
        "ExposedBreaches": {
            "breaches_details": [
                {"breach": "A", "xposed_records": 100},
                {"breach": "B", "xposed_records": 50},
            ]
        },
        "BreachesSummary": {"site": "A;B;C"},
        "ExposedPastes": [],
        "PastesSummary": {"cnt": 2},
    }
    data.update(overrides)
    return data


def test_run_parses_full_payload(monkeypatch):
    monkeypatch.setattr(
        requests, "get", lambda *a, **k: FakeResponse(200, _payload())
    )
    res = run("victim@example.com")
    assert "error" not in res
    assert res["found"] is True
    assert res["breach_count"] == 2
    assert res["sites"] == ["A", "B", "C"]
    assert res["risk"] == {"label": "High", "score": 80}
    assert res["total_exposed_records"] == 150
    assert res["paste_count"] == 2
    assert res["password_strength"]["strong_hash"] == 5
    # industries sorted by count desc
    assert res["industries"] == [{"code": "elec", "count": 5}, {"code": "mini", "count": 2}]
    # year-wise excludes the falsy 0 entry
    assert res["years"] == [{"year": 2010, "count": 4}, {"year": 2015, "count": 1}]
    assert res["exposed_data"][0]["category"] == "Personal Info"
    assert res["exposed_data"][0]["items"][0]["name"] == "email"


def test_run_not_found_when_metrics_or_breaches_null(monkeypatch):
    monkeypatch.setattr(
        requests,
        "get",
        lambda *a, **k: FakeResponse(
            200, {"BreachMetrics": None, "ExposedBreaches": None}
        ),
    )
    res = run("clean@example.com")
    assert res["found"] is False
    assert res["breach_count"] == 0


def test_invalid_email_and_error_paths(monkeypatch):
    assert "error" in run("nope")

    def boom(*a, **k):
        raise requests.RequestException("down")

    monkeypatch.setattr(requests, "get", boom)
    assert "Failed to connect" in run("a@b.com")["error"]


def test_helpers():
    assert _flatten_industries([[["elec", 1], ["mini", 3]]]) == [
        {"code": "mini", "count": 3},
        {"code": "elec", "count": 1},
    ]
    assert _parse_yearwise([{"y2007": 0, "y2015": 1, "y2010": 4}]) == [
        {"year": 2010, "count": 4},
        {"year": 2015, "count": 1},
    ]
    assert _parse_exposed_data(None) == []
