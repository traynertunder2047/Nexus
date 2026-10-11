import pytest

from modules.metadata.atlas.__main__ import render

SUCCESS_PAYLOAD = {
    "input": {"text": "Ristorante da Gigi, Roma", "language": "it", "country_prior": "italy"},
    "results": [
        {"lat": 41.8933203, "lon": 12.4829321, "display_name": "Roma, Roma Capitale, Lazio, Italia",
         "country": "Italia", "provider": "nominatim", "candidate": "Roma",
         "score": 1.1563247902186549, "prior_conflict": False},
        {"lat": 41.8520413, "lon": 12.6312117, "display_name": "Roma Capitale, Lazio, Italia",
         "country": "Italia", "provider": "nominatim", "candidate": "Roma",
         "score": 0.7686129565623993, "prior_conflict": False},
        {"lat": 26.4094075, "lon": -99.0144578, "display_name": "Roma, Starr County, Texas, United States",
         "country": "United States", "provider": "nominatim", "candidate": "Roma",
         "score": 0.1816830044510621, "prior_conflict": True},
        {"lat": 9.0, "lon": 9.0, "display_name": "Fourth, Should Not Appear",
         "country": "Italy", "provider": "nominatim", "candidate": "Roma",
         "score": 0.05, "prior_conflict": False},
    ],
    "final": {"method": "fusion", "lat": 41.8933203, "lon": 12.4829321,
              "confidence": 0.7, "radius_m": 100},
    "summary": "Location resolved from text references.",
}


def test_render_limits_to_top_3():
    out = render(SUCCESS_PAYLOAD, "Ristorante da Gigi, Roma")
    assert "Fourth, Should Not Appear" not in out
    assert "Roma, Roma Capitale, Lazio, Italia" in out
    assert "Roma, Starr County, Texas, United States" in out


def test_render_flags_prior_conflict():
    out = render(SUCCESS_PAYLOAD, "Ristorante da Gigi, Roma")
    assert "[country-prior conflict]" in out


def test_render_includes_final_and_map():
    out = render(SUCCESS_PAYLOAD, "Ristorante da Gigi, Roma")
    assert "Final: [41.8933203, 12.4829321]" in out
    assert "https://www.google.com/maps?q=41.8933203,12.4829321" in out
    assert "Location resolved from text references." in out


def test_render_empty_results():
    out = render({"input": {"text": "zzz"}, "results": [], "nearby": [],
                  "candidates": [], "final": {"method": "none", "lat": None, "lon": None},
                  "summary": "No place references found in the text."}, "zzz")
    assert "No candidate matches found." in out
    assert "Final:" not in out


def test_render_error_payload():
    assert render({"error": "empty input text"}, "") == "Atlas error: empty input text"
