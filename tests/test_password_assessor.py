import json

import pytest
import requests

import modules.identity.password_assessor as pa
import modules.identity.password_checker as pc
from conftest import FakeResponse


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def mock_breach(monkeypatch, status_code=404, payload=None):
    """Patch password_checker's seam; returns the list of seen prefixes."""
    seen = []

    def fake_lookup(prefix, timeout=10):
        seen.append(prefix)
        return FakeResponse(status_code, payload or {"Error": "Not found"})

    monkeypatch.setattr(pc, "_lookup", fake_lookup)
    return seen


STRONG_PW = "corrEct-horse-battery-2026!x"
WEAK_PW = "123456"


# ---------------------------------------------------------------------------
# verdict matrix
# ---------------------------------------------------------------------------


def test_verdict_matrix():
    assert pa._verdict({"score": 90}, {"exposed": True}) == "compromised"
    assert pa._verdict({"score": 10}, {"exposed": False}) == "weak"
    assert pa._verdict({"score": 50}, {"exposed": False}) == "fair"
    assert pa._verdict({"score": 80}, {"exposed": False}) == "strong"
    assert pa._verdict({"score": 90}, None) == "strong"


# ---------------------------------------------------------------------------
# fusion behaviour
# ---------------------------------------------------------------------------


def test_strong_and_not_breached(monkeypatch):
    seen = mock_breach(monkeypatch, 404)
    res = pa.run(STRONG_PW)
    assert res["status"] == "ok"
    assert res["verdict"] == "strong"
    assert res["strength"]["score"] >= 60
    assert res["breach"]["exposed"] is False
    assert len(seen) == 1 and len(seen[0]) == 10  # k-anonymity prefix only
    assert "Not found in known breach databases." in res["findings"]


def test_weak_password_not_breached(monkeypatch):
    mock_breach(monkeypatch, 404)
    res = pa.run(WEAK_PW)
    assert res["verdict"] == "weak"
    assert res["strength"]["score"] < 40


def test_compromised_wins_over_strength(monkeypatch):
    # A leaked "Very Strong" password must still be COMPROMISED
    payload = {
        "SearchPassAnon": {"anon": "abcdefghij", "char": "D:0;A:9;S:0;L:9", "count": "2", "wordlist": 0}
    }
    mock_breach(monkeypatch, 200, payload)
    res = pa.run(STRONG_PW)
    assert res["verdict"] == "compromised"
    assert res["breach"]["count"] == 2
    assert "do NOT reuse" in " ".join(res["findings"])
    assert res["summary"].startswith("COMPROMISED")


def test_breach_failure_is_contained(monkeypatch):
    def boom(prefix, timeout=10):
        raise requests.RequestException("network down")

    monkeypatch.setattr(pc, "_lookup", boom)
    res = pa.run(STRONG_PW)
    assert res["status"] == "ok"  # strength verdict stands
    assert res["verdict"] == "strong"
    assert res["breach"]["status"] == "error"
    assert "network down" in res["breach"]["error"]
    assert any("Breach check unavailable" in f for f in res["findings"])
    assert "could not complete" in res["summary"]


def test_check_breaches_false_skips_network(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("must not touch the network")

    monkeypatch.setattr(pc, "_lookup", boom)
    res = pa.run(STRONG_PW, check_breaches=False)
    assert res["status"] == "ok"
    assert res["breach"] is None
    assert res["verdict"] == "strong"
    assert "skipped" in res["summary"]


def test_empty_and_nonstring_passwords():
    for bad in ("", None, 12345):
        res = pa.run(bad)
        assert res["status"] == "error"
        assert "non-empty string" in res["error"]


# ---------------------------------------------------------------------------
# privacy guarantees
# ---------------------------------------------------------------------------


def test_password_never_appears_in_payload(monkeypatch):
    mock_breach(monkeypatch, 404)
    res = pa.run("SuperSecret!Password99")
    blob = json.dumps(res)
    assert "SuperSecret!Password99" not in blob
    assert "SuperSecret!Password99" not in str(res["query"])
    # the k-anonymity prefix is present, but that's by design (10 hex chars)
    assert len(res["breach"]["hash_prefix"]) == 10


def test_assess_password_alias(monkeypatch):
    mock_breach(monkeypatch, 404)
    assert pa.assess_password(STRONG_PW) == pa.run(STRONG_PW)


# ---------------------------------------------------------------------------
# render + CLI
# ---------------------------------------------------------------------------


def test_render_success(monkeypatch):
    mock_breach(monkeypatch, 404)
    out = pa.render(pa.run(STRONG_PW))
    assert "verdict STRONG" in out
    assert "Strength  :" in out
    assert "Breach    : exposed=False" in out


def test_render_breach_failure(monkeypatch):
    def boom(prefix, timeout=10):
        raise requests.RequestException("down")

    monkeypatch.setattr(pc, "_lookup", boom)
    out = pa.render(pa.run(STRONG_PW))
    assert "Breach    : failed" in out


def test_render_breach_skipped():
    out = pa.render(pa.run(STRONG_PW, check_breaches=False))
    assert "skipped" in out


def test_render_error_envelope():
    out = pa.render(pa.run(""))
    assert "Password Assessor failed" in out


def test_cli_json_offline(capsys):
    rc = pa.main([STRONG_PW, "--skip-breach", "--json"])
    captured = capsys.readouterr().out
    payload = json.loads(captured)
    assert rc == 0
    assert payload["verdict"] == "strong"
    assert payload["breach"] is None


def test_cli_rejects_multiple_passwords(capsys):
    rc = pa.main(["one", "two"])
    assert rc == 2


# ---------------------------------------------------------------------------
# password_checker: multi-block Keccak-512 against an independent reference
# ---------------------------------------------------------------------------


def test_keccak_512_multiblock_matches_reference():
    """Sizes around the 72-byte rate must match pycryptodome's Keccak-512.

    Guards the absorb loop + exact-multiple padding, which the original
    short-string vectors never exercised.
    """
    Crypto_Keccak = pytest.importorskip("Crypto.Hash.keccak")
    from modules.identity.password_checker import _keccak_512

    data = bytes(range(256)) * 4  # deterministic pseudo-random bytes
    for size in (0, 1, 71, 72, 73, 144, 200, 1000):
        chunk = data[:size]
        expected = Crypto_Keccak.new(data=chunk, digest_bits=512).hexdigest()
        assert _keccak_512(chunk) == expected, f"Keccak-512 mismatch at size {size}"
