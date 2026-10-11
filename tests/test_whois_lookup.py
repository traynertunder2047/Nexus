import json
import threading
import time
from datetime import datetime, timedelta, timezone

import modules.network.whois_lookup as wl

NOW = datetime(2026, 8, 1, 12, 0, 0, tzinfo=timezone.utc)


class FakeDomain:
    """Synthetic whoisdomain.Domain stand-in with realistic defaults."""

    def __init__(self, **overrides):
        defaults = {
            "name": "example.com",
            "registrar": "RESERVED-Internet Assigned Numbers Authority",
            "registrar_url": "https://example.com",
            "registrant": "",
            "admin": "",
            "abuse_contact": "abuse@iana.org",
            "emails": ["abuse@iana.org"],
            "creation_date": datetime(1995, 8, 14, 4, 0),
            "updated_date": datetime(2026, 1, 1, 8, 0),
            "expiration_date": datetime(2027, 8, 13, 4, 0),
            "name_servers": ["A.IANA-SERVERS.NET", "b.iana-servers.net."],
            "status": "client delete prohibited",
            "statuses": ["client delete prohibited", "client transfer prohibited"],
            "dnssec": True,
        }
        defaults.update(overrides)
        self.__dict__.update(defaults)


# ---------------------------------------------------------------------------
# Field mapping
# ---------------------------------------------------------------------------

def test_map_registration_ok():
    mapped = wl.map_registration(FakeDomain())
    assert mapped["registrar"]["name"] == "RESERVED-Internet Assigned Numbers Authority"
    assert mapped["registrar"]["url"] == "https://example.com"
    assert mapped["dates"]["created"] == "1995-08-14T04:00:00+00:00"
    assert mapped["dates"]["expires"] == "2027-08-13T04:00:00+00:00"
    # trailing dots stripped + lowercased + sorted + deduped
    assert mapped["name_servers"] == ["a.iana-servers.net", "b.iana-servers.net"]
    assert mapped["security"]["dnssec"] is True
    assert mapped["contacts"]["emails"] == ["abuse@iana.org"]
    # empty registrant/admin collapse to "redacted"
    assert mapped["contacts"]["registrant"] == "redacted"
    assert mapped["contacts"]["admin"] == "redacted"
    assert mapped["contacts"]["abuse"] == "abuse@iana.org"


def test_map_registration_public_contacts():
    d = FakeDomain(registrant="ACME Corp", admin="admin@acme.example",
                   abuse_contact="abuse@acme.example")
    mapped = wl.map_registration(d)
    assert mapped["contacts"]["registrant"] == "ACME Corp"
    assert mapped["contacts"]["admin"] == "admin@acme.example"
    assert mapped["contacts"]["abuse"] == "abuse@acme.example"


def test_map_registration_privacy_proxy_flag():
    d = FakeDomain(registrant="REDACTED FOR PRIVACY",
                   admin="contact@privacyguard.example")
    mapped = wl.map_registration(d)
    assert mapped["contacts"]["registrant"] == "redacted"
    assert mapped["contacts"]["admin"] == "redacted"


def test_contact_flat_empty_is_redacted():
    assert wl._contact_flat("") == "redacted"
    assert wl._contact_flat(None) == "redacted"
    assert wl._contact_flat("  ACME Corp  ") == "ACME Corp"


def test_name_servers_single_string():
    d = FakeDomain(name_servers="ns1.example.net.")
    assert wl._name_servers(d) == ["ns1.example.net"]


def test_statuses_from_string_fallback():
    d = FakeDomain(statuses=[], status="client hold\npending delete")
    statuses = wl._statuses(d)
    assert "client hold" in statuses and "pending delete" in statuses


def test_epp_flags_filter_noise():
    assert wl._epp_flag(wl._statuses(FakeDomain())) == []  # transfer-prohibited = noise
    assert wl._epp_flag(["client hold", "redemption period"]) == ["client hold", "redemption period"]


def test_dates_missing_ok():
    d = FakeDomain(creation_date=None, expiration_date=None)
    mapped = wl.map_registration(d)
    assert mapped["dates"]["created"] is None
    assert mapped["dates"]["expires"] is None


# ---------------------------------------------------------------------------
# Registration-age / expiry analysis
# ---------------------------------------------------------------------------

def test_registration_age_days():
    created = datetime(2025, 1, 1, tzinfo=timezone.utc)
    assert wl.registration_age_days(created, NOW) == (NOW - created).days
    assert wl.registration_age_days(None, NOW) is None
    # future creation date clamps to 0
    future = NOW + timedelta(days=5)
    assert wl.registration_age_days(future, NOW) == 0


def test_days_to_expiry():
    expires = NOW + timedelta(days=45)
    assert wl.days_to_expiry(expires, NOW) == 45
    assert wl.days_to_expiry(NOW - timedelta(days=3), NOW) == -3
    assert wl.days_to_expiry(None, NOW) is None


def test_analyze_recently_registered():
    d = FakeDomain(creation_date=NOW - timedelta(days=30))
    a = wl.analyze_registration(d, now=NOW)
    assert a["recently_registered"] is True
    assert a["age_days"] == 30
    assert any("Recently registered" in n for n in a["notes"])


def test_analyze_expiring_soon():
    d = FakeDomain(expiration_date=NOW + timedelta(days=30))
    a = wl.analyze_registration(d, now=NOW)
    assert a["expiring_soon"] is True
    assert a["days_to_expiry"] == 30
    assert any("Expires within" in n for n in a["notes"])


def test_analyze_expired():
    d = FakeDomain(expiration_date=NOW - timedelta(days=10))
    a = wl.analyze_registration(d, now=NOW)
    assert a["expired"] is True
    assert any("EXPIRED" in n for n in a["notes"])


def test_analyze_no_red_flags():
    a = wl.analyze_registration(FakeDomain(), now=NOW)
    assert a["recently_registered"] is False
    assert a["expiring_soon"] is False
    assert a["expired"] is False
    assert any("No registration-age/expiry red flags" in n for n in a["notes"])


# ---------------------------------------------------------------------------
# findings
# ---------------------------------------------------------------------------

def test_build_findings_redaction_flagged():
    d = FakeDomain()  # registrant/admin redacted, abuse present
    mapped = wl.map_registration(d)
    findings = wl.build_findings(mapped, wl.analyze_registration(d, now=NOW))
    assert any("2/2 identity contact(s) redacted" in f for f in findings)
    assert any("No registration-age/expiry red flags" in f for f in findings)


def test_build_findings_no_redaction():
    d = FakeDomain(registrant="ACME Corp", admin="admin@acme.example")
    mapped = wl.map_registration(d)
    findings = wl.build_findings(mapped, wl.analyze_registration(d, now=NOW))
    assert not any("redacted" in f for f in findings)


def test_build_findings_epp_flag():
    d = FakeDomain(statuses=["client hold", "client transfer prohibited"])
    mapped = wl.map_registration(d)
    findings = wl.build_findings(mapped, wl.analyze_registration(d, now=NOW))
    assert any("client hold" in f for f in findings)


def test_build_findings_dnssec_disabled_old_domain():
    d = FakeDomain(dnssec=False,
                   creation_date=datetime(2005, 1, 1, tzinfo=timezone.utc))
    mapped = wl.map_registration(d)
    findings = wl.build_findings(mapped, wl.analyze_registration(d, now=NOW))
    assert any("DNSSEC not enabled" in f for f in findings)


# ---------------------------------------------------------------------------
# run() + error taxonomy
# ---------------------------------------------------------------------------

def test_run_success(monkeypatch):
    monkeypatch.setattr(wl, "_lookup", lambda *a, **k: FakeDomain())
    out = wl.run("example.com")
    assert out["status"] == "ok"
    assert out["query"]["method"] == "auto"
    assert isinstance(out["query"]["elapsed_ms"], int)
    # timeline merges raw dates with derived analysis
    assert "1995-08-14T04:00:00+00:00" in out["timeline"]["created"]
    assert out["timeline"]["age_days"] > 0
    assert out["registrar"]["name"] == "RESERVED-Internet Assigned Numbers Authority"
    assert "example.com:" in out["summary"]
    assert "2 name server(s)" in out["summary"]


def test_run_success_status_ok_top_level(monkeypatch):
    monkeypatch.setattr(wl, "_lookup", lambda *a, **k: FakeDomain())
    out = wl.run("example.com")
    assert out["status"] == "ok"
    # every success payload has the full semantic group set
    for key in ("domain", "status", "query", "registrar", "contacts",
                "timeline", "name_servers", "security", "findings", "summary"):
        assert key in out


def test_run_invalid_input():
    out = wl.run("")
    assert out["status"] == "error"
    assert "No domain" in out["error"]
    assert "error" in wl.run("not a domain!")
    assert "error" in wl.run("localhost")


def test_run_none_result(monkeypatch):
    monkeypatch.setattr(wl, "_lookup", lambda *a, **k: None)
    out = wl.run("example.com")
    assert out["status"] == "no_data"
    assert "No WHOIS/RDAP record" in out["error"]


def test_run_unknown_tld_error(monkeypatch):
    def boom(*a, **k):
        raise wl.whoisdomain.UnknownTldError("nope.tld")
    monkeypatch.setattr(wl, "_lookup", boom)
    out = wl.run("example.com")
    assert out["status"] == "error"
    assert "Unsupported TLD" in out["error"]


def test_run_timeout_error(monkeypatch):
    def boom(*a, **k):
        raise wl.whoisdomain.WhoisCommandTimeoutError("slow")
    monkeypatch.setattr(wl, "_lookup", boom)
    out = wl.run("example.com")
    assert out["status"] == "error"
    assert "timed out" in out["error"]


def test_run_quota_error(monkeypatch):
    def boom(*a, **k):
        raise wl.whoisdomain.WhoisQuotaExceededError("quota")
    monkeypatch.setattr(wl, "_lookup", boom)
    out = wl.run("example.com")
    assert out["status"] == "error"
    assert "quota" in out["error"].lower()


def test_run_private_registry_error(monkeypatch):
    def boom(*a, **k):
        raise wl.whoisdomain.WhoisPrivateRegistryError("private")
    monkeypatch.setattr(wl, "_lookup", boom)
    out = wl.run("example.com")
    assert out["status"] == "error"
    assert "private" in out["error"].lower()


def test_run_parse_error(monkeypatch):
    def boom(*a, **k):
        raise wl.whoisdomain.FailedParsingWhoisOutputError("unparseable")
    monkeypatch.setattr(wl, "_lookup", boom)
    out = wl.run("example.com")
    assert out["status"] == "error"
    assert "unparseable" in out["error"]


def test_run_command_failed_error(monkeypatch):
    def boom(*a, **k):
        raise wl.whoisdomain.WhoisCommandFailedError("cmd failed")
    monkeypatch.setattr(wl, "_lookup", boom)
    out = wl.run("example.com")
    assert out["status"] == "error"
    assert "command failed" in out["error"]


def test_run_generic_whois_error(monkeypatch):
    def boom(*a, **k):
        raise wl._whois_exc.WhoisExceptionError("mystery")
    monkeypatch.setattr(wl, "_lookup", boom)
    out = wl.run("example.com")
    assert out["status"] == "error"
    assert "WHOIS error" in out["error"]


# ---------------------------------------------------------------------------
# renderer
# ---------------------------------------------------------------------------

def test_render_success(monkeypatch):
    monkeypatch.setattr(wl, "_lookup", lambda *a, **k: FakeDomain())
    text = wl.render(wl.run("example.com"))
    assert text.startswith("WHOIS Lookup: example.com")
    assert "Registrar" in text
    assert "Registered" in text and "days ago" in text
    assert "Expires" in text and "in " in text
    assert "abuse: abuse@iana.org" in text
    assert "Findings" in text


def test_render_error():
    text = wl.render({"status": "error", "domain": "x.example",
                      "error": "Unsupported TLD: .zzz"})
    assert "failed" in text
    assert "Unsupported TLD: .zzz" in text


def test_render_no_data():
    text = wl.render({"status": "no_data", "domain": "x.example",
                      "error": "no WHOIS/RDAP record"})
    assert "returned no data" in text


def test_render_redacted_contacts(monkeypatch):
    monkeypatch.setattr(wl, "_lookup", lambda *a, **k: FakeDomain())
    text = wl.render(wl.run("example.com"))
    assert "registrant: redacted" in text
    assert "admin: redacted" in text


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def test_main_usage_no_args(capsys):
    assert wl.main([]) == 1
    out = capsys.readouterr().out
    assert "Usage:" in out


def test_main_json_flag(monkeypatch, capsys):
    monkeypatch.setattr(wl, "_lookup", lambda *a, **k: FakeDomain())
    rc = wl.main(["--json", "example.com"])
    import json
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["status"] == "ok"


def test_main_human_flag(monkeypatch, capsys):
    monkeypatch.setattr(wl, "_lookup", lambda *a, **k: FakeDomain())
    rc = wl.main(["example.com"])
    out = capsys.readouterr().out
    assert rc == 0
    assert out.startswith("WHOIS Lookup: example.com")
    assert "{json" not in out  # not the raw dumps


def test_main_error_exit_code(monkeypatch, capsys):
    def boom(*a, **k):
        raise wl.whoisdomain.UnknownTldError("nope.tld")
    monkeypatch.setattr(wl, "_lookup", boom)
    rc = wl.main(["example.com"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "failed" in out


# ---------------------------------------------------------------------------
# CLI --multi: one domain per call by default, a race behind the flag
# ---------------------------------------------------------------------------

def test_main_rejects_two_domains_without_multi(monkeypatch, capsys):
    """The base command is single-domain: a second one is refused, not dropped."""
    calls = []
    monkeypatch.setattr(wl, "_lookup",
                        lambda *a, **k: calls.append(a) or FakeDomain())
    assert wl.main(["a.example", "b.example"]) == 2
    captured = capsys.readouterr()
    assert "One domain at a time." in captured.err
    assert "--multi" in captured.err
    assert "Usage:" in captured.out
    assert calls == []  # nothing was queried


def test_main_multi_no_domains_prints_usage(capsys):
    assert wl.main(["--multi"]) == 1
    assert "Usage:" in capsys.readouterr().out


def test_main_multi_single_domain_still_ok(monkeypatch, capsys):
    """--multi with one domain degrades to the plain single-domain output."""
    monkeypatch.setattr(wl, "_lookup", lambda *a, **k: FakeDomain())
    rc = wl.main(["--multi", "example.com"])
    stdout = capsys.readouterr().out
    assert rc == 0
    assert stdout.startswith("WHOIS Lookup: example.com")
    assert "[1/1]" not in stdout  # no race header for a single domain


def test_main_multi_short_alias(monkeypatch, capsys):
    monkeypatch.setattr(wl, "_lookup", lambda *a, **k: FakeDomain())
    assert wl.main(["-m", "a.example", "b.example"]) == 0
    stdout = capsys.readouterr().out
    assert "[1/2]" in stdout and "[2/2]" in stdout


def test_main_multi_prints_in_arrival_order(monkeypatch, capsys):
    """The first domain typed answers last, so its block is printed last."""
    gates = {"first.example": threading.Event(),
             "second.example": threading.Event()}
    fast_consumed = threading.Event()
    real_render = wl.render

    def fake_lookup(domain, *a, **k):
        gates[domain].wait(timeout=5)
        return FakeDomain(name=domain)

    def spy_render(payload):
        if payload["domain"] == "second.example":
            # _race consumes futures one at a time on this thread, so once the
            # fast block is being rendered nothing else can be printed first.
            fast_consumed.set()
        return real_render(payload)

    monkeypatch.setattr(wl, "_lookup", fake_lookup)
    monkeypatch.setattr(wl, "render", spy_render)

    outcome = {}
    thread = threading.Thread(
        target=lambda: outcome.update(
            rc=wl.main(["--multi", "first.example", "second.example"])))
    thread.start()
    gates["second.example"].set()      # answer the domain typed second
    assert fast_consumed.wait(timeout=5), "the fast domain never got printed"
    gates["first.example"].set()       # only now let the slow one answer
    thread.join(timeout=10)

    stdout = capsys.readouterr().out
    assert outcome["rc"] == 0
    assert "[1/2] second.example" in stdout
    assert "[2/2] first.example" in stdout
    assert (stdout.index("[1/2] second.example")
            < stdout.index("[2/2] first.example"))
    assert (stdout.index("WHOIS Lookup: second.example")
            < stdout.index("WHOIS Lookup: first.example"))
    assert "2/2 domain(s) ok" in stdout


def test_main_multi_json_results_in_arrival_order(monkeypatch, capsys):
    """--json emits one document whose results[] follows arrival order."""
    gates = {"a.example": threading.Event(), "b.example": threading.Event()}
    released = threading.Event()

    def fake_run(domain, **kw):
        gates[domain].wait(timeout=5)
        if domain == "b.example":
            released.set()
        else:
            time.sleep(0.05)  # preemption guard: b was released first, b wins
        return {"status": "ok", "domain": domain, "summary": "ok."}

    monkeypatch.setattr(wl, "run", fake_run)

    outcome = {}
    thread = threading.Thread(
        target=lambda: outcome.update(
            rc=wl.main(["--json", "--multi", "a.example", "b.example"])))
    thread.start()
    gates["b.example"].set()
    assert released.wait(timeout=5)
    gates["a.example"].set()
    thread.join(timeout=10)

    doc = json.loads(capsys.readouterr().out)
    assert outcome["rc"] == 0
    assert doc["status"] == "ok"
    assert doc["domains"] == 2
    assert doc["workers"] == wl.DEFAULT_WORKERS
    assert "elapsed_ms" in doc
    assert [r["domain"] for r in doc["results"]] == ["b.example", "a.example"]
    assert [r["order"] for r in doc["results"]] == [1, 2]
    # input_index keeps the typed position, so a consumer can restore it
    assert [r["input_index"] for r in doc["results"]] == [1, 0]
    assert all("elapsed_ms" in r for r in doc["results"])


def test_main_multi_contains_unexpected_exception(monkeypatch, capsys):
    """A library crash outside run()'s typed excepts fails one domain only."""
    def fake_lookup(domain, *a, **k):
        if domain == "boom.example":
            raise KeyError("Try")  # the whoisdomain global-state failure mode
        return FakeDomain(name=domain)

    monkeypatch.setattr(wl, "_lookup", fake_lookup)
    rc = wl.main(["--multi", "boom.example", "fine.example"])
    stdout = capsys.readouterr().out
    assert rc == 0                                   # one domain succeeded
    assert "WHOIS Lookup: boom.example failed" in stdout
    assert "KeyError" in stdout
    assert "WHOIS Lookup: fine.example" in stdout


def test_main_multi_all_fail_exit_code_and_status(monkeypatch, capsys):
    monkeypatch.setattr(wl, "run",
                        lambda d, **kw: {"status": "error", "domain": d,
                                         "error": "nope"})
    rc = wl.main(["--json", "--multi", "a.example", "b.example"])
    doc = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert doc["status"] == "error"


def test_main_multi_partial_status(monkeypatch, capsys):
    def fake_run(domain, **kw):
        if domain == "bad.example":
            return {"status": "error", "domain": domain, "error": "nope"}
        return {"status": "ok", "domain": domain, "summary": "ok."}

    monkeypatch.setattr(wl, "run", fake_run)
    rc = wl.main(["--json", "--multi", "bad.example", "good.example"])
    doc = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert doc["status"] == "partial"


def test_main_multi_dedupes_domains(monkeypatch, capsys):
    seen = []

    def fake_run(domain, **kw):
        seen.append(domain)
        return {"status": "ok", "domain": domain, "summary": "ok."}

    monkeypatch.setattr(wl, "run", fake_run)
    rc = wl.main(["--json", "--multi", "a.example", "a.example", "b.example"])
    doc = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert doc["domains"] == 2
    assert seen.count("a.example") == 1


def test_main_multi_respects_worker_cap(monkeypatch, capsys):
    lock = threading.Lock()
    release = threading.Event()
    live, peak = 0, 0

    def fake_run(domain, **kw):
        nonlocal live, peak
        with lock:
            live += 1
            peak = max(peak, live)
        release.wait(timeout=5)
        with lock:
            live -= 1
        return {"status": "ok", "domain": domain, "summary": "ok."}

    monkeypatch.setattr(wl, "run", fake_run)
    domains = [f"d{i}.example" for i in range(8)]
    outcome = {}
    thread = threading.Thread(
        target=lambda: outcome.update(
            rc=wl.main(["--json", "--multi", "--workers", "3", *domains])))
    thread.start()
    deadline = time.monotonic() + 3
    while peak < 3 and time.monotonic() < deadline:
        time.sleep(0.01)
    assert peak == 3                 # the cap is actually used, not ignored
    assert live == 3
    release.set()
    thread.join(timeout=10)
    assert outcome["rc"] == 0
    assert peak == 3                 # ... and never exceeded


def test_main_multi_workers_validation(capsys):
    for bad in (["--workers"], ["--workers", "0"], ["--workers", "abc"]):
        assert wl.main(["--multi", *bad, "a.example"]) == 2
        assert "workers" in capsys.readouterr().err


def test_main_unknown_option_still_rejected(capsys):
    assert wl.main(["--nope", "a.example"]) == 2
    assert "Unknown option: --nope" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# registrant_country + tld mapping
# ---------------------------------------------------------------------------

def test_map_registrant_country():
    mapped = wl.map_registration(FakeDomain())
    assert mapped["contacts"]["registrant_country"] is None
    d = FakeDomain(registrant_country="US")
    assert wl.map_registration(d)["contacts"]["registrant_country"] == "US"


def test_run_includes_tld(monkeypatch):
    monkeypatch.setattr(wl, "_lookup", lambda *a, **k: FakeDomain())
    out = wl.run("example.com")
    assert out["tld"] == "com"


def test_render_tld_and_country_rows(monkeypatch):
    monkeypatch.setattr(wl, "_lookup",
                        lambda *a, **k: FakeDomain(registrant_country="US"))
    text = wl.render(wl.run("example.com"))
    assert "TLD" in text and "com" in text
    assert "Registrant country" in text and "US" in text
