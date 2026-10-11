import dns.exception
import requests

import modules.network.dns_enumerator as de
from conftest import FakeResponse


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

def fake_resolver(table):
    """Build a _resolve replacement from {(name, rdtype): [records...]}.

    Missing keys behave like NXDOMAIN (return []).
    """
    def _fake(name, rdtype, timeout=5.0):
        return list(table.get((name.lower(), rdtype.upper()), []))
    return _fake


def fake_http_get(fn):
    """Install fn as requests.get replacement; returns it for reuse."""
    return fn


BASE = "example.com"


# ---------------------------------------------------------------------------
# 1. Core record mapping
# ---------------------------------------------------------------------------

def test_address_records(monkeypatch):
    table = {
        (BASE, "A"): ["93.184.216.34", "93.184.216.35"],
        (BASE, "AAAA"): ["2606:2800:220:1:248:1893:25c8:1946"],
    }
    monkeypatch.setattr(de, "_resolve", fake_resolver(table))
    addrs = de.address_records(BASE)
    assert addrs["a"] == ["93.184.216.34", "93.184.216.35"]
    assert addrs["aaaa"] == ["2606:2800:220:1:248:1893:25c8:1946"]


def test_mx_records_parsed_and_sorted(monkeypatch):
    table = {
        (BASE, "MX"): ["20 alt1.aspmx.l.google.com.",
                       "10 aspmx.l.google.com."],
    }
    monkeypatch.setattr(de, "_resolve", fake_resolver(table))
    mx = de.mx_records(BASE)
    assert mx == [
        {"priority": 10, "exchange": "aspmx.l.google.com"},
        {"priority": 20, "exchange": "alt1.aspmx.l.google.com"},
    ]


def test_ns_records_strip_dots(monkeypatch):
    monkeypatch.setattr(de, "_resolve",
                        fake_resolver({(BASE, "NS"): ["a.iana-servers.net."]}))
    assert de.ns_records(BASE) == ["a.iana-servers.net"]


def test_mx_null_mx_preserved(monkeypatch):
    # RFC 7505 null MX: exchange "." means "no mail", must not become ""
    monkeypatch.setattr(de, "_resolve",
                        fake_resolver({(BASE, "MX"): ["0 ."]}))
    assert de.mx_records(BASE) == [{"priority": 0, "exchange": "."}]


def test_txt_spf_dmarc_and_tokens(monkeypatch):
    table = {
        (BASE, "TXT"): [
            '"v=spf1 include:_spf.google.com ~all"',
            '"google-site-verification=abc123XYZ"',
            '"some-other-token=1"',
        ],
        ("_dmarc." + BASE, "TXT"): ['"v=DMARC1; p=none; rua=mailto:dmarc@example.com"'],
    }
    monkeypatch.setattr(de, "_resolve", fake_resolver(table))
    txt = de.txt_analysis(BASE)
    assert txt["spf"] == "v=spf1 include:_spf.google.com ~all"
    assert txt["dmarc"].startswith("v=DMARC1")
    assert {"type": "google-site-verification",
            "value": "abc123XYZ"} in txt["verification_tokens"]
    assert len(txt["verification_tokens"]) == 1


def test_cname_target(monkeypatch):
    monkeypatch.setattr(de, "_resolve",
                        fake_resolver({("www." + BASE, "CNAME"): ["example.com."]}))
    assert de.cname_target("www." + BASE) == "example.com"
    # no CNAME -> None
    monkeypatch.setattr(de, "_resolve", fake_resolver({}))
    assert de.cname_target("www." + BASE) is None


def test_ptr_records(monkeypatch):
    def fake(name, rdtype, timeout=5.0):
        if rdtype == "PTR" and name.startswith("34.216.184.93"):
            return ["host1.example.net."]
        return []
    monkeypatch.setattr(de, "_resolve", fake)
    out = de.ptr_records(["93.184.216.34", "not-an-ip"])
    assert out["93.184.216.34"] == ["host1.example.net"]
    assert "not-an-ip" not in out


def test_core_record_mapping_shape(monkeypatch):
    table = {
        (BASE, "A"): ["93.184.216.34"],
        (BASE, "MX"): ["10 aspmx.l.google.com."],
        (BASE, "NS"): ["a.iana-servers.net."],
        (BASE, "TXT"): ['"v=spf1 ~all"'],
    }
    monkeypatch.setattr(de, "_resolve", fake_resolver(table))
    mapping = de.core_record_mapping(BASE)
    assert mapping["a"] == ["93.184.216.34"]
    assert mapping["ns"] == ["a.iana-servers.net"]
    assert mapping["txt"]["spf"] == "v=spf1 ~all"
    assert "ptr" in mapping and "resolved_ips" in mapping


# ---------------------------------------------------------------------------
# 2. Subdomain discovery
# ---------------------------------------------------------------------------

def test_ct_log_scan_parses_and_dedupes(monkeypatch):
    data = [
        {"name_value": "www.example.com\n*.example.com\nmail.example.com",
         "common_name": "example.com"},
        {"name_value": "WWW.EXAMPLE.COM", "common_name": "other.test"},
    ]
    monkeypatch.setattr(requests, "get",
                        lambda *a, **k: FakeResponse(200, data))
    out = de.ct_log_scan(BASE)
    assert out["status"] == "ok"
    assert out["subdomains"] == ["mail.example.com", "www.example.com"]
    # wildcard-only + unrelated certs are excluded
    assert "example.com" not in out["subdomains"]
    assert "other.test" not in out["subdomains"]


def test_ct_log_scan_http_error(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse(500))
    out = de.ct_log_scan(BASE)
    assert out["status"] == "error"
    assert "HTTP 500" in out["note"]


def test_ct_log_scan_connection_error(monkeypatch):
    def boom(*a, **k):
        raise requests.RequestException("down")
    monkeypatch.setattr(requests, "get", boom)
    out = de.ct_log_scan(BASE)
    assert out["status"] == "error"
    assert "request failed" in out["note"]


def test_passive_dns_skipped_without_keys(monkeypatch):
    monkeypatch.delenv("SECURITYTRAILS_API_KEY", raising=False)
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    out = de.passive_dns_lookup(BASE)
    assert out["status"] == "skipped"
    assert out["subdomains"] == []


def test_passive_dns_securitytrails(monkeypatch):
    monkeypatch.setenv("SECURITYTRAILS_API_KEY", "st-key")
    data = {"subdomains": ["api", "WWW", "mail"]}
    monkeypatch.setattr(requests, "get",
                        lambda *a, **k: FakeResponse(200, data))
    out = de.passive_dns_lookup(BASE)
    assert out["status"] == "ok"
    assert "api.example.com" in out["subdomains"]
    assert "www.example.com" in out["subdomains"]


def test_passive_dns_bad_key_noted(monkeypatch):
    monkeypatch.setenv("SECURITYTRAILS_API_KEY", "bad")
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse(401))
    out = de.passive_dns_lookup(BASE)
    assert out["status"] == "error"
    assert "invalid API key" in out["note"]


def test_wildcard_detection_enabled_and_disabled(monkeypatch):
    # enabled: random label resolves
    monkeypatch.setattr(de, "_resolve", fake_resolver(
        {(de._RANDOM_LABEL + "." + BASE, "A"): ["1.2.3.4"]}))
    wc = de.wildcard_detection(BASE)
    assert wc["enabled"] is True
    assert wc["ips"] == ["1.2.3.4"]

    # disabled: no answer
    monkeypatch.setattr(de, "_resolve", fake_resolver({}))
    assert de.wildcard_detection(BASE)["enabled"] is False


def test_dictionary_bruteforce(monkeypatch):
    resolved = {}
    hits = ["www", "api", "dev"]
    for word in de.DEFAULT_WORDLIST:
        if word in hits:
            resolved[(f"{word}.{BASE}", "A")] = ["10.0.0.1"]
    resolved[("www." + BASE, "CNAME")] = ["example.com."]
    monkeypatch.setattr(de, "_resolve", fake_resolver(resolved))
    out = de.dictionary_bruteforce(BASE, wordlist=["www", "api", "dev", "nope"])
    assert out["status"] == "ok"
    found = {h["hostname"] for h in out["found"]}
    assert found == {"www.example.com", "api.example.com", "dev.example.com"}
    www = next(h for h in out["found"] if h["hostname"] == "www.example.com")
    assert www["cname"] == "example.com"


def test_generate_permutations_pure(monkeypatch):
    known = ["app-dev.example.com", "www.example.com"]
    out = de.generate_permutations("example.com", known, cap=500)
    # env-word swaps produce the obvious sibling
    assert "app-prod.example.com" in out
    assert "app-staging.example.com" in out
    # known names are never re-emitted
    assert "app-dev.example.com" not in out
    assert "www.example.com" not in out
    assert len(out) <= 500


def test_permutation_scan(monkeypatch):
    known = ["app-dev.example.com"]
    generated = de.generate_permutations("example.com", known, cap=50)
    table = {(c, "A"): ["10.1.1.1"] for c in generated}
    monkeypatch.setattr(de, "_resolve", fake_resolver(table))
    out = de.permutation_scan("example.com", known, max_queries=50)
    assert out["generated"] == len(generated)
    assert len(out["found"]) == len(generated), "every permutation resolves"


# ---------------------------------------------------------------------------
# 3. Asset intelligence & vulnerability indicators
# ---------------------------------------------------------------------------

def _ns_resolve(table):
    """Combine nameserver A records with a base fake-resolver table."""
    table = dict(table)
    table[("ns1.example.net", "A")] = ["192.0.2.1"]
    return table


def test_zone_transfer_vulnerable(monkeypatch):
    class FakeMsg:
        def __init__(self, n):
            self.answer = ["rr"] * n

    monkeypatch.setattr(de, "_resolve",
                        fake_resolver(_ns_resolve({})))
    monkeypatch.setattr(de.dns.query, "xfr",
                        lambda *a, **k: iter([FakeMsg(2), FakeMsg(3)]))
    out = de.zone_transfer_check(BASE, ["ns1.example.net"])
    assert out["vulnerable"] is True
    assert out["servers"][0]["vulnerable"] is True
    assert "ALLOWED" in out["servers"][0]["note"]


def test_zone_transfer_refused(monkeypatch):
    monkeypatch.setattr(de, "_resolve",
                        fake_resolver(_ns_resolve({})))
    monkeypatch.setattr(de.dns.query, "xfr",
                        lambda *a, **k: iter([type("M", (), {"answer": []})()]))
    out = de.zone_transfer_check(BASE, ["ns1.example.net"])
    assert out["vulnerable"] is False
    assert "refused" in out["servers"][0]["note"].lower()


def test_zone_transfer_error_paths(monkeypatch):
    monkeypatch.setattr(de, "_resolve",
                        fake_resolver(_ns_resolve({})))

    def refused(*a, **k):
        raise de.dns.query.TransferError(de.dns.rcode.REFUSED)
    monkeypatch.setattr(de.dns.query, "xfr", refused)
    out = de.zone_transfer_check(BASE, ["ns1.example.net"])
    assert out["vulnerable"] is False
    assert "refused" in out["servers"][0]["note"].lower()

    def timeout(*a, **k):
        raise de.dns.exception.Timeout("t")
    monkeypatch.setattr(de.dns.query, "xfr", timeout)
    out = de.zone_transfer_check(BASE, ["ns1.example.net"])
    assert "timed out" in out["servers"][0]["note"]


def test_zone_transfer_unresolvable_ns(monkeypatch):
    # nameserver hostname with no A record -> per-server note, no crash
    monkeypatch.setattr(de, "_resolve", fake_resolver({}))
    out = de.zone_transfer_check(BASE, ["ns1.example.net"])
    assert out["vulnerable"] is False
    assert "could not be resolved" in out["servers"][0]["note"]


def test_provider_for_cname():
    assert de._provider_for_cname("sub.s3.amazonaws.com") == "aws-s3"
    assert de._provider_for_cname("user.github.io") == "github-pages"
    assert de._provider_for_cname("something.example.org") is None


def test_takeover_dangling_cname_dns(monkeypatch):
    # host CNAME -> herokuapp but the canonical target no longer resolves
    monkeypatch.setattr(de, "_resolve", fake_resolver({}))
    monkeypatch.setattr(requests, "get",
                        lambda *a, **k: FakeResponse(200, text="<html>No such app</html>"))
    hosts = [{"hostname": "app.example.com", "cname": "ghost.herokuapp.com"}]
    out = de.subdomain_takeover_check(hosts)
    check = out["checks"][0]
    assert check["status"] == "vulnerable"
    assert check["dns_dangling"] is True


def test_takeover_live_resource_ok(monkeypatch):
    monkeypatch.setattr(de, "_resolve", fake_resolver(
        {("ghost.herokuapp.com", "A"): ["50.1.2.3"]}))
    monkeypatch.setattr(requests, "get",
                        lambda *a, **k: FakeResponse(200, text="Welcome aboard"))
    hosts = [{"hostname": "app.example.com", "cname": "ghost.herokuapp.com"}]
    check = de.subdomain_takeover_check(hosts)["checks"][0]
    assert check["status"] == "ok"
    assert check["dns_dangling"] is False


# ---------------------------------------------------------------------------
# Orchestration: run()
# ---------------------------------------------------------------------------

def test_run_full_pipeline_shape(monkeypatch):
    table = {
        (BASE, "A"): ["93.184.216.34"],
        (BASE, "NS"): ["a.iana-servers.net."],
        (BASE, "TXT"): ['"v=spf1 ~all"'],
        ("www." + BASE, "A"): ["93.184.216.34"],
        ("www." + BASE, "CNAME"): ["example.com."],
        ("_dmarc." + BASE, "TXT"): [],
    }
    monkeypatch.setattr(de, "_resolve", fake_resolver(table))

    ct_data = [{"name_value": "www.example.com\napi.example.com",
                "common_name": "example.com"}]
    def http_get(url, **kw):
        if "crt.sh" in url:
            return FakeResponse(200, ct_data)
        return FakeResponse(200, text="<html>ok</html>")
    monkeypatch.setattr(requests, "get", http_get)
    monkeypatch.delenv("SECURITYTRAILS_API_KEY", raising=False)
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)

    out = de.run(BASE, do_passive=True, do_bruteforce=False,
                 do_permutations=False, do_axfr=False, do_takeover=False)
    assert out["status"] == "ok"
    assert "error" not in out
    assert out["domain"] == BASE
    assert isinstance(out["elapsed_ms"], int)
    assert out["record_mapping"]["a"] == ["93.184.216.34"]
    assert out["subdomain_discovery"]["certificate_transparency"]["count"] == 2
    assert out["known_subdomains"] == ["api.example.com", "www.example.com"]
    assert out["subdomain_discovery"]["passive_dns"]["status"] == "skipped"
    assert out["subdomain_discovery"]["dictionary_bruteforce"]["status"] == "skipped"
    assert out["asset_intelligence"]["wildcard_dns"]["enabled"] is False
    for key in ("domain", "status", "elapsed_ms", "stages",
                "record_mapping", "subdomain_discovery",
                "asset_intelligence", "findings", "summary"):
        assert key in out
    assert "summary" in out and BASE in out["summary"]


def test_run_invalid_domain():
    assert "error" in de.run("")
    assert "error" in de.run("not a domain!")
    assert "error" in de.run("localhost")


def test_run_bruteforce_wildcard_filtering(monkeypatch):
    # wildcard enabled: every unknown name answers with 1.2.3.4
    wc_probe = de._RANDOM_LABEL + "." + BASE
    table = {
        (wc_probe, "A"): ["1.2.3.4"],
        ("www." + BASE, "A"): ["1.2.3.4"],          # wildcard-only -> filtered
        ("real." + BASE, "A"): ["5.6.7.8"],          # distinct -> kept
        ("_dmarc." + BASE, "TXT"): [],
    }
    monkeypatch.setattr(de, "_resolve", fake_resolver(table))
    monkeypatch.setattr(requests, "get",
                        lambda *a, **k: FakeResponse(200, []))
    out = de.run(BASE, do_passive=False, do_bruteforce=True,
                 do_permutations=False, do_axfr=False, do_takeover=False,
                 wordlist=["www", "real"])
    hosts = {h["hostname"] for h in out["asset_intelligence"]["hosts"]}
    assert hosts == {"real.example.com"}
    assert out["asset_intelligence"]["wildcard_dns"]["enabled"] is True


# ---------------------------------------------------------------------------
# New output organization: verdict, findings, renderer, CLI
# ---------------------------------------------------------------------------

def test_run_partial_when_stage_fails(monkeypatch):
    table = {
        (BASE, "A"): ["93.184.216.34"],
        (BASE, "NS"): ["a.iana-servers.net."],
        (BASE, "TXT"): [],
        ("_dmarc." + BASE, "TXT"): [],
    }
    monkeypatch.setattr(de, "_resolve", fake_resolver(table))
    monkeypatch.setattr(requests, "get",
                        lambda *a, **k: FakeResponse(500, []))  # crt.sh down
    monkeypatch.delenv("SECURITYTRAILS_API_KEY", raising=False)
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    out = de.run(BASE, do_passive=False, do_bruteforce=False,
                 do_permutations=False, do_axfr=False, do_takeover=False)
    assert out["status"] == "partial"
    assert any("Certificate Transparency scan failed" in f for f in out["findings"])
    assert "stage(s) with errors" in out["summary"]


def test_run_mail_security_findings(monkeypatch):
    # real mail MX present but no SPF / DMARC published -> findings
    table = {
        (BASE, "A"): ["93.184.216.34"],
        (BASE, "MX"): ["10 aspmx.l.google.com."],
        (BASE, "TXT"): [],
        ("_dmarc." + BASE, "TXT"): [],
    }
    monkeypatch.setattr(de, "_resolve", fake_resolver(table))
    monkeypatch.setattr(requests, "get",
                        lambda *a, **k: FakeResponse(200, []))
    monkeypatch.delenv("SECURITYTRAILS_API_KEY", raising=False)
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    out = de.run(BASE, do_passive=False, do_bruteforce=False,
                 do_permutations=False, do_axfr=False, do_takeover=False)
    assert any("No SPF record published" in f for f in out["findings"])
    assert any("No DMARC policy" in f for f in out["findings"])


def test_render_success(monkeypatch):
    table = {
        (BASE, "A"): ["93.184.216.34"],
        (BASE, "MX"): ["10 aspmx.l.google.com."],
        (BASE, "NS"): ["a.iana-servers.net."],
        (BASE, "TXT"): ['"v=spf1 ~all"'],
        ("_dmarc." + BASE, "TXT"): [],
        ("www." + BASE, "A"): ["93.184.216.34"],
        ("www." + BASE, "CNAME"): ["example.com."],
    }
    monkeypatch.setattr(de, "_resolve", fake_resolver(table))
    ct_data = [{"name_value": "www.example.com", "common_name": "example.com"}]
    monkeypatch.setattr(requests, "get",
                        lambda *a, **k: FakeResponse(200, ct_data))
    out = de.run(BASE, do_passive=False, do_bruteforce=False,
                 do_permutations=False, do_axfr=False, do_takeover=False)
    text = de.render(out)
    assert text.startswith("DNS Enumerator: example.com")
    assert "Status" in text and "ok" in text
    assert "IPv4 (A)" in text and "93.184.216.34" in text
    assert "Discovery" in text
    assert "Asset intelligence" in text
    assert "Findings" in text


def test_render_error():
    text = de.render({"status": "error", "domain": "example.com",
                      "error": "boom"})
    assert "failed" in text
    assert "boom" in text


def test_render_null_mx_label(monkeypatch):
    table = {
        (BASE, "A"): ["93.184.216.34"],
        (BASE, "MX"): ["0 ."],
        (BASE, "NS"): [],
        (BASE, "TXT"): [],
        ("_dmarc." + BASE, "TXT"): [],
    }
    monkeypatch.setattr(de, "_resolve", fake_resolver(table))
    monkeypatch.setattr(requests, "get",
                        lambda *a, **k: FakeResponse(200, []))
    out = de.run(BASE, do_passive=False, do_bruteforce=False,
                 do_permutations=False, do_axfr=False, do_takeover=False)
    text = de.render(out)
    assert "null MX - no mail service" in text


def test_main_json_flag(monkeypatch, capsys):
    import json
    monkeypatch.setattr(de, "_resolve", fake_resolver({}))
    monkeypatch.setattr(requests, "get",
                        lambda *a, **k: FakeResponse(200, []))
    rc = de.main(["--json", "example.com"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["domain"] == "example.com"
    assert payload["status"] in ("ok", "partial")


def test_main_human_flag(monkeypatch, capsys):
    monkeypatch.setattr(de, "_resolve", fake_resolver({}))
    monkeypatch.setattr(requests, "get",
                        lambda *a, **k: FakeResponse(200, []))
    rc = de.main(["example.com"])
    out = capsys.readouterr().out
    assert rc == 0
    assert out.startswith("DNS Enumerator: example.com")


def test_main_usage_no_args(capsys):
    assert de.main([]) == 1
    assert "Usage:" in capsys.readouterr().out


def test_passive_dns_censys(monkeypatch):
    monkeypatch.setenv("CENSYS_API_ID", "id-123")
    monkeypatch.setenv("CENSYS_API_SECRET", "secret-456")
    monkeypatch.delenv("SECURITYTRAILS_API_KEY", raising=False)
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    body = {"result": {"hits": [
        {"names": ["example.com", "www.example.com", "*.api.example.com"]}]}}
    monkeypatch.setattr(requests, "get",
                        lambda *a, **k: FakeResponse(200, body))
    out = de.passive_dns_lookup(BASE)
    assert out["status"] == "ok"
    assert "www.example.com" in out["subdomains"]
    assert "api.example.com" in out["subdomains"]
    assert "example.com" not in out["subdomains"]  # apex excluded


def test_ct_log_scan_retries_then_errors(monkeypatch):
    calls = []
    def flaky(url, **kw):
        calls.append(url)
        return FakeResponse(404, [])
    monkeypatch.setattr(requests, "get", flaky)
    out = de.ct_log_scan(BASE, retries=1, backoff=0)
    assert out["status"] == "error"
    assert "HTTP 404" in out["note"]
    assert len(calls) == 2  # first + one retry


def test_ct_log_scan_recovers_after_retry(monkeypatch):
    calls = []
    ct_data = [{"name_value": "www.example.com", "common_name": "example.com"}]
    def flaky(url, **kw):
        calls.append(url)
        return FakeResponse(500, []) if len(calls) == 1 else FakeResponse(200, ct_data)
    monkeypatch.setattr(requests, "get", flaky)
    out = de.ct_log_scan(BASE, retries=1, backoff=0)
    assert out["status"] == "ok"
    assert out["subdomains"] == ["www.example.com"]


def test_main_wordlist_flag(monkeypatch, tmp_path, capsys):
    wl_file = tmp_path / "words.txt"
    wl_file.write_text("dev\n  STAGE \n\napi\n", encoding="utf-8")
    captured = {}
    def fake_run(domain, **kwargs):
        captured.update(kwargs)
        return {"status": "ok", "domain": domain}
    monkeypatch.setattr(de, "run", fake_run)
    rc = de.main(["--json", "--wordlist", str(wl_file), "example.com"])
    assert rc == 0
    assert captured["wordlist"] == ["dev", "stage", "api"]
    assert de.json.loads(capsys.readouterr().out)["domain"] == "example.com"


def test_main_wordlist_missing_file(capsys):
    rc = de.main(["--wordlist", "no-such-file.txt", "example.com"])
    assert rc == 2
    assert "Cannot read wordlist" in capsys.readouterr().err


def test_verification_tokens_surfaced(monkeypatch):
    table = {
        (BASE, "A"): ["93.184.216.34"],
        (BASE, "NS"): [],
        (BASE, "TXT"): ['"google-site-verification=AbC123xYz456longtokenvalue"',
                        '"v=spf1 -all"'],
        ("_dmarc." + BASE, "TXT"): [],
    }
    monkeypatch.setattr(de, "_resolve", fake_resolver(table))
    monkeypatch.setattr(requests, "get",
                        lambda *a, **k: FakeResponse(200, []))
    monkeypatch.delenv("SECURITYTRAILS_API_KEY", raising=False)
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    monkeypatch.delenv("CENSYS_API_ID", raising=False)
    monkeypatch.delenv("CENSYS_API_SECRET", raising=False)
    out = de.run(BASE, do_passive=False, do_bruteforce=False,
                 do_permutations=False, do_axfr=False, do_takeover=False)
    assert any("google-site-verification" in f for f in out["findings"])
    assert "domain-verification token(s)" in out["findings"][0]
    text = de.render(out)
    assert "Verification tokens" in text
    assert "google-site-verification=AbC123xYz456longtokenvalue" in text


# ---------------------------------------------------------------------------
# Scope model: active stages are opt-in (--bruteforce / --permutations /
# --axfr / --takeover, or the --full preset); passive discovery stays default
# ---------------------------------------------------------------------------

def _passive_table():
    return {
        (BASE, "A"): ["93.184.216.34"],
        (BASE, "NS"): ["a.iana-servers.net."],
        (BASE, "TXT"): ['"v=spf1 ~all"'],
        ("_dmarc." + BASE, "TXT"): [],
    }


def _quiet_env(monkeypatch):
    monkeypatch.setattr(de, "_resolve", fake_resolver(_passive_table()))
    monkeypatch.setattr(requests, "get",
                        lambda *a, **k: FakeResponse(200, []))
    monkeypatch.delenv("SECURITYTRAILS_API_KEY", raising=False)
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    monkeypatch.delenv("CENSYS_API_ID", raising=False)
    monkeypatch.delenv("CENSYS_API_SECRET", raising=False)


def test_run_default_scope_is_passive_only(monkeypatch):
    _quiet_env(monkeypatch)
    out = de.run(BASE)
    assert out["stages"] == {"passive": True, "bruteforce": False,
                             "permutations": False, "axfr": False,
                             "takeover": False}
    assert out["subdomain_discovery"]["dictionary_bruteforce"]["status"] == "skipped"
    assert out["subdomain_discovery"]["permutation_scan"]["status"] == "skipped"
    assert out["asset_intelligence"]["zone_transfer"]["status"] == "skipped"
    assert out["asset_intelligence"]["subdomain_takeover"]["status"] == "skipped"


def test_render_flags_partial_scope(monkeypatch):
    _quiet_env(monkeypatch)
    text = de.render(de.run(BASE))
    assert "Scan scope" in text
    assert "use --full" in text
    full = de.render(de.run(BASE, do_bruteforce=True, do_permutations=True,
                            do_axfr=True, do_takeover=True))
    assert "Scan scope" not in full


def _capture_run(monkeypatch):
    captured = {}

    def fake_run(domain, **kwargs):
        captured.update(kwargs)
        return {"status": "ok", "domain": domain}

    monkeypatch.setattr(de, "run", fake_run)
    return captured


def test_main_full_preset_enables_every_stage(monkeypatch, capsys):
    captured = _capture_run(monkeypatch)
    assert de.main(["--json", "--full", "example.com"]) == 0
    for key in ("do_passive", "do_bruteforce", "do_permutations",
                "do_axfr", "do_takeover"):
        assert captured[key] is True


def test_main_single_active_flag(monkeypatch, capsys):
    captured = _capture_run(monkeypatch)
    assert de.main(["--json", "--permutations", "example.com"]) == 0
    assert captured["do_permutations"] is True
    assert captured["do_bruteforce"] is False
    assert captured["do_axfr"] is False
    assert captured["do_passive"] is True  # passive stays on by default


def test_wordlist_implies_bruteforce(monkeypatch, tmp_path, capsys):
    wl = tmp_path / "words.txt"
    wl.write_text("dev\n", encoding="utf-8")
    captured = _capture_run(monkeypatch)
    assert de.main(["--json", "--wordlist", str(wl), "example.com"]) == 0
    assert captured["do_bruteforce"] is True
    assert captured["wordlist"] == ["dev"]


def test_no_bruteforce_overrides_wordlist(monkeypatch, tmp_path, capsys):
    wl = tmp_path / "words.txt"
    wl.write_text("dev\n", encoding="utf-8")
    captured = _capture_run(monkeypatch)
    assert de.main(["--json", "--no-bruteforce", "--wordlist", str(wl),
                    "example.com"]) == 0
    assert captured["do_bruteforce"] is False


def test_legacy_no_passive_flag_still_accepted(monkeypatch, capsys):
    captured = _capture_run(monkeypatch)
    assert de.main(["--json", "--no-passive", "example.com"]) == 0
    assert captured["do_passive"] is False


# ---------------------------------------------------------------------------
# CLI tunables: --timeout / --workers / --max-queries
# ---------------------------------------------------------------------------

def test_main_tunable_limits_pass_through(monkeypatch, capsys):
    captured = _capture_run(monkeypatch)
    rc = de.main(["--json", "--timeout", "2.5", "--workers", "3",
                  "--max-queries", "50", "example.com"])
    assert rc == 0
    assert captured["timeout"] == 2.5
    assert captured["max_workers"] == 3
    assert captured["max_queries"] == 50


def test_main_tunable_limits_default_to_module_defaults(monkeypatch, capsys):
    captured = _capture_run(monkeypatch)
    assert de.main(["--json", "example.com"]) == 0
    assert captured["timeout"] == 5.0
    assert captured["max_workers"] == 10
    assert captured["max_queries"] == 250


def test_main_tunable_limits_reject_bad_values(capsys):
    for argv in (["--timeout", "abc", "example.com"],
                 ["--timeout", "-1", "example.com"],
                 ["--timeout", "0", "example.com"],
                 ["--workers", "many", "example.com"],
                 ["--workers", "0", "example.com"],
                 ["--max-queries", "0", "example.com"],
                 ["--max-queries"],
                 ["--timeout"]):
        assert de.main(argv) == 2, argv
    assert "must be greater than 0" in capsys.readouterr().err


def test_run_timeout_reaches_the_resolver(monkeypatch):
    seen = []

    def fake(name, rdtype, timeout=5.0):
        seen.append(timeout)
        return []

    monkeypatch.setattr(de, "_resolve", fake)
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse(200, []))
    de.run(BASE, timeout=1.25, do_passive=False, do_bruteforce=False,
           do_permutations=False, do_axfr=False, do_takeover=False)
    assert seen and set(seen) == {1.25}


def test_run_max_queries_caps_dictionary_candidates(monkeypatch):
    table = {
        (BASE, "A"): ["93.184.216.34"],
        (BASE, "NS"): ["a.iana-servers.net."],
        (BASE, "TXT"): ['"v=spf1 ~all"'],
        ("_dmarc." + BASE, "TXT"): [],
        ("one." + BASE, "A"): ["5.6.7.8"],
    }
    monkeypatch.setattr(de, "_resolve", fake_resolver(table))
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse(200, []))
    out = de.run(BASE, do_passive=False, do_bruteforce=True,
                 do_permutations=False, do_axfr=False, do_takeover=False,
                 wordlist=["one", "two", "three"], max_queries=1)
    bf = out["subdomain_discovery"]["dictionary_bruteforce"]
    assert bf["queried"] == 1
    assert [h["hostname"] for h in bf["found"]] == ["one.example.com"]
