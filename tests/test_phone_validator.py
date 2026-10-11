import modules.identity.phone_validator as pv


def test_valid_italian_mobile():
    res = pv.run("+39 345 1234567", default_region="IT")
    assert res["status"] == "ok"
    assert res["valid"] is True
    assert res["search_keys"]["e164"] == "+393451234567"
    assert res["search_keys"]["msisdn"] == "393451234567"
    # Country comes from region_code_for_number, not the geocoder —
    # mobile numbers have no geographic area but always have a region.
    assert res["metadata"]["country"] == "IT"
    assert res["metadata"]["carrier"] == "Vodafone"
    # "possible" was removed from the contract (users only care about valid)
    assert "possible" not in res


def test_mobile_has_no_area():
    res = pv.run("+39 345 1234567", default_region="IT")
    assert res["status"] == "ok"
    # Italian mobile ranges are non-geographic: area falls back to Unknown
    assert res["metadata"]["area"] == "Unknown"


def test_landline_has_geographic_area():
    res = pv.run("+39 06 5550 1234", default_region="IT")
    assert res["status"] == "ok"
    assert res["metadata"]["country"] == "IT"
    assert res["metadata"]["area"] == "Rome"


def test_default_region_used_for_national_format():
    # No + prefix: parser needs the default region to interpret it
    res = pv.run("345 1234567", default_region="IT")
    assert res["status"] == "ok"
    assert res["search_keys"]["e164"] == "+393451234567"
    assert res["metadata"]["country"] == "IT"


def test_invalid_number_is_error():
    res = pv.run("999", default_region="IT")
    assert res["status"] == "error"
    assert "error" in res
    assert res["query"] == {"input": "999", "default_region": "IT"}


def test_empty_input_is_error():
    res = pv.run("   ")
    assert res["status"] == "error"
    assert "No phone number provided" in res["error"]


def test_unparseable_input_is_error():
    res = pv.run("not-a-phone", default_region="IT")
    assert res["status"] == "error"
    assert "Parsing failed" in res["error"]


def test_search_phone_pipeline_legacy_shape():
    res = pv.search_phone_pipeline("+39 345 1234567", "IT")
    assert res["status"] == "success"
    assert res["search_keys"]["e164"] == "+393451234567"
    assert res["metadata"]["country"] == "IT"
    assert res["database_hits"] == []

    err = pv.search_phone_pipeline("999", "IT")
    assert err == {"status": "error", "message": "Invalid phone number structure."}


def test_render_shows_valid_and_country_only():
    res = pv.run("+39 345 1234567", default_region="IT")
    out = pv.render(res)
    assert "Valid     : True" in out
    assert "Country   : IT" in out
    assert "possible" not in out
