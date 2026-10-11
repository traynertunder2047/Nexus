from modules.identity.strong_password import run


def test_long_complex_password_is_very_strong():
    res = run("Bunny-h0p3s-0ver-73-Walls!")
    assert "error" not in res
    assert res["score"] >= 80
    assert res["label"] == "Very Strong"


def test_weak_short_password_is_weak():
    res = run("abc12")
    assert res["score"] < 60
    assert res["label"] in ("Weak", "Very Weak")


def test_common_password_scores_below_threshold():
    res = run("Password123!")
    assert res["score"] <= 15
    assert res["label"] == "Very Weak"
    issue = "This is one of the most common passwords."
    assert issue in res["issues"]
    assert any("common" in s for s in res["suggestions"])


def test_sequential_run_is_penalized():
    res = run("abcdefgXYZ12345")
    assert res["score"] < 80
    assert any("sequential" in i for i in res["issues"])


def test_single_class_penalty_on_short_passwords():
    res = run("llamas")  # lowercase-only, short
    assert "Uses only one character type." in res["issues"]


def test_password_never_leaks_into_result():
    res = run("SuperSecret99!")
    dumped = str(res)
    assert "SuperSecret99!" not in dumped
