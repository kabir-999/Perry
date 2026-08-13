from app.services.custom_tests import resolve_attack_preset, run_attack_preset_tests, run_custom_tests
from app.services.scope import build_scope
from fixtures import FakeFetcher, ok_result


def _scope():
    return build_scope("https://example.com")


def _case(**overrides) -> dict:
    base = {
        "name": "Custom Authorization Test",
        "description": "",
        "path": "/api/resource/1",
        "method": "GET",
        "input": "id",
        "location": "query",
        "test": "2",
        "expected": "differs",
        "severity": "high",
    }
    base.update(overrides)
    return base


async def test_out_of_scope_path_is_never_requested():
    fetcher = FakeFetcher(lambda url, **kwargs: ok_result(url))
    case = _case(path="https://not-example.com/api/resource/1")
    findings = await run_custom_tests(fetcher, _scope(), [case])
    assert findings == []
    assert fetcher.calls == []


async def test_contains_validation_matches_produces_a_finding():
    def responder(url, **kwargs):
        return ok_result(url, status_code=200, text="internal-debug-marker-present")

    fetcher = FakeFetcher(responder)
    case = _case(expected="contains:internal-debug-marker-present")
    findings = await run_custom_tests(fetcher, _scope(), [case])
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].category == "custom_test"


async def test_contains_validation_not_met_produces_no_finding():
    fetcher = FakeFetcher(lambda url, **kwargs: ok_result(url, status_code=200, text="nothing interesting"))
    case = _case(expected="contains:internal-debug-marker-present")
    findings = await run_custom_tests(fetcher, _scope(), [case])
    assert findings == []


async def test_differs_validation_uses_baseline_comparison():
    calls = {"n": 0}

    def responder(url, **kwargs):
        calls["n"] += 1
        # First call is the baseline, second is the probe with test value.
        if calls["n"] == 1:
            return ok_result(url, status_code=200, text="baseline response")
        return ok_result(url, status_code=500, text="error: something broke")

    fetcher = FakeFetcher(responder)
    findings = await run_custom_tests(fetcher, _scope(), [_case(expected="differs")])
    assert len(findings) == 1


async def test_differs_validation_identical_response_produces_no_finding():
    fetcher = FakeFetcher(lambda url, **kwargs: ok_result(url, status_code=200, text="same every time"))
    findings = await run_custom_tests(fetcher, _scope(), [_case(expected="differs")])
    assert findings == []


# --------------------------------------------------------------------------
# Attack presets (the "attack=sql injection" shorthand path)
# --------------------------------------------------------------------------

def _preset_spec(**overrides) -> dict:
    base = {"attack": "sql injection", "path": "/products", "name": "sqli on /products",
            "fields": {"id": "1"}}
    base.update(overrides)
    return base


def test_resolve_attack_preset_accepts_known_aliases():
    assert resolve_attack_preset("sql injection").dedup_prefix == "sqli"
    assert resolve_attack_preset("SQLi").dedup_prefix == "sqli"
    assert resolve_attack_preset("xss").dedup_prefix == "reflected_xss"
    assert resolve_attack_preset("directory traversal").dedup_prefix == "path_traversal"
    assert resolve_attack_preset("not-a-real-attack") is None


async def test_out_of_scope_preset_path_is_never_requested():
    fetcher = FakeFetcher(lambda url, **kwargs: ok_result(url))
    spec = _preset_spec(path="https://not-example.com/products")
    findings = await run_attack_preset_tests(fetcher, _scope(), [spec])
    assert findings == []
    assert fetcher.calls == []


async def test_preset_fires_using_active_engines_own_detector():
    """The SQL-error text active_engine._sqli_detect looks for must be
    enough to fire here too — same detector, not a re-implementation."""
    def responder(url, **kwargs):
        if "id=1" in url and "'" not in url:
            return ok_result(url, status_code=200, text="Product #1")
        return ok_result(url, status_code=500, text="SQLSTATE[42000]: syntax error")

    fetcher = FakeFetcher(responder)
    findings = await run_attack_preset_tests(fetcher, _scope(), [_preset_spec()])
    assert len(findings) == 1
    assert findings[0].category == "input_validation"


async def test_preset_finding_dedup_key_preserves_display_name():
    """Regression: severity_policy.apply_policy rewrites titles that make
    an unconfirmed attack claim (e.g. "SQL injection" -> "possible SQL
    injection pattern"). Callers that need to know which spec fired must
    match on dedup_key, not .title — so the original display name has to
    survive in dedup_key even though the title gets rewritten."""
    def responder(url, **kwargs):
        if "id=1" in url and "'" not in url:
            return ok_result(url, status_code=200, text="Product #1")
        return ok_result(url, status_code=500, text="SQLSTATE[42000]: syntax error")

    fetcher = FakeFetcher(responder)
    spec = _preset_spec(name="my very specific test name")
    findings = await run_attack_preset_tests(fetcher, _scope(), [spec])
    assert len(findings) == 1
    assert findings[0].dedup_key.split("|")[1] == "my very specific test name"


async def test_unrecognized_attack_name_produces_no_finding_not_an_error():
    fetcher = FakeFetcher(lambda url, **kwargs: ok_result(url, status_code=500, text="error"))
    findings = await run_attack_preset_tests(
        fetcher, _scope(), [_preset_spec(attack="not_a_real_attack")]
    )
    assert findings == []


async def test_target_field_narrows_which_field_gets_the_payload():
    seen_urls = []

    def responder(url, **kwargs):
        seen_urls.append(url)
        return ok_result(url, status_code=200, text="ok")

    fetcher = FakeFetcher(responder)
    spec = _preset_spec(fields={"id": "1", "extra": "2"}, target="id")
    await run_attack_preset_tests(fetcher, _scope(), [spec])
    # Every probe after the baseline must vary "id" only — "extra" stays at
    # its baseline value in every request.
    assert all("extra=2" in u for u in seen_urls[1:])
