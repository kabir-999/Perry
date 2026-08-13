from app.services.custom_tests import run_custom_tests
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
