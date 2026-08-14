"""Dedicated tests for the HTTP Parameter Pollution (HPP) detector.

HPP lives in the active engine (``_hpp_test``): it compares a single-value
request against a duplicated-parameter request and flags the target only when
the duplicate meaningfully changes the response *and* the second injected
value is reflected. These tests exercise that real detector via FakeFetcher.
"""
from urllib.parse import parse_qs, urlsplit

from app.services.active_engine import ParamTarget, _hpp_test
from fixtures import FakeFetcher, ok_result

URL = "https://example.com/hpp"


def _values(url: str, name: str) -> list[str]:
    return parse_qs(urlsplit(url).query).get(name, [])


def _ambiguous_responder(name: str):
    """Simulate ambiguous duplicate handling: with two values the server
    selects the last, reflects it, and renders extra (elevated) content — so
    the duplicated request differs meaningfully from the single request."""
    def responder(url, **kwargs):
        vals = _values(url, name)
        if len(vals) > 1:
            return ok_result(
                url,
                text=(
                    f"Effective {name}: {vals[-1]}. "
                    "Duplicate parameters detected; the final value overrode the "
                    "earlier one and elevated content was rendered for it."
                ),
            )
        sel = vals[0] if vals else ""
        return ok_result(url, text=f"Effective {name}: {sel}.")

    return responder


async def test_hpp_duplicate_different_values():
    fetcher = FakeFetcher(_ambiguous_responder("id"))
    findings = await _hpp_test(fetcher, ParamTarget(url=URL, name="id", location="query"))
    assert len(findings) == 1
    assert findings[0].dedup_key.startswith("hpp")
    assert findings[0].parameter == "id"


async def test_hpp_duplicate_identical_handling_not_flagged():
    """A host that ignores the duplicate (identical response, second value not
    reflected) is not ambiguous and must not be flagged."""
    fetcher = FakeFetcher(lambda url, **k: ok_result(url, text="Effective id: 1."))
    findings = await _hpp_test(fetcher, ParamTarget(url=URL, name="id", location="query"))
    assert findings == []


async def test_hpp_single_parameter_non_query_location_is_skipped():
    """HPP only applies to query parameters; a body parameter is skipped
    without any request being sent."""
    fetcher = FakeFetcher(lambda url, **k: ok_result(url, text="x"))
    findings = await _hpp_test(fetcher, ParamTarget(url=URL, name="id", location="json"))
    assert findings == []
    assert fetcher.calls == []


async def test_hpp_alternate_parameter_name_not_hardcoded():
    """The detector must work for any parameter name, not a hardcoded one."""
    fetcher = FakeFetcher(_ambiguous_responder("role"))
    findings = await _hpp_test(fetcher, ParamTarget(url=URL, name="role", location="query"))
    assert len(findings) == 1
    assert findings[0].parameter == "role"
