from app.services.active_engine import _TESTS, ParamTarget, _test_target, unicode_slash_variants
from fixtures import FakeFetcher, ok_result


def test_encoding_is_only_wired_for_traversal():
    """XSS/SQLi already have a realistic plain-payload set; encoding every
    payload for every test class would multiply requests without adding
    signal there — only path_traversal escalates."""
    by_name = {t.name: t for t in _TESTS}
    assert by_name["Path Traversal"].encoders
    assert by_name["Reflected XSS"].encoders == []
    assert by_name["SQL Injection"].encoders == []


def test_unicode_slash_variants_only_applies_when_slash_present():
    assert unicode_slash_variants("no-slash-here") == []
    variants = unicode_slash_variants("../../etc/passwd")
    assert any("%c0%af" in v for v in variants)


async def test_encoding_escalation_fires_only_after_literal_payloads_fail():
    """If a literal traversal payload already succeeds, no encoded variant
    should ever be requested — escalation is for the negative case only."""
    target = ParamTarget(url="https://example.com/read", name="file", location="query")

    # Every request (including the baseline) returns passwd-shaped content,
    # so the very first literal traversal payload already produces a hit.
    fetcher = FakeFetcher(
        lambda url, **kwargs: ok_result(url, status_code=200, text="root:x:0:0:root:/root:/bin/bash")
    )
    await _test_target(fetcher, target)
    # The literal ".." payload already hit, so no %c0%af/fullwidth encoded
    # variant should ever have been requested.
    assert not any("%c0%af" in url or "／" in url for url, _ in fetcher.calls)


async def test_encoding_escalation_only_applies_to_query_and_form_locations():
    """Byte-level URL encoding doesn't apply meaningfully to header values —
    escalation must not fire there."""
    target = ParamTarget(url="https://example.com/read", name="file", location="header")

    fetcher = FakeFetcher(lambda url, **kwargs: ok_result(url, status_code=200, text="nothing"))
    await _test_target(fetcher, target)
    assert not any("%c0%af" in str(kwargs) for _, kwargs in fetcher.calls)
