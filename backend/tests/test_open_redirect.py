"""Dedicated tests for the open-redirect detector.

Exercises the real ``check_open_redirect`` detector via FakeFetcher. The
detector sends its own external marker and classifies the response by the
``Location`` header, so the responder simulates how the server handles the
redirect destination.
"""
from app.services.security_checks import check_open_redirect
from fixtures import FakeFetcher, ok_result

URL = "https://example.com/redirect"
PARAM = "url"


async def test_open_redirect_https_external():
    """Server honours an attacker-controlled HTTPS destination -> flagged."""
    def responder(url, **kwargs):
        return ok_result(
            url, status_code=302,
            headers={"location": "https://external.invalid/wf-redirect-test"},
        )

    fetcher = FakeFetcher(responder)
    findings = await check_open_redirect(fetcher, URL, PARAM)
    assert len(findings) == 1
    assert findings[0].dedup_key.startswith("open_redirect")
    assert findings[0].confidence == "confirmed"
    assert findings[0].parameter == PARAM


async def test_open_redirect_http_external():
    """A plain-HTTP external destination is also an open redirect."""
    def responder(url, **kwargs):
        return ok_result(
            url, status_code=302,
            headers={"location": "http://external.invalid/phish"},
        )

    fetcher = FakeFetcher(responder)
    findings = await check_open_redirect(fetcher, URL, PARAM)
    assert len(findings) == 1


async def test_open_redirect_internal_is_safe():
    """A same-application relative redirect must not be flagged."""
    def responder(url, **kwargs):
        return ok_result(url, status_code=302, headers={"location": "/dashboard"})

    fetcher = FakeFetcher(responder)
    findings = await check_open_redirect(fetcher, URL, PARAM)
    assert findings == []


async def test_open_redirect_no_location_no_false_positive():
    """A 200 response that merely echoes the URL in the body (no redirect,
    no attacker-controlled Location) must not produce a false positive."""
    def responder(url, **kwargs):
        return ok_result(
            url, status_code=200,
            text="You will be redirected to: https://external.invalid/ shortly.",
        )

    fetcher = FakeFetcher(responder)
    findings = await check_open_redirect(fetcher, URL, PARAM)
    assert findings == []
