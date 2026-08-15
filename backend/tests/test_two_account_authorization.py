"""Regression tests for check_two_account_authorization: two real,
scanner-controlled identities requesting the same URL must show a genuine
content match to be flagged — a shared login/error page or generic 200
shell must never be reported as broken object-level authorization.
"""
from app.services.response_analyzer import NotFoundProfile, analyze
from app.services.security_checks import check_two_account_authorization
from fixtures import FakeFetcher, ok_result

_PERMISSIVE = NotFoundProfile()
URL = "https://example.com/api/orders/42"


async def test_missing_credential_never_fabricates_a_finding():
    fetcher = FakeFetcher(lambda url, **kwargs: ok_result(url, text='{"id":42}', content_type="application/json"))
    findings = await check_two_account_authorization(fetcher, URL, "Authorization: Bearer a", None, _PERMISSIVE)
    assert findings == []


async def test_both_accounts_reading_the_same_real_resource_is_flagged():
    body = '{"id": 42, "owner": "user_a"}'

    def responder(url, **kwargs):
        return ok_result(url, text=body, content_type="application/json")

    fetcher = FakeFetcher(responder)
    findings = await check_two_account_authorization(
        fetcher, URL, "Authorization: Bearer a", "Authorization: Bearer b", _PERMISSIVE
    )
    assert len(findings) == 1
    assert findings[0].category == "authorization"


async def test_both_accounts_bounced_to_login_is_not_flagged():
    """Both accounts getting redirected to the same login page (a 3xx,
    never followed here) is a sign auth IS enforced, not IDOR."""
    def responder(url, **kwargs):
        return ok_result(url, status_code=302, text="", headers={"location": "/login"})

    fetcher = FakeFetcher(responder)
    findings = await check_two_account_authorization(
        fetcher, URL, "Authorization: Bearer a", "Authorization: Bearer b", _PERMISSIVE
    )
    assert findings == []


async def test_both_accounts_hitting_generic_catch_all_is_not_flagged():
    """Both accounts landing on the site's own generic not-found/catch-all
    response (learned as a baseline) must not be reported as IDOR."""
    shell = '{"__catch_all__": true}'
    probe_result = ok_result("https://example.com/some-random-probe-path", text=shell,
                             content_type="application/json")
    not_found = NotFoundProfile(fingerprints={analyze(probe_result).fingerprint})

    def responder(url, **kwargs):
        return ok_result(url, text=shell, content_type="application/json")

    fetcher = FakeFetcher(responder)
    findings = await check_two_account_authorization(
        fetcher, URL, "Authorization: Bearer a", "Authorization: Bearer b", not_found
    )
    assert findings == []
