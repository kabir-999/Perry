from app.services.response_analyzer import NotFoundProfile, analyze
from app.services.security_checks import check_authz_boundary
from fixtures import FakeFetcher, ok_result

SENSITIVE_URL = "https://example.com/api/users/42"
# No baseline learned — permissive, matches learn_not_found_profile()'s
# result for a site with no distinctive not-found behavior to learn.
_PERMISSIVE = NotFoundProfile()


async def test_no_credential_never_fabricates_a_finding():
    """Never assume vulnerable without evidence — no credential supplied
    means this check must not run at all, not guess."""
    fetcher = FakeFetcher(lambda url, **kwargs: ok_result(url, status_code=200, text="{}"))
    findings = await check_authz_boundary(fetcher, SENSITIVE_URL, None, _PERMISSIVE)
    assert findings == []
    assert fetcher.calls == []


async def test_identical_response_with_and_without_credential_is_flagged():
    body = '{"id": 42, "email": "user@example.com"}'

    def responder(url, **kwargs):
        return ok_result(url, status_code=200, text=body)

    fetcher = FakeFetcher(responder)
    findings = await check_authz_boundary(fetcher, SENSITIVE_URL, "Authorization: Bearer test-token", _PERMISSIVE)
    assert len(findings) == 1
    assert findings[0].category == "authorization"
    assert findings[0].confidence == "potential"


async def test_different_response_with_credential_is_not_flagged():
    """The expected, healthy case: the credential actually changes the
    response — no finding, since authorization appears to be enforced."""
    calls = {"n": 0}

    def responder(url, **kwargs):
        calls["n"] += 1
        if kwargs.get("headers"):
            return ok_result(url, status_code=200, text='{"id": 42, "private": true}')
        return ok_result(url, status_code=403, text="")

    fetcher = FakeFetcher(responder)
    findings = await check_authz_boundary(fetcher, SENSITIVE_URL, "Authorization: Bearer test-token", _PERMISSIVE)
    assert findings == []


async def test_non_sensitive_path_is_not_flagged_even_if_identical():
    fetcher = FakeFetcher(lambda url, **kwargs: ok_result(url, status_code=200, text="hello world"))
    findings = await check_authz_boundary(
        fetcher, "https://example.com/about", "Authorization: Bearer test-token", _PERMISSIVE
    )
    assert findings == []


async def test_spa_fallback_shell_is_not_flagged_even_if_identical():
    """The reported false-positive class: a protected SPA (e.g. an account
    settings page) serves the identical client-side-routed shell for every
    path, with or without a session — this must never be reported as a
    broken authorization boundary just because the path looks sensitive."""
    shell = "<html><body><div id='root'>App Shell</div></body></html>"

    def responder(url, **kwargs):
        return ok_result(url, status_code=200, text=shell, content_type="text/html")

    fetcher = FakeFetcher(responder)
    not_found = NotFoundProfile(root=analyze(ok_result("https://example.com/", status_code=200, text=shell, content_type="text/html")), is_spa=True)
    findings = await check_authz_boundary(
        fetcher, "https://example.com/account/settings", "Authorization: Bearer test-token", not_found
    )
    assert findings == []


async def test_login_redirect_both_ways_is_not_flagged():
    """Both requests bouncing to a login page (a 3xx, never followed here)
    means auth *is* being enforced — not evidence of a broken boundary."""
    def responder(url, **kwargs):
        return ok_result(url, status_code=302, text="", headers={"location": "/login"})

    fetcher = FakeFetcher(responder)
    findings = await check_authz_boundary(fetcher, SENSITIVE_URL, "Authorization: Bearer test-token", _PERMISSIVE)
    assert findings == []
