"""Regression tests: discovering a sensitive-looking path must never, by
itself, produce a vulnerability finding — only a response that survives
baseline (not-found/SPA-fallback/blanket-auth-gate) comparison can.
"""
from app.services.response_analyzer import NotFoundProfile, analyze
from app.services.security_checks import check_api_security
from fixtures import FakeFetcher, ok_result

_PERMISSIVE = NotFoundProfile()


async def test_sensitive_json_surviving_baseline_is_flagged():
    """The healthy positive case: a real, distinct 200 JSON response with no
    baseline match is still reported — the fix must not make this check mute."""
    def responder(url, **kwargs):
        return ok_result(url, text='{"id": 1, "email": "a@b.com"}', content_type="application/json")

    fetcher = FakeFetcher(responder)
    findings = await check_api_security(fetcher, ["https://example.com/api/users/1"], _PERMISSIVE)
    assert any(f.dedup_key.startswith("api_unauthenticated") for f in findings)


async def test_identical_json_error_shell_for_sensitive_paths_is_not_flagged():
    """/admin, /dashboard, /account, /tokens etc. on a backend that answers
    every unknown API path with the exact same generic JSON body must never
    be flagged from the path alone — this is the JSON-API analogue of an SPA
    HTML fallback (that case can't reach this check at all: it requires
    is_json, and an HTML shell never is)."""
    shell = '{"__catch_all__": true}'
    probe_result = ok_result("https://example.com/some-random-probe-path", text=shell,
                             content_type="application/json")
    not_found = NotFoundProfile(fingerprints={analyze(probe_result).fingerprint})

    def responder(url, **kwargs):
        return ok_result(url, text=shell, content_type="application/json")

    fetcher = FakeFetcher(responder)
    for path in ("/admin", "/dashboard", "/account", "/tokens", "/settings"):
        findings = await check_api_security(fetcher, [f"https://example.com{path}"], not_found)
        assert findings == [], f"{path} should not be flagged from path alone"


async def test_soft_404_json_error_page_is_not_flagged():
    """A backend that answers every unknown API path with 200 + a generic
    JSON error body must not have that misread as 'sensitive data exposed'."""
    error_body = '{"error": "not found"}'
    probe_result = ok_result("https://example.com/some-random-probe-path", text=error_body,
                             content_type="application/json")
    not_found = NotFoundProfile(fingerprints={analyze(probe_result).fingerprint})

    def responder(url, **kwargs):
        return ok_result(url, text=error_body, content_type="application/json")

    fetcher = FakeFetcher(responder)
    findings = await check_api_security(fetcher, ["https://example.com/api/admin/config"], not_found)
    assert findings == []


async def test_401_challenge_is_not_flagged():
    def responder(url, **kwargs):
        return ok_result(url, status_code=401, text="", content_type="application/json")

    fetcher = FakeFetcher(responder)
    findings = await check_api_security(fetcher, ["https://example.com/api/admin"], _PERMISSIVE)
    assert findings == []


async def test_non_sensitive_path_is_not_flagged():
    def responder(url, **kwargs):
        return ok_result(url, text='{"greeting": "hello"}', content_type="application/json")

    fetcher = FakeFetcher(responder)
    findings = await check_api_security(fetcher, ["https://example.com/api/status"], _PERMISSIVE)
    assert findings == []


async def test_login_redirect_is_not_flagged():
    """A protected endpoint that redirects to a login page (never followed
    here) must not have the login page's status/body misattributed."""
    def responder(url, **kwargs):
        return ok_result(url, status_code=302, text="", headers={"location": "/login"})

    fetcher = FakeFetcher(responder)
    findings = await check_api_security(fetcher, ["https://example.com/api/account"], _PERMISSIVE)
    assert findings == []
