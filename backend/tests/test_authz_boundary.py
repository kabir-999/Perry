from app.services.security_checks import check_authz_boundary
from fixtures import FakeFetcher, ok_result

SENSITIVE_URL = "https://example.com/api/users/42"


async def test_no_credential_never_fabricates_a_finding():
    """Never assume vulnerable without evidence — no credential supplied
    means this check must not run at all, not guess."""
    fetcher = FakeFetcher(lambda url, **kwargs: ok_result(url, status_code=200, text="{}"))
    findings = await check_authz_boundary(fetcher, SENSITIVE_URL, None)
    assert findings == []
    assert fetcher.calls == []


async def test_identical_response_with_and_without_credential_is_flagged():
    body = '{"id": 42, "email": "user@example.com"}'

    def responder(url, **kwargs):
        return ok_result(url, status_code=200, text=body)

    fetcher = FakeFetcher(responder)
    findings = await check_authz_boundary(fetcher, SENSITIVE_URL, "Authorization: Bearer test-token")
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
    findings = await check_authz_boundary(fetcher, SENSITIVE_URL, "Authorization: Bearer test-token")
    assert findings == []


async def test_non_sensitive_path_is_not_flagged_even_if_identical():
    fetcher = FakeFetcher(lambda url, **kwargs: ok_result(url, status_code=200, text="hello world"))
    findings = await check_authz_boundary(
        fetcher, "https://example.com/about", "Authorization: Bearer test-token"
    )
    assert findings == []
