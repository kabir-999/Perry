"""Dedicated tests for the CSRF detector."""
from app.services.phase2_checks import check_csrf
from fixtures import FakeFetcher, ok_result

URL = "https://example.com/profile/change-email"


async def test_csrf_missing_token():
    """State-changing POST accepted cross-site, session cookie has no SameSite.

    The GET baseline returns the (much longer) profile page, distinct from
    the POST's short confirmation body — real evidence the POST was
    actually processed, not just a page re-serve regardless of method."""
    def responder(url, **kwargs):
        if kwargs.get("method") == "GET":
            return ok_result(url, status_code=200,
                             text="<html>" + "change email form " * 50 + "</html>")
        return ok_result(url, status_code=200, text="email updated",
                         headers={"set-cookie": "sid=abc; Path=/"})
    findings = await check_csrf(FakeFetcher(responder), URL, method="POST")
    assert len(findings) == 1
    assert findings[0].dedup_key.startswith("csrf")


async def test_csrf_valid_token():
    """Protected endpoint requires a token; the token-less request is rejected."""
    def responder(url, **kwargs):
        return ok_result(url, status_code=403, text="missing csrf token")
    findings = await check_csrf(FakeFetcher(responder), URL, method="POST")
    assert findings == []


async def test_csrf_invalid_token():
    def responder(url, **kwargs):
        return ok_result(url, status_code=403, text="invalid csrf token")
    findings = await check_csrf(FakeFetcher(responder), URL, method="POST")
    assert findings == []


async def test_csrf_same_site_protection():
    """Accepted, but the session cookie is SameSite=Strict -> defended."""
    def responder(url, **kwargs):
        return ok_result(url, status_code=200, text="ok",
                         headers={"set-cookie": "sid=abc; Path=/; SameSite=Strict"})
    findings = await check_csrf(FakeFetcher(responder), URL, method="POST")
    assert findings == []


async def test_csrf_origin_validation():
    """Server validates Origin and rejects the forged one -> no finding."""
    def responder(url, **kwargs):
        origin = (kwargs.get("headers") or {}).get("Origin", "")
        if "evil.example" in origin:
            return ok_result(url, status_code=403, text="bad origin")
        return ok_result(url, status_code=200, text="ok")
    findings = await check_csrf(FakeFetcher(responder), URL, method="POST")
    assert findings == []


async def test_csrf_safe_get():
    """GET is not state-changing; the detector must not run it."""
    fetcher = FakeFetcher(lambda url, **k: ok_result(url, text="ok"))
    findings = await check_csrf(fetcher, URL, method="GET")
    assert findings == []
    assert fetcher.calls == []
