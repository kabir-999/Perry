"""Dedicated tests for the NoSQL injection detector."""
from app.services.phase2_checks import check_nosql_injection
from fixtures import FakeFetcher, ok_result

URL = "https://example.com/api/v1/nosql/login"


def _vulnerable_responder(url, **kwargs):
    """Authenticates whenever the password is a non-string (operator/type
    confusion) — the classic unsanitised NoSQL query bug."""
    body = kwargs.get("json") or {}
    pw = body.get("password")
    if not isinstance(pw, str):  # {"$ne": null}, arrays, objects...
        return ok_result(url, text='{"authenticated": true, "token": "abc"}',
                         content_type="application/json")
    return ok_result(url, status_code=401, text='{"authenticated": false}',
                     content_type="application/json")


def _safe_responder(url, **kwargs):
    """Casts the password to a string; only the correct password authenticates."""
    body = kwargs.get("json") or {}
    pw = body.get("password")
    if isinstance(pw, str) and pw == "correct-horse":
        return ok_result(url, text='{"authenticated": true}', content_type="application/json")
    return ok_result(url, status_code=401, text='{"authenticated": false}',
                     content_type="application/json")


async def test_nosql_operator_injection():
    findings = await check_nosql_injection(FakeFetcher(_vulnerable_responder), URL)
    assert len(findings) == 1
    assert findings[0].dedup_key.startswith("nosqli")
    assert findings[0].confidence == "confirmed"


async def test_nosql_type_confusion():
    findings = await check_nosql_injection(FakeFetcher(_vulnerable_responder), URL)
    assert len(findings) == 1


async def test_nosql_normal_login():
    """A properly-typed backend rejects the operator payload -> no finding."""
    findings = await check_nosql_injection(FakeFetcher(_safe_responder), URL)
    assert findings == []


async def test_nosql_negative_case():
    findings = await check_nosql_injection(
        FakeFetcher(lambda url, **k: ok_result(url, status_code=401,
                                               text='{"authenticated": false}',
                                               content_type="application/json")),
        URL,
    )
    assert findings == []
