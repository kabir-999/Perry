"""Dedicated tests for the IDOR / BOLA detector."""
from urllib.parse import parse_qs, urlsplit

from app.services.phase2_checks import check_idor
from fixtures import FakeFetcher, ok_result

AUTH_A = "Authorization: Bearer token-user-a"
OWNERS = {"order_a": "user_a", "order_b": "user_b"}


def _obj_id(url, location, param):
    if location == "path":
        return url.rstrip("/").rsplit("/", 1)[-1]
    return (parse_qs(urlsplit(url).query).get(param) or [""])[0]


def _vulnerable(location="path", param="id"):
    """Returns any object by id, ignoring who is authenticated (broken auth)."""
    def responder(url, **kwargs):
        oid = _obj_id(url, location, param)
        if oid not in OWNERS:
            return ok_result(url, status_code=404, text='{"error":"not found"}',
                             content_type="application/json")
        return ok_result(url, text=f'{{"id":"{oid}","owner":"{OWNERS[oid]}"}}',
                         content_type="application/json")
    return responder


def _protected(location="path", param="id"):
    """Enforces ownership: A can only read objects A owns."""
    def responder(url, **kwargs):
        oid = _obj_id(url, location, param)
        if oid not in OWNERS:
            return ok_result(url, status_code=404, text='{"error":"not found"}',
                             content_type="application/json")
        ident = "user_a" if "user-a" in ((kwargs.get("headers") or {}).get("Authorization", "")) else "unknown"
        if OWNERS[oid] != ident:
            return ok_result(url, status_code=403, text='{"error":"forbidden"}',
                             content_type="application/json")
        return ok_result(url, text=f'{{"id":"{oid}","owner":"{OWNERS[oid]}"}}',
                         content_type="application/json")
    return responder


TEMPLATE = "https://example.com/orders/{id}"


async def test_idor_cross_user_resource():
    findings = await check_idor(FakeFetcher(_vulnerable()), TEMPLATE,
                                auth_header_a=AUTH_A, id_a="order_a", id_b="order_b")
    assert len(findings) == 1
    assert findings[0].dedup_key.startswith("idor")
    assert "user_b" in findings[0].evidence


async def test_idor_same_user_resource():
    """Accessing one's own object is not IDOR."""
    findings = await check_idor(FakeFetcher(_vulnerable()), TEMPLATE,
                                auth_header_a=AUTH_A, id_a="order_a", id_b="order_a")
    assert findings == []


async def test_idor_protected_resource():
    findings = await check_idor(FakeFetcher(_protected()), TEMPLATE,
                                auth_header_a=AUTH_A, id_a="order_a", id_b="order_b")
    assert findings == []


async def test_idor_invalid_identifier():
    findings = await check_idor(FakeFetcher(_vulnerable()), TEMPLATE,
                                auth_header_a=AUTH_A, id_a="order_a", id_b="order_zzz")
    assert findings == []


async def test_idor_path_identifier():
    findings = await check_idor(FakeFetcher(_vulnerable("path")), TEMPLATE,
                                auth_header_a=AUTH_A, id_a="order_a", id_b="order_b",
                                location="path")
    assert len(findings) == 1


async def test_idor_query_identifier():
    q_template = "https://example.com/orders?id={id}"
    findings = await check_idor(FakeFetcher(_vulnerable("query", "id")), q_template,
                                auth_header_a=AUTH_A, id_a="order_a", id_b="order_b",
                                location="query", param="id")
    assert len(findings) == 1
