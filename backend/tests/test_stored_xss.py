"""Dedicated tests for the Stored XSS detector (multi-request workflow)."""
import html

from app.services.phase2_checks import check_stored_xss
from fixtures import FakeFetcher, ok_result

SUBMIT = "https://example.com/comments"
VIEW = "https://example.com/comments"


def _stateful(*, persist=True, escape=False):
    """A tiny in-memory comment store. POST persists the comment; GET renders
    all stored comments (raw or HTML-escaped)."""
    store: list[str] = []

    def responder(url, **kwargs):
        method = kwargs.get("method", "GET").upper()
        if method == "POST":
            if persist:
                store.append((kwargs.get("data") or {}).get("comment", ""))
            return ok_result(url, status_code=302, text="")
        rendered = "".join(
            (html.escape(c) if escape else c) for c in store
        )
        return ok_result(url, text=f"<ul>{rendered}</ul>")

    return responder


async def test_stored_xss_basic():
    findings = await check_stored_xss(FakeFetcher(_stateful()), SUBMIT, VIEW)
    assert len(findings) == 1
    assert findings[0].dedup_key.startswith("stored_xss")
    assert findings[0].confidence == "confirmed"


async def test_stored_xss_marker_persists():
    findings = await check_stored_xss(FakeFetcher(_stateful()), SUBMIT, VIEW)
    assert findings and "persisted" in findings[0].evidence.lower()


async def test_stored_xss_not_persisted():
    findings = await check_stored_xss(FakeFetcher(_stateful(persist=False)), SUBMIT, VIEW)
    assert findings == []


async def test_stored_xss_escaped_output():
    """Persisted but HTML-escaped on render -> not exploitable, no finding."""
    findings = await check_stored_xss(FakeFetcher(_stateful(escape=True)), SUBMIT, VIEW)
    assert findings == []


async def test_stored_xss_negative_case():
    findings = await check_stored_xss(
        FakeFetcher(lambda url, **k: ok_result(url, text="<ul></ul>")), SUBMIT, VIEW
    )
    assert findings == []
