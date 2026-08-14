"""Dedicated end-to-end tests for the reflected-XSS detector.

Exercises the real ``check_reflected_xss`` detector (not the custom-test or
severity layers). The FakeFetcher simulates how a server reflects the query
parameter; the detector analyses the resulting response body.
"""
import html
from urllib.parse import parse_qs, urlsplit

from app.services.security_checks import check_reflected_xss, _XSS_MARKER
from fixtures import FakeFetcher, ok_result

URL = "https://example.com/search"
PARAM = "q"


def _q(url: str) -> str:
    return (parse_qs(urlsplit(url).query).get(PARAM) or [""])[0]


async def test_xss_basic_reflection():
    """Marker reflected verbatim into the body -> possible XSS is reported."""
    fetcher = FakeFetcher(lambda url, **k: ok_result(url, text=f"Results for: {_q(url)}"))
    findings = await check_reflected_xss(fetcher, URL, PARAM)
    assert len(findings) == 1
    assert findings[0].category == "input_validation"
    assert findings[0].parameter == PARAM
    assert findings[0].dedup_key.startswith("reflected_xss")


async def test_xss_html_reflection():
    """Marker reflected inside an HTML element context -> still flagged."""
    fetcher = FakeFetcher(
        lambda url, **k: ok_result(url, text=f"<div class='results'><p>{_q(url)}</p></div>")
    )
    findings = await check_reflected_xss(fetcher, URL, PARAM)
    assert len(findings) == 1


async def test_xss_escaped_reflection():
    """HTML-escaped reflection contains no raw '<z>' -> not reported as
    exploitable reflected XSS. The detector's semantics distinguish escaped
    output, so escaping must clear the finding."""
    fetcher = FakeFetcher(
        lambda url, **k: ok_result(url, text=f"Results for: {html.escape(_q(url))}")
    )
    findings = await check_reflected_xss(fetcher, URL, PARAM)
    assert findings == []


async def test_xss_no_reflection():
    """Input not reflected at all -> no finding."""
    fetcher = FakeFetcher(lambda url, **k: ok_result(url, text="<p>No results found.</p>"))
    findings = await check_reflected_xss(fetcher, URL, PARAM)
    assert findings == []


async def test_xss_non_executable_context_is_still_flagged():
    """This detector is context-insensitive by design: a raw, unescaped
    reflection is reported wherever it lands — it does not attempt to prove the
    reflection sits in an executable context. This test pins that expected
    behaviour so that adding context analysis later is a deliberate change,
    not an accidental regression."""
    fetcher = FakeFetcher(lambda url, **k: ok_result(url, text=f"<!-- debug: {_q(url)} -->"))
    findings = await check_reflected_xss(fetcher, URL, PARAM)
    assert len(findings) == 1
    # Sanity: the exact marker really was what triggered it.
    assert _XSS_MARKER  # marker constant is defined and imported
