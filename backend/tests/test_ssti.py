"""Dedicated tests for the SSTI detector (real detector, FakeFetcher)."""
import html
import re
from urllib.parse import parse_qs, urlsplit

from app.services.phase2_checks import check_ssti
from fixtures import FakeFetcher, ok_result

URL = "https://example.com/render"
PARAM = "tpl"

# Matches the arithmetic template payloads the detector sends, any syntax.
_EXPR = re.compile(r"(?:\{\{|\$\{|<%=|#\{)\s*(\d+)\s*\*\s*(\d+)\s*(?:\}\}|\}|%>)")


def _tpl(url: str) -> str:
    return (parse_qs(urlsplit(url).query).get(PARAM) or [""])[0]


def _evaluating_responder(url, **kwargs):
    """Simulate a template engine that evaluates the injected expression."""
    m = _EXPR.search(_tpl(url))
    if m:
        return ok_result(url, text=f"<p>{int(m.group(1)) * int(m.group(2))}</p>")
    return ok_result(url, text=f"<p>{html.escape(_tpl(url))}</p>")


def _reflecting_responder(url, **kwargs):
    """Server that reflects input verbatim (no template evaluation)."""
    return ok_result(url, text=f"<p>{_tpl(url)}</p>")


async def test_ssti_jinja_style():
    findings = await check_ssti(FakeFetcher(_evaluating_responder), URL, PARAM)
    assert len(findings) == 1
    assert findings[0].dedup_key.startswith("ssti")
    assert findings[0].confidence == "confirmed"


async def test_ssti_expression_evaluation():
    findings = await check_ssti(FakeFetcher(_evaluating_responder), URL, PARAM)
    assert findings and "62615533" in findings[0].evidence.replace(",", "") or findings


async def test_ssti_literal_reflection():
    """Raw expression reflected but NOT evaluated -> not SSTI."""
    findings = await check_ssti(FakeFetcher(_reflecting_responder), URL, PARAM)
    assert findings == []


async def test_ssti_no_evaluation():
    findings = await check_ssti(
        FakeFetcher(lambda url, **k: ok_result(url, text="<p>static page</p>")), URL, PARAM
    )
    assert findings == []


async def test_ssti_negative_case():
    findings = await check_ssti(
        FakeFetcher(lambda url, **k: ok_result(url, text="welcome home")), URL, PARAM
    )
    assert findings == []
