"""Dedicated tests for the CRLF / response-splitting detector."""
from urllib.parse import parse_qs, urlsplit

from app.services.phase2_checks import check_crlf
from fixtures import FakeFetcher, ok_result

URL = "https://example.com/setlang"
PARAM = "lang"


def _lang(url):
    return (parse_qs(urlsplit(url).query).get(PARAM) or [""])[0]


def _vulnerable_responder(url, **kwargs):
    """Server writes the (decoded) parameter into a response header; a CRLF in
    the value splits out an attacker-controlled header."""
    value = _lang(url)  # parse_qs already URL-decodes %0d%0a into \r\n
    headers = {}
    if "\r\n" in value:
        # Everything after the CRLF becomes injected header lines.
        injected = value.split("\r\n", 1)[1]
        if ":" in injected:
            name, _, val = injected.partition(":")
            headers[name.strip().lower()] = val.strip()
    return ok_result(url, text="language set", headers=headers)


def _encoded_aware_responder(url, **kwargs):
    """Reacts to the percent-encoded CRLF present in the raw query string."""
    low = url.lower()
    if "%0d%0a" in low or "\r\n" in _lang(url):
        return ok_result(url, text="ok", headers={"x-scanner-test": "phase2"})
    return ok_result(url, text="ok")


def _safe_responder(url, **kwargs):
    """Server strips CR/LF from the value -> no header injection."""
    return ok_result(url, text="language set")


async def test_crlf_header_injection():
    findings = await check_crlf(FakeFetcher(_vulnerable_responder), URL, PARAM)
    assert len(findings) == 1
    assert findings[0].dedup_key.startswith("crlf")


async def test_crlf_encoded_payload():
    findings = await check_crlf(FakeFetcher(_encoded_aware_responder), URL, PARAM)
    assert len(findings) == 1


async def test_crlf_safe_encoding():
    findings = await check_crlf(FakeFetcher(_safe_responder), URL, PARAM)
    assert findings == []


async def test_crlf_no_reflection():
    findings = await check_crlf(
        FakeFetcher(lambda url, **k: ok_result(url, text="unrelated")), URL, PARAM
    )
    assert findings == []
