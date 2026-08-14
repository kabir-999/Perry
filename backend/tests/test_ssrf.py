"""Dedicated tests for the SSRF detector (out-of-band callback oracle)."""
from urllib.parse import parse_qs, urlsplit

from app.services.phase2_checks import check_ssrf, classify_ssrf_target
from fixtures import FakeFetcher, ok_result

URL = "https://example.com/fetch"


def _url_param(url, name="url"):
    return (parse_qs(urlsplit(url).query).get(name) or [""])[0]


def _fetching_responder(url, **kwargs):
    """Server that performs the requested server-side fetch and echoes evidence
    (the callback token) — simulating a real SSRF."""
    target = _url_param(url)
    return ok_result(url, text=f"Fetched {target}\nSSRF-FETCHED")


async def test_ssrf_external_callback():
    findings = await check_ssrf(FakeFetcher(_fetching_responder), URL, "url")
    assert len(findings) == 1
    assert findings[0].dedup_key.startswith("ssrf")
    assert findings[0].confidence == "confirmed"


async def test_ssrf_no_server_side_fetch():
    """Server does not fetch the URL (just renders the page) -> no finding."""
    findings = await check_ssrf(
        FakeFetcher(lambda url, **k: ok_result(url, text="<p>Submitted.</p>")), URL, "url"
    )
    assert findings == []


async def test_ssrf_url_parameter():
    findings = await check_ssrf(FakeFetcher(_fetching_responder), URL, "webhook")
    assert len(findings) == 1


async def test_ssrf_non_url_parameter():
    """A non-URL-like parameter must be skipped without any request sent."""
    fetcher = FakeFetcher(_fetching_responder)
    findings = await check_ssrf(fetcher, URL, "q", example="hello")
    assert findings == []
    assert fetcher.calls == []


def test_ssrf_private_target_classification():
    assert classify_ssrf_target("http://127.0.0.1/x") == "internal"
    assert classify_ssrf_target("http://10.0.0.5/x") == "internal"
    assert classify_ssrf_target("http://169.254.169.254/latest/meta-data") == "cloud_metadata"
    assert classify_ssrf_target("https://example.com/x") == "external"
