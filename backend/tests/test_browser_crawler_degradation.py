import app.services.browser_crawler as browser_crawler
from app.services.scope import build_scope


async def test_missing_playwright_degrades_gracefully_never_raises(monkeypatch):
    monkeypatch.setattr(browser_crawler, "_PLAYWRIGHT_AVAILABLE", False)
    scope = build_scope("https://example.com")
    result = await browser_crawler.browser_crawl(scope, "https://example.com")
    assert result.pages == []
    assert result.network_requests == []
    assert result.errors
    assert "not installed" in result.errors[0].lower()
