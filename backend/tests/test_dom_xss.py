"""Dedicated tests for the static DOM-XSS analyzer (no JS execution)."""
import app.services.active_engine as active_engine
from app.services.dom_xss import analyze_dom_xss

SRC = "https://example.com/app.js"


def test_dom_xss_source_to_innerhtml():
    js = "var el = document.getElementById('o'); el.innerHTML = location.hash;"
    findings = analyze_dom_xss(js, source_url=SRC)
    assert len(findings) == 1
    assert findings[0].dedup_key.startswith("dom_xss")
    assert findings[0].confidence == "confirmed"


def test_dom_xss_hash_to_sink():
    """Taint flows through an intermediate variable into document.write."""
    js = "var h = location.hash.substring(1); document.write(h);"
    findings = analyze_dom_xss(js, source_url=SRC)
    assert len(findings) == 1
    assert "document.write" in findings[0].title


def test_dom_xss_safe_text_content():
    """textContent is not a dangerous sink -> no finding."""
    js = "el.textContent = location.hash;"
    findings = analyze_dom_xss(js, source_url=SRC)
    assert findings == []


def test_dom_xss_unrelated_sink():
    """A sink assigned only a static string literal is safe."""
    js = "el.innerHTML = '<b>Welcome</b>';"
    findings = analyze_dom_xss(js, source_url=SRC)
    assert findings == []


def test_dom_xss_no_source():
    """A sink fed by non-source application data is not reported."""
    js = "eval(config.expression);"
    findings = analyze_dom_xss(js, source_url=SRC)
    assert findings == []


async def test_dom_xss_browser_check_skips_in_lite_profile(monkeypatch):
    monkeypatch.setattr(active_engine.settings, "SCAN_PROFILE", "lite")
    monkeypatch.setattr(active_engine, "_PLAYWRIGHT_AVAILABLE", True)
    target = active_engine.ParamTarget(
        url="https://example.com/?q=test",
        name="q",
        location="query",
        method="GET",
    )
    findings = await active_engine.check_dom_xss(target)
    assert findings == []
