"""Dedicated tests for the static DOM-XSS analyzer (no JS execution)."""
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
