from app.services.response_analyzer import (
    INCONCLUSIVE,
    REAL,
    AnalyzedResponse,
    NotFoundProfile,
)


def _response(status_code: int, fingerprint: str, text: str = "blocked") -> AnalyzedResponse:
    return AnalyzedResponse(
        url="https://example.com/x",
        status_code=status_code,
        content_type="text/html",
        length=len(text),
        redirected=False,
        redirect_chain=[],
        title="",
        visible_text=text,
        fingerprint=fingerprint,
        shingles={hash(text)},
    )


def test_blanket_403_matching_baseline_is_inconclusive_not_real():
    """A WAF/catch-all auth gate that answers every path with the same 403
    page must not be reported as a confirmed discovery for every probed
    path — previously any 401/403 was returned as REAL unconditionally."""
    profile = NotFoundProfile()
    baseline = _response(403, fingerprint="blocked-page-fp")
    profile.fingerprints.add(baseline.fingerprint)
    profile.samples.append(baseline)

    candidate = _response(403, fingerprint="blocked-page-fp")
    assert profile.classify(candidate) == INCONCLUSIVE


def test_genuine_403_with_no_baseline_match_is_still_real():
    """A single resource that's genuinely auth-protected, with no evidence
    that random nonexistent paths get the same treatment, must keep
    presenting as REAL — this is the fail-safe path, unchanged."""
    profile = NotFoundProfile()
    candidate = _response(403, fingerprint="some-other-fp")
    assert profile.classify(candidate) == REAL


def test_403_distinct_from_baseline_blocked_page_is_real():
    profile = NotFoundProfile()
    baseline = _response(403, fingerprint="blocked-page-fp", text="generic block page")
    profile.fingerprints.add(baseline.fingerprint)
    profile.samples.append(baseline)

    candidate = _response(403, fingerprint="distinct-fp", text="this specific resource is forbidden")
    assert profile.classify(candidate) == REAL
