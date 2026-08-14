from app.services.discovery_types import DiscoveredPath
from app.services.repo_correlator import SourceFinding, correlate


def _endpoint(url: str) -> DiscoveredPath:
    return DiscoveredPath(url=url, status_code=200, content_type="application/json", response_size=10)


def _source_finding(file: str, confidence: str = "potential") -> SourceFinding:
    return SourceFinding(
        finding_type="sql_injection",
        file=file,
        line=10,
        severity="high",
        confidence=confidence,
        evidence="query built with string concatenation",
        secret_type="",
        redacted_value="",
        # Deliberately not shaped like the SQL-injection regex itself
        # (SELECT ... FROM ... WHERE ... = "..." + var) — this file's own
        # source would otherwise be flagged when this repo scans itself.
        code_context="query built from untrusted request input",
    )


def test_spurious_substring_match_does_not_correlate():
    """A bare substring test would match '/api/users' against
    'superusers_backup.js' because 'users' appears in the filename — that is
    not the same route and must not be reported as a correlation."""
    endpoints = [_endpoint("https://example.com/api/users")]
    sf = _source_finding("routes/superusers_backup.js")
    result = correlate([], endpoints, [sf])
    assert result == []


def test_genuine_match_correlates_at_potential_confidence():
    endpoints = [_endpoint("https://example.com/api/users")]
    sf = _source_finding("routes/api/users.js", confidence="potential")
    result = correlate([], endpoints, [sf])
    assert len(result) == 1
    assert result[0].confidence == "potential"


def test_genuine_match_propagates_confirmed_confidence_from_source():
    """Correlation may only propagate a confidence the source finding
    already had — it must never manufacture 'confirmed' from the filename
    match alone."""
    endpoints = [_endpoint("https://example.com/api/users")]
    sf = _source_finding("routes/api/users.js", confidence="confirmed")
    result = correlate([], endpoints, [sf])
    assert len(result) == 1
    assert result[0].confidence == "confirmed"


def test_correlated_finding_reuses_source_dedup_key():
    """The correlation must share the main pipeline's dedup key for this
    source finding (see deep_scan.py's _convert_repo_findings) so the risk
    model merges them into one contributor instead of double-counting."""
    endpoints = [_endpoint("https://example.com/api/users")]
    sf = _source_finding("routes/api/users.js")
    result = correlate([], endpoints, [sf])
    assert result[0].dedup_key == f"repo_code|{sf.file}|{sf.line}|{sf.finding_type}"
