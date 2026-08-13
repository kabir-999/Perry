from app.services.finding_types import FindingCandidate
from app.services.risk_model import calculate_sentinel_risk, confidence_of, deduplicate


def test_confidence_of_malformed_value_is_treated_as_uncertain():
    """A typo'd/missing confidence string must never score higher than a
    legitimately 'uncertain' finding — the old default of 0.5 sat between
    'uncertain' (0.35) and 'potential' (0.60), silently rewarding a bug."""
    f = FindingCandidate(title="x", category="code_security", severity="low", confidence="not_a_real_value")
    assert confidence_of(f) == confidence_of(
        FindingCandidate(title="y", category="code_security", severity="low", confidence="uncertain")
    )


def test_confidence_of_known_values_unchanged():
    f = FindingCandidate(title="x", category="code_security", severity="low", confidence="confirmed")
    assert confidence_of(f) == 0.95


def test_deduplicate_merges_same_dedup_key_keeping_strongest_confidence():
    a = FindingCandidate(
        title="SQL Injection in app.py",
        category="code_security",
        severity="high",
        confidence="potential",
        dedup_key="repo_code|app.py|10|sql_injection",
    )
    b = FindingCandidate(
        title="Correlated SQL Injection at /api/users",
        category="source_correlation",
        severity="high",
        confidence="confirmed",
        dedup_key="repo_code|app.py|10|sql_injection",
    )
    merged = deduplicate([a, b])
    assert len(merged) == 1
    assert merged[0].confidence == "confirmed"


def test_correlation_finding_does_not_double_count_in_risk_score():
    """The same underlying source finding, once as the plain SAST hit and
    once as the repo_correlator's 'confirmed at this endpoint' annotation,
    must produce exactly one contributor to the risk score, not two."""
    source = FindingCandidate(
        title="Sql Injection in app.py",
        category="code_security",
        severity="high",
        confidence="potential",
        dedup_key="repo_code|app.py|10|sql_injection",
    )
    correlation = FindingCandidate(
        title="Correlated SQL Injection at /api/users",
        category="source_correlation",
        severity="high",
        confidence="potential",
        dedup_key="repo_code|app.py|10|sql_injection",
    )
    result = calculate_sentinel_risk([source, correlation])
    assert len(result["contributors"]) == 1
