from app.cli import _to_finding
from app.services.repo_correlator import SourceFinding
from app.services.risk_model import calculate_sentinel_risk


def _secret(local_only: bool) -> SourceFinding:
    return SourceFinding(
        finding_type="env_secret",
        file="backend/.env",
        line=4,
        severity="info" if local_only else "critical",
        confidence="uncertain" if local_only else "confirmed",
        evidence="GROQ_API_KEY=[REDACTED]",
        secret_type="GROQ_API_KEY",
        redacted_value="[REDACTED]",
        code_context="GROQ_API_KEY=[REDACTED] (gitignored, not committed to version control)"
        if local_only else "GROQ_API_KEY=[REDACTED]",
        local_only=local_only,
    )


def test_hygiene_secret_dedup_key_is_not_matched_as_a_vuln_class():
    """A gitignored secret's dedup key must not collide with the plain
    'env_secret' vuln-class prefix the risk model scores with a fixed CVSS
    vector — otherwise capping severity/confidence has no effect on the
    displayed CVSS line."""
    finding = _to_finding(_secret(local_only=True), "information_exposure")
    assert not finding.dedup_key.startswith("env_secret")
    assert "|env_secret" not in finding.dedup_key


def test_committed_secret_keeps_normal_dedup_key():
    finding = _to_finding(_secret(local_only=False), "information_exposure")
    assert finding.dedup_key == "env_secret|backend/.env|4"


def test_hygiene_secret_contributes_zero_to_risk_score():
    finding = _to_finding(_secret(local_only=True), "information_exposure")
    result = calculate_sentinel_risk([finding])
    assert result["score"] == 0
    assert result["contributors"][0]["type"] == "INFORMATIONAL"
    assert result["contributors"][0]["contribution"] == 0.0


def test_committed_secret_still_scores_as_a_vulnerability():
    finding = _to_finding(_secret(local_only=False), "information_exposure")
    result = calculate_sentinel_risk([finding])
    assert result["contributors"][0]["type"] == "VULNERABILITY"
    assert result["score"] > 0
