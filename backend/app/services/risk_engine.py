"""
Deterministic risk scoring.

Assigns each finding a 0-100 risk score from its severity and confidence,
and rolls a set of findings up into an overall risk level. Runs before and
independently of the LLM — the LLM refines, it does not originate, risk.
"""
from __future__ import annotations

from app.services.finding_types import FindingCandidate

_SEVERITY_BASE = {
    "critical": 95.0,
    "high": 78.0,
    "medium": 55.0,
    "low": 30.0,
    "info": 12.0,
}

_CONFIDENCE_FACTOR = {
    "confirmed": 1.0,
    "potential": 0.8,
    "uncertain": 0.55,
    "false_positive": 0.1,
}


def score_finding(finding: FindingCandidate) -> float:
    base = _SEVERITY_BASE.get(finding.severity, 20.0)
    factor = _CONFIDENCE_FACTOR.get(finding.confidence, 0.7)
    return round(base * factor, 1)


def score_all(findings: list[FindingCandidate]) -> None:
    """Score findings in place."""
    for f in findings:
        f.risk_score = score_finding(f)


# Representative 0-100 score per level, aligned to the analyst's bands
# (Minimal 0-19, Low 20-39, Medium 40-59, High 60-79, Critical 80-100).
_LEVEL_SCORE = {
    "critical": 90,
    "high": 70,
    "medium": 50,
    "low": 30,
    "minimal": 8,
}


def overall_score(findings: list[FindingCandidate]) -> int:
    """A deterministic 0-100 risk score, used when the AI analyst is
    unavailable so the UI always has a number to show."""
    return _LEVEL_SCORE.get(overall_risk(findings), 8)


def level_for_score(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "minimal"


# Findings whose severity is only as good as the evidence behind them: a
# pattern in source code or a published advisory is not a demonstrated attack.
_UNDEMONSTRATED_CATEGORIES = {"dependency_vulnerability", "code_security"}


def _evidence_weight(f: FindingCandidate) -> float:
    """How much this finding may influence the overall level.

    A demonstrated attack counts fully. An advisory or a matched code pattern
    is discounted, so no quantity of them can push a site to Critical on its
    own — only stronger evidence can.
    """
    if f.confidence == "false_positive":
        return 0.0
    weight = _CONFIDENCE_FACTOR.get(f.confidence, 0.7)
    if f.category in _UNDEMONSTRATED_CATEGORIES:
        weight *= 0.6
    if f.category == "security_headers":
        # A missing header is a weakened defence, never the headline risk.
        weight *= 0.5
    return weight


def overall_risk(findings: list[FindingCandidate]) -> str:
    """Roll findings up into one risk level.

    Driven by the single strongest evidence-backed finding, not by how many
    findings exist. Twenty low-confidence advisories stay Low; one
    demonstrated injection is High on its own.
    """
    # Third-party observations never move the target's risk level.
    live = [
        f for f in findings
        if f.confidence != "false_positive"
        and getattr(f, "contributes_to_risk", True)
    ]
    if not live:
        return "minimal"

    top = max(
        _SEVERITY_BASE.get(f.severity, 20.0) * _evidence_weight(f) for f in live
    )
    return level_for_score(int(round(top)))
