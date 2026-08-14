"""
Overall application risk, assessment confidence, and coverage — three
SEPARATE numbers, never blended (§24/§25).

  - Overall Risk      — the highest confirmed/validated finding's 5-factor
                        score (risk_engine.overall_confirmed_risk). Coverage
                        NEVER modifies this number.
  - Assessment Confidence — how much to trust that risk score, derived from
                        coverage + inconclusive-test ratio + scan-limit/error
                        signals. Reported alongside, never folded in.
  - Assessment Coverage   — the raw 0-100% of discovery+testing completed.

This is what keeps a barely-examined target from ever reading as "safe": low
coverage lowers *confidence*, it does not lower the risk of a confirmed
finding, and it does not inflate the risk of a clean-but-shallow scan.
"""
from __future__ import annotations

from dataclasses import dataclass

from app.services.coverage import CoverageMetrics
from app.services.risk_engine import level_for_score, overall_confirmed_risk

HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"
INSUFFICIENT = "INSUFFICIENT"


@dataclass
class Assessment:
    overall_risk: int
    risk_level: str
    assessment_confidence: str
    assessment_coverage: int
    warning: str = ""


def _confidence(
    coverage_ratio: float,
    *,
    inconclusive_tests: int,
    security_tests_executed: int,
    security_tests_not_executed: int,
    scan_errors: bool,
    crawl_limit_reached: bool,
) -> str:
    """Deterministic thresholds on coverage + inconclusive-test ratio +
    scan-limit/error signals. Never inferred from the risk score itself."""
    total_tests = security_tests_executed + security_tests_not_executed + inconclusive_tests
    inconclusive_ratio = (inconclusive_tests / total_tests) if total_tests else 0.0

    if coverage_ratio < 0.25 or inconclusive_ratio > 0.5:
        return INSUFFICIENT
    if coverage_ratio < 0.5 or scan_errors or crawl_limit_reached:
        return LOW
    if coverage_ratio < 0.8:
        return MEDIUM
    return HIGH


def _warning(confidence: str, coverage_pct: int) -> str:
    if confidence == HIGH:
        return ""
    if confidence == INSUFFICIENT:
        return (
            f"Assessment coverage was only {coverage_pct}% — Sentinel could "
            "not reach enough of the application's attack surface to draw a "
            "reliable conclusion. Treat the risk score as provisional; "
            "increase crawl depth/budget or supply authentication and re-scan."
        )
    if confidence == LOW:
        return (
            f"Assessment coverage was {coverage_pct}%. Some attack surface "
            "was not discovered or not tested, so this assessment may miss "
            "issues in the untested surface."
        )
    return (
        f"Assessment coverage was {coverage_pct}%. Most, but not all, of the "
        "discovered attack surface was tested."
    )


def compute_assessment(
    findings: list,
    coverage: CoverageMetrics,
    *,
    scan_errors: bool = False,
    crawl_limit_reached: bool = False,
) -> Assessment:
    """Overall risk = highest confirmed finding score (coverage-independent).
    Confidence + coverage are computed and reported separately."""
    overall_risk = overall_confirmed_risk(findings)
    risk_level = level_for_score(overall_risk)
    coverage_ratio = coverage.coverage_ratio
    coverage_pct = round(coverage_ratio * 100)

    confidence = _confidence(
        coverage_ratio,
        inconclusive_tests=coverage.inconclusive_tests,
        security_tests_executed=coverage.security_tests_executed,
        security_tests_not_executed=coverage.security_tests_not_executed,
        scan_errors=scan_errors,
        crawl_limit_reached=crawl_limit_reached,
    )
    return Assessment(
        overall_risk=overall_risk,
        risk_level=risk_level,
        assessment_confidence=confidence,
        assessment_coverage=coverage_pct,
        warning=_warning(confidence, coverage_pct),
    )
