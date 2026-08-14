from app.services.assessment import HIGH, INSUFFICIENT, LOW, compute_assessment
from app.services.coverage import CoverageMetrics
from app.services.finding_types import FindingCandidate


def _crit():
    return FindingCandidate(title="SQLi", category="input_validation", severity="critical",
                            confidence="confirmed", url="https://t/x", parameter="id")


def _cov(executed, not_executed, inconclusive=0, urls=10, apis=5, params=10):
    return CoverageMetrics(
        urls_discovered=urls, apis_discovered=apis, parameters_discovered=params,
        security_tests_executed=executed, security_tests_not_executed=not_executed,
        inconclusive_tests=inconclusive,
    )


def test_overall_is_coverage_independent():
    hi = compute_assessment([_crit()], _cov(10, 0))
    lo = compute_assessment([_crit()], _cov(1, 9))
    assert hi.overall_risk == lo.overall_risk  # coverage must NOT change the score
    assert hi.assessment_confidence == HIGH
    assert lo.assessment_confidence in (LOW, INSUFFICIENT)


def test_no_findings_is_zero():
    a = compute_assessment([], _cov(10, 0))
    assert a.overall_risk == 0
    assert a.risk_level == "minimal"


def test_confirmed_critical_never_suppressed_by_low_coverage():
    a = compute_assessment([_crit()], _cov(1, 20))
    assert a.overall_risk >= 60  # a confirmed critical stays high regardless of coverage


def test_inconclusive_heavy_is_insufficient():
    a = compute_assessment([], _cov(1, 1, inconclusive=8))
    assert a.assessment_confidence == INSUFFICIENT
