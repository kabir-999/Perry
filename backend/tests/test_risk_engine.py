from app.services.risk_engine import (
    _WEIGHTS,
    level_for_score,
    overall_confirmed_risk,
    risk_breakdown,
    score_all,
    score_finding,
)
from app.services.finding_types import FindingCandidate


def _f(**kw):
    base = dict(title="X", category="input_validation", severity="high",
                confidence="confirmed", url="https://t/x", parameter="q")
    base.update(kw)
    return FindingCandidate(**base)


def test_weights_sum_to_one():
    assert abs(sum(_WEIGHTS.values()) - 1.0) < 1e-9


def test_breakdown_has_five_factors_and_matches_score():
    b = risk_breakdown(_f())
    assert set(b["factors"]) == {"type_severity", "confidence", "exposure", "blast_radius", "asset_severity"}
    assert abs(b["score"] - score_finding(_f())) < 1e-6


def test_critical_scores_higher_than_low():
    assert score_finding(_f(severity="critical")) > score_finding(_f(severity="low"))


def test_confirmed_scores_higher_than_uncertain():
    assert score_finding(_f(confidence="confirmed")) > score_finding(_f(confidence="uncertain"))


def test_level_ladder():
    assert level_for_score(80) == "critical"
    assert level_for_score(79) == "high"
    assert level_for_score(60) == "high"
    assert level_for_score(40) == "medium"
    assert level_for_score(20) == "low"
    assert level_for_score(19) == "minimal"


def test_overall_is_highest_confirmed_finding_score():
    findings = [_f(severity="low", confidence="confirmed"),
                _f(severity="critical", confidence="confirmed")]
    assert overall_confirmed_risk(findings) == round(max(score_finding(x) for x in findings))


def test_uncertain_and_false_positive_never_set_overall():
    assert overall_confirmed_risk([_f(confidence="uncertain")]) == 0
    assert overall_confirmed_risk([_f(confidence="false_positive")]) == 0


def test_no_findings_is_zero():
    assert overall_confirmed_risk([]) == 0


def test_score_all_sets_risk_score_in_place():
    findings = [_f(), _f(severity="low")]
    score_all(findings)
    assert all(0 <= f.risk_score <= 100 for f in findings)
