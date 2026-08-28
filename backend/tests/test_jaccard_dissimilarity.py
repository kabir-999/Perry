"""Regression tests for the Jaccard shingle-based body-dissimilarity metric
(response_analyzer.jaccard/jaccard_detail + anomaly_engine.probe_anomaly's
audit trail). Verifies the exact mathematical contract:

    Body_Dissimilarity = 1 - J(shingles(base), shingles(fuzz))

is deterministic, symmetric, unbiased by any other signal, and that a raw
Jaccard/dissimilarity value never implies a severity or vulnerability
verdict on its own.
"""
from app.services import anomaly_engine as A
from app.services.response_analyzer import SHINGLE_SIZE, AnalyzedResponse, jaccard, jaccard_detail


def _resp(status=200, length=100, shingles=(), redirected=False):
    return AnalyzedResponse(
        url="https://t/x", status_code=status, content_type="text/html",
        length=length, redirected=redirected, redirect_chain=[], title="",
        visible_text="", fingerprint=f"{status}:{length}", shingles=set(shingles),
    )


# --------------------------------------------------------------------------
# Jaccard/dissimilarity math — edge cases from spec §10
# --------------------------------------------------------------------------

def test_identical_shingle_sets_give_zero_dissimilarity():
    a = {1, 2, 3, 4, 5}
    assert jaccard(a, set(a)) == 1.0
    assert jaccard_detail(a, set(a))["body_dissimilarity"] == 0.0


def test_completely_disjoint_nonempty_sets_give_full_dissimilarity():
    a, b = {1, 2, 3}, {4, 5, 6}
    assert jaccard(a, b) == 0.0
    assert jaccard_detail(a, b)["body_dissimilarity"] == 1.0


def test_both_empty_defined_as_zero_dissimilarity():
    assert jaccard(set(), set()) == 1.0
    assert jaccard_detail(set(), set())["body_dissimilarity"] == 0.0


def test_one_empty_one_nonempty_gives_full_dissimilarity():
    assert jaccard(set(), {1, 2, 3}) == 0.0
    assert jaccard(({1, 2, 3}), set()) == 0.0
    assert jaccard_detail(set(), {1, 2, 3})["body_dissimilarity"] == 1.0


def test_intermediate_overlap_matches_exact_formula():
    # |A∩B|=2, |A∪B|=6 -> J = 1/3
    a, b = {1, 2, 3, 4}, {3, 4, 5, 6}
    j = jaccard(a, b)
    assert abs(j - (2 / 6)) < 1e-9
    detail = jaccard_detail(a, b)
    assert abs(detail["jaccard"] - j) < 1e-6
    assert abs(detail["body_dissimilarity"] - (1 - j)) < 1e-6
    assert detail["intersection"] == 2
    assert detail["union"] == 6


def test_jaccard_is_symmetric():
    a, b = {1, 2, 3, 7}, {3, 4, 5}
    assert jaccard(a, b) == jaccard(b, a)


def test_jaccard_is_deterministic_across_repeated_calls():
    a, b = {1, 2, 3, 4}, {2, 3, 5}
    results = {jaccard(a, b) for _ in range(20)}
    assert len(results) == 1


def test_jaccard_detail_exposes_full_audit_trail():
    a, b = {1, 2, 3}, {2, 3, 4, 5}
    detail = jaccard_detail(a, b)
    assert set(detail.keys()) >= {
        "baseline_shingle_count", "fuzz_shingle_count",
        "intersection", "union", "jaccard", "body_dissimilarity",
    }
    assert detail["baseline_shingle_count"] == 3
    assert detail["fuzz_shingle_count"] == 4


# --------------------------------------------------------------------------
# probe_anomaly's audit trail — never adjusts the raw Jaccard-derived value
# --------------------------------------------------------------------------

def test_probe_anomaly_body_anomaly_score_is_exactly_100x_dissimilarity():
    base = _resp(shingles=range(0, 10))
    fuzz = _resp(shingles=range(5, 15))  # 5 shared, 15 total -> J = 1/3
    _, factors = A.probe_anomaly(base, fuzz, signal_matched=False)
    audit = factors["jaccard_audit"]
    expected_dissim = 1 - jaccard(base.shingles, fuzz.shingles)
    assert abs(audit["body_dissimilarity"] - expected_dissim) < 1e-6
    assert audit["body_anomaly_score"] == round(100 * expected_dissim)


def test_probe_anomaly_records_shingle_size_and_metric_name():
    base = _resp(shingles={1, 2, 3})
    fuzz = _resp(shingles={1, 2, 3})
    _, factors = A.probe_anomaly(base, fuzz, signal_matched=False)
    audit = factors["jaccard_audit"]
    assert audit["shingle_size"] == SHINGLE_SIZE
    assert audit["metric"] == "jaccard_shingle_dissimilarity"


def test_signal_and_status_do_not_alter_the_raw_body_dissimilarity():
    """Changing signal_matched or the status code must not change the
    Jaccard-derived body_dissimilarity value itself — only the separately
    reported blended `score` may move."""
    base = _resp(status=200, shingles=range(0, 10))
    fuzz_same_status = _resp(status=200, shingles=range(5, 15))
    fuzz_diff_status = _resp(status=500, shingles=range(5, 15))

    _, f1 = A.probe_anomaly(base, fuzz_same_status, signal_matched=False)
    _, f2 = A.probe_anomaly(base, fuzz_same_status, signal_matched=True)
    _, f3 = A.probe_anomaly(base, fuzz_diff_status, signal_matched=False)

    # Same bodies -> identical body_dissimilarity regardless of signal or
    # status-code differences elsewhere.
    assert f1["jaccard_audit"]["body_dissimilarity"] == f2["jaccard_audit"]["body_dissimilarity"]
    assert f1["jaccard_audit"]["body_dissimilarity"] == f3["jaccard_audit"]["body_dissimilarity"]
    # But the blended score IS allowed to move with signal/status — those
    # are separate, clearly-labelled factors, not folded into the Jaccard
    # value.
    assert f2["signal"] == 1.0 and f1["signal"] == 0.0
    assert f3["status_changed"] is True and f1["status_changed"] is False


def test_changing_the_fuzz_response_changes_the_measured_dissimilarity():
    base = _resp(shingles=range(0, 10))
    fuzz_close = _resp(shingles=range(0, 9))       # 9/10 shared
    fuzz_far = _resp(shingles=range(50, 60))       # nothing shared

    _, f_close = A.probe_anomaly(base, fuzz_close, signal_matched=False)
    _, f_far = A.probe_anomaly(base, fuzz_far, signal_matched=False)

    d_close = f_close["jaccard_audit"]["body_dissimilarity"]
    d_far = f_far["jaccard_audit"]["body_dissimilarity"]
    assert d_far > d_close
    assert d_far == 1.0


def test_same_pair_always_produces_the_same_score():
    base = _resp(shingles=range(0, 20))
    fuzz = _resp(shingles=range(10, 30))
    results = {A.probe_anomaly(base, fuzz, signal_matched=True)[0] for _ in range(10)}
    assert len(results) == 1


# --------------------------------------------------------------------------
# No hardcoded severity/criticality inference from raw dissimilarity alone
# --------------------------------------------------------------------------

def test_high_dissimilarity_alone_does_not_imply_vulnerable_status():
    """A maximally dissimilar body is an anomaly-scoring input, not a
    classification — probe_anomaly itself never returns a TestStatus, and
    a high score must not by itself be labelled a vulnerability anywhere in
    this module."""
    base = _resp(shingles=range(0, 10))
    fuzz = _resp(shingles=range(100, 110))  # fully disjoint -> dissimilarity 1.0
    score, factors = A.probe_anomaly(base, fuzz, signal_matched=False)
    assert factors["jaccard_audit"]["body_dissimilarity"] == 1.0
    # probe_anomaly returns only a float score + factors dict — no status,
    # verdict, or severity field exists to manufacture certainty from.
    assert isinstance(score, float)
    assert "status" not in factors
    assert "severity" not in factors
    assert "vulnerable" not in factors


def test_compute_anomaly_reports_metric_metadata():
    """The scan-level anomaly output must record which objective metric and
    shingle size produced its scores, per spec §3."""
    result = A.compute_anomaly([])
    assert result["metric_metadata"] == {
        "metric": "jaccard_shingle_dissimilarity",
        "shingle_size": SHINGLE_SIZE,
    }


def test_low_dissimilarity_with_confirmed_signal_can_still_score_high():
    """The inverse must also hold: a small body difference does not force a
    low score when the attack's own detector already fired — signal and
    body dissimilarity are independent inputs, neither overrides the other's
    meaning."""
    base = _resp(shingles=range(0, 10))
    fuzz = _resp(shingles=range(0, 10))  # identical bodies -> dissimilarity 0
    score, factors = A.probe_anomaly(base, fuzz, signal_matched=True)
    assert factors["jaccard_audit"]["body_dissimilarity"] == 0.0
    # The detector-fired signal alone (weight 0.55) still pushes the blended
    # score well above "minimal", proving dissimilarity isn't the sole input.
    assert score >= 0.5
