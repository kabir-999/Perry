from types import SimpleNamespace

from app.services.report_generator import build_report


def _finding(fingerprint: str, **overrides) -> SimpleNamespace:
    base = dict(
        title="X", category="input_validation", severity="high", confidence="potential",
        url="https://example.com/x", parameter="q", risk_score=10.0, llm_verdict=None,
        remediation="", fingerprint=fingerprint,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def _scan() -> SimpleNamespace:
    return SimpleNamespace(
        id="scan-1", target=None, risk_score=10, sentinel_risk_json="{}",
        final_risk="low", ai_analyzed=False, ai_error="", ai_summary="",
        ai_recommendation="", risk_factors_json="", urls_discovered=0,
        apis_discovered=0, parameters_discovered=0, subdomains_discovered=0,
        requests_made=0,
    )


def test_no_prior_scan_is_unverified():
    report = build_report(_scan(), [_finding("fp1")], prior_fingerprints=None)
    entry = report["findings_by_severity"]["high"][0]
    assert entry["verification_status"] == "UNVERIFIED"
    assert report["remediation"]["has_prior_scan"] is False


def test_finding_present_before_and_now_is_open():
    report = build_report(
        _scan(), [_finding("fp1")], prior_fingerprints={"fp1"},
    )
    entry = report["findings_by_severity"]["high"][0]
    assert entry["verification_status"] == "OPEN"


def test_finding_absent_two_scans_ago_present_last_scan_absent_now_is_fixed():
    """No current Finding row exists for a fixed issue — it's reported via
    the separate fixed_since_last_scan count, not per-finding."""
    report = build_report(
        _scan(), [], prior_fingerprints={"fp1"}, prior_prior_fingerprints=set(),
    )
    assert report["remediation"]["fixed_since_last_scan"] == 1


def test_finding_fixed_then_reappearing_is_regressed():
    report = build_report(
        _scan(), [_finding("fp1")],
        prior_fingerprints=set(),  # absent in the immediately preceding scan
        prior_prior_fingerprints={"fp1"},  # but present two scans ago
    )
    entry = report["findings_by_severity"]["high"][0]
    assert entry["verification_status"] == "REGRESSED"


def test_brand_new_finding_with_history_is_open_not_regressed():
    report = build_report(
        _scan(), [_finding("fp-new")],
        prior_fingerprints={"fp1"}, prior_prior_fingerprints={"fp1"},
    )
    entry = report["findings_by_severity"]["high"][0]
    assert entry["verification_status"] == "OPEN"
