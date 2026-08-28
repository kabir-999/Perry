"""
Anomaly scoring — turn the baseline-vs-fuzz comparison into a graded score.

Every active test sends a *baseline* request (the parameter's normal value)
and one or more *fuzz* requests (malicious payloads), and detection is a
comparison of the two: did a new error/marker/file-content signature appear,
did the body diverge, did the status or size change? This module turns that
comparison into a numeric **anomaly score** so a scan can report, per attack
domain (SQL injection, XSS, path traversal, …) and overall, *how anomalously
the application behaved under attack* — independent of, and complementary to,
the deterministic finding-severity risk score.

Two anomaly sources feed the aggregation:

  1. **Measured** — a real response diff computed by :func:`probe_anomaly`
     from the baseline and fuzz ``AnalyzedResponse`` objects. Used by the
     active injection family, where a live baseline/fuzz pair exists.
  2. **Outcome-derived** — a fallback from the test's final status/confidence
     (:func:`status_anomaly`), used where no baseline/fuzz pair is produced
     (evidence-driven modules, or probes whose detector returns only a
     finding). This is labelled ``measured=false`` so consumers can tell the
     difference.

The score is a *suspicion* signal, not a severity: a value near 100 means the
app behaved very differently under attack (or a vulnerability was confirmed),
near 0 means it behaved essentially identically to baseline.
"""
from __future__ import annotations

from app.services.attacks import catalog as C
from app.services.response_analyzer import SHINGLE_SIZE, AnalyzedResponse, jaccard_detail
from app.services.test_status import TestStatus

# Metric identity for scan metadata / API auditing (§3 of the Jaccard spec):
# every consumer of a probe's anomaly factors can see exactly which formula
# and shingle size produced the body-dissimilarity number.
ANOMALY_METRIC = "jaccard_shingle_dissimilarity"

# Statuses that represent an executed comparison (baseline vs fuzz actually
# happened, or a definite outcome was reached). NOT_TESTED / NOT_APPLICABLE are
# excluded from anomaly scoring entirely — no comparison took place, so scoring
# them would be dishonest.
_SCORABLE = {
    TestStatus.VULNERABLE, TestStatus.NOT_VULNERABLE,
    TestStatus.INCONCLUSIVE, TestStatus.HARDENING,
}

# Outcome-derived anomaly when no measured response diff is available.
_STATUS_ANOMALY = {
    TestStatus.VULNERABLE: 0.90,
    TestStatus.INCONCLUSIVE: 0.35,
    # A confirmed hardening gap is a real, non-zero observation (unlike
    # NOT_VULNERABLE's "nothing found") but nowhere near an exploit — well
    # below INCONCLUSIVE's "something suspicious we couldn't resolve."
    TestStatus.HARDENING: 0.25,
    TestStatus.NOT_VULNERABLE: 0.05,
}
_CONFIDENCE_MULT = {"confirmed": 1.0, "potential": 0.95, "uncertain": 0.85, "": 0.9}
# Evidence-driven modules (security misconfiguration, sensitive-info,
# vhost/subdomain checks) have no baseline/fuzz pair to measure a real
# diff from, so every VULNERABLE execution fell back to the same flat 0.90
# regardless of what was actually found — a confirmed low-severity "missing
# security headers" finding scored identically to a critical one. Scaling
# by the underlying finding's own severity keeps a genuinely dangerous
# evidence-driven finding at full weight while a low/info one no longer
# reads as "critical" in the anomaly score.
_SEVERITY_MULT = {"critical": 1.0, "high": 0.85, "medium": 0.65, "low": 0.4, "info": 0.2}

# Weights for the measured per-probe anomaly components. `signal` (the detector
# fired) dominates; the response-diff components add magnitude.
_W_SIGNAL = 0.55
_W_DISSIM = 0.20
_W_LENGTH = 0.15
_W_STATUS = 0.10

# Overall = weighted blend of the worst domain and the mean across tested
# domains, so a single confirmed domain dominates but breadth still counts.
_W_MAX_DOMAIN = 0.65
_W_MEAN_DOMAIN = 0.35

# Domain score = blend of the worst probe and the mean probe in that domain.
_W_MAX_PROBE = 0.70
_W_MEAN_PROBE = 0.30

_ANOMALOUS_THRESHOLD = 0.50  # a per-probe anomaly at/above this is "anomalous"


def _clamp01(x: float) -> float:
    return 0.0 if x < 0 else 1.0 if x > 1 else x


def probe_anomaly(
    baseline: AnalyzedResponse | None,
    fuzz: AnalyzedResponse | None,
    *,
    signal_matched: bool,
) -> tuple[float, dict]:
    """Anomaly magnitude in [0,1] for one baseline-vs-fuzz probe.

    Combines whether the attack's detector fired (`signal_matched`) with the
    measured divergence of the fuzz response from the baseline: body
    dissimilarity (1 − Jaccard over content shingles), relative length change,
    and status-code change — each kept as its own separate factor, never
    folded into the others. Returns (score, factors); factors carries the
    full Jaccard audit trail (shingle counts, intersection, union, the raw
    jaccard/dissimilarity, and the body-only anomaly score = 100 ×
    dissimilarity) alongside the blended per-probe score, so the objective
    body-dissimilarity measurement is always independently inspectable and
    never mutated by the other components.
    """
    signal = 1.0 if signal_matched else 0.0
    dissim = 0.0
    length = 0.0
    status = 0.0
    jaccard_audit: dict = {
        "metric": ANOMALY_METRIC, "shingle_size": SHINGLE_SIZE,
        "baseline_shingle_count": 0, "fuzz_shingle_count": 0,
        "intersection": 0, "union": 0, "jaccard": 1.0,
        "body_dissimilarity": 0.0, "body_anomaly_score": 0,
    }
    if baseline is not None and fuzz is not None:
        detail = jaccard_detail(baseline.shingles, fuzz.shingles)
        dissim = detail["body_dissimilarity"]
        jaccard_audit.update(detail)
        jaccard_audit["metric"] = ANOMALY_METRIC
        jaccard_audit["shingle_size"] = SHINGLE_SIZE
        jaccard_audit["body_anomaly_score"] = round(100 * dissim)
        b_len = baseline.length or 0
        f_len = fuzz.length or 0
        denom = max(b_len, f_len, 1)
        length = min(1.0, abs(b_len - f_len) / denom * 2.0)  # 50% change -> 1.0
        if baseline.status_code != fuzz.status_code:
            status = 0.6
            if (fuzz.status_code or 0) >= 500 and (baseline.status_code or 0) < 500:
                status = 1.0
    score = _clamp01(
        _W_SIGNAL * signal + _W_DISSIM * dissim + _W_LENGTH * length + _W_STATUS * status
    )
    factors = {
        "signal": round(signal, 3),
        "dissimilarity": round(dissim, 3),
        "length_delta": round(length, 3),
        "status_change": round(status, 3),
        "status_changed": bool(
            baseline is not None and fuzz is not None
            and baseline.status_code != fuzz.status_code
        ),
        "redirect_changed": bool(
            baseline is not None and fuzz is not None
            and baseline.redirected != fuzz.redirected
        ),
        # Full Jaccard audit trail — independent of, and never adjusted by,
        # the signal/length/status components above. body_anomaly_score is
        # exactly 100 * body_dissimilarity; nothing else feeds into it.
        "jaccard_audit": jaccard_audit,
    }
    return score, factors


def status_anomaly(status: str, confidence: str = "", severity: str = "") -> float:
    """Outcome-derived anomaly when no measured response diff exists."""
    base = _STATUS_ANOMALY.get(status, 0.0)
    if status in (TestStatus.VULNERABLE, TestStatus.HARDENING):
        severity_mult = _SEVERITY_MULT.get(severity, 1.0) if severity else 1.0
        return _clamp01(base * _CONFIDENCE_MULT.get(confidence, 0.9) * severity_mult)
    return base


def _exec_anomaly(execution) -> float | None:
    """Per-execution anomaly, or None if this execution is not scorable."""
    if execution.status not in _SCORABLE:
        return None
    measured = getattr(execution, "anomaly", 0.0) or 0.0
    if measured > 0.0:
        return _clamp01(measured)
    finding = getattr(execution, "finding", None)
    severity = getattr(finding, "severity", "") if finding is not None else ""
    return status_anomaly(execution.status, execution.confidence, severity)


def _level(score_0_100: float) -> str:
    if score_0_100 >= 70:
        return "critical"
    if score_0_100 >= 45:
        return "high"
    if score_0_100 >= 25:
        return "medium"
    if score_0_100 >= 10:
        return "low"
    return "minimal"


def _domain_entry(attack: str, execs: list) -> dict:
    scores: list[float] = []
    measured_count = 0
    for e in execs:
        a = _exec_anomaly(e)
        if a is None:
            continue
        scores.append(a)
        if getattr(e, "anomaly", 0.0) and e.anomaly > 0.0:
            measured_count += 1

    display = C.DISPLAY_NAME.get(attack, attack)
    if not scores:
        # Nothing comparable ran for this domain — report honestly, no score.
        return {
            "attack": attack,
            "display": display,
            "score": None,
            "level": "not_tested",
            "max": 0.0,
            "mean": 0.0,
            "tested": 0,
            "anomalous": 0,
            "measured": measured_count,
            "vulnerable": sum(1 for e in execs if e.status == TestStatus.VULNERABLE),
        }

    mx = max(scores)
    mean = sum(scores) / len(scores)
    score = round(100 * (_W_MAX_PROBE * mx + _W_MEAN_PROBE * mean))
    return {
        "attack": attack,
        "display": display,
        "score": score,
        "level": _level(score),
        "max": round(mx, 3),
        "mean": round(mean, 3),
        "tested": len(scores),
        "anomalous": sum(1 for s in scores if s >= _ANOMALOUS_THRESHOLD),
        "measured": measured_count,
        "vulnerable": sum(1 for e in execs if e.status == TestStatus.VULNERABLE),
    }


def compute_anomaly(executions: list) -> dict:
    """Per-domain and overall anomaly scores for a scan's executions.

    Returns ``{"overall": {...}, "domains": {attack: {...}}}``. Domains with no
    scorable execution carry ``score=None`` (``level="not_tested"``) and are
    excluded from the overall computation.
    """
    by_attack: dict[str, list] = {}
    for e in executions:
        by_attack.setdefault(e.attack, []).append(e)

    domains: dict[str, dict] = {}
    # Preserve the catalogue's canonical ordering, then any extras.
    ordered = [a for a in C.ALL_ATTACKS if a in by_attack]
    ordered += [a for a in by_attack if a not in C.ALL_ATTACKS]
    for attack in ordered:
        domains[attack] = _domain_entry(attack, by_attack[attack])

    scored = [d for d in domains.values() if d["score"] is not None]
    if scored:
        fractions = [d["score"] / 100 for d in scored]
        mx = max(fractions)
        mean = sum(fractions) / len(fractions)
        overall_score = round(100 * (_W_MAX_DOMAIN * mx + _W_MEAN_DOMAIN * mean))
        top = max(scored, key=lambda d: d["score"])
        overall = {
            "score": overall_score,
            "level": _level(overall_score),
            "domains_tested": len(scored),
            "domains_total": len(domains),
            "domains_anomalous": sum(1 for d in scored if d["score"] >= 45),
            "top_domain": top["attack"],
            "top_domain_display": top["display"],
            "top_domain_score": top["score"],
        }
    else:
        overall = {
            "score": 0,
            "level": "not_tested",
            "domains_tested": 0,
            "domains_total": len(domains),
            "domains_anomalous": 0,
            "top_domain": "",
            "top_domain_display": "",
            "top_domain_score": 0,
        }

    return {
        "overall": overall,
        "domains": domains,
        # Documents the objective metric backing every measured (non
        # outcome-derived) score above, so the scan's anomaly numbers are
        # auditable against the exact formula that produced them.
        "metric_metadata": {"metric": ANOMALY_METRIC, "shingle_size": SHINGLE_SIZE},
    }
