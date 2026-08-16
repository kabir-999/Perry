"""
Deterministic per-finding risk scoring.

    Risk Score = 0.35*TypeSeverity + 0.20*Confidence + 0.20*Exposure
               + 0.15*BlastRadius + 0.10*AssetSeverity

Each factor is normalised to 0-1 before weighting, so the weights (which sum
to 1.0) translate directly into a 0-100 score:

  - TypeSeverity  — the finding's own severity band (critical..info).
  - Confidence    — how sure Perry is this is real (confirmed..false_positive),
                    reusing the same confidence vocabulary as the rest of the
                    pipeline (severity_policy.py, risk_model/__init__.py).
  - Exposure      — how many URLs/locations this same issue affects, reusing
                    risk_model's own exposure tiers (hardening_model.json) so
                    "3 affected pages" means the same thing everywhere.
  - BlastRadius   — how far the damage could spread if exploited. Not a
                    literal input field anywhere upstream, so it's inferred:
                    dependency findings use the existing reachability ladder
                    (reachability.py) — is the vulnerable code path actually
                    reachable from attacker input, or just present in a
                    manifest? Everything else uses a per-category estimate
                    (injection/RCE-shaped findings spread further than a
                    missing header).
  - AssetSeverity — how sensitive the thing being tested is. Inferred from
                    whether the URL/parameter looks like a sensitive
                    endpoint (security_checks._SENSITIVE_API_RE — the same
                    pattern the API-security check already uses) or,
                    lacking a URL, from the finding's category.

This score is per-finding, used for report display and sort-ordering — it
is independent of (and does not feed) the authoritative aggregate score in
risk_model.calculate_Perry_risk, which scores real CVSS vectors and a
documented hardening scale rather than a general-purpose weighted formula;
mixing the two would blur "this finding's estimated risk" with "this scan's
CVSS-backed score." Runs before and independently of the LLM — the LLM
refines, it does not originate, risk.
"""
from __future__ import annotations

from app.services.finding_types import FindingCandidate

# ---------------------------------------------------------------------- 1/5
# Type Severity — the finding's own severity band, 0-1.
_SEVERITY_WEIGHT = {
    "critical": 1.0,
    "high": 0.75,
    "medium": 0.5,
    "low": 0.25,
    "info": 0.1,
}

# ---------------------------------------------------------------------- 2/5
# Confidence — same four-state vocabulary as severity_policy.py /
# risk_model/__init__.py's confidence_of, already 0-1 scaled. An unrecognized
# value is treated as the lowest non-zero tier, never a mid-value default —
# consistent with the fix already applied to risk_model.confidence_of.
_CONFIDENCE_FACTOR = {
    "confirmed": 1.0,
    "potential": 0.8,
    "uncertain": 0.55,
    "false_positive": 0.1,
}
_UNKNOWN_CONFIDENCE_DEFAULT = _CONFIDENCE_FACTOR["uncertain"]

# ---------------------------------------------------------------------- 4/5
# Blast Radius per category — how far exploitation could spread. Dependency
# findings don't use this table at all; they use the reachability ladder
# below instead, since that's a real, evidence-backed signal rather than a
# category guess.
_BLAST_RADIUS_BY_CATEGORY = {
    "code_security": 0.9,        # arbitrary code exec / injection can pivot
    "input_validation": 0.9,
    "information_exposure": 0.85,  # a leaked secret can compromise the whole app
    "source_correlation": 0.85,
    "authentication": 0.8,
    "authorization": 0.8,
    "attack_surface": 0.3,       # exposure of a fact, not a foothold
    "security_headers": 0.2,
    "configuration": 0.2,
    "custom_test": 0.5,
}
_DEFAULT_BLAST_RADIUS = 0.4

# Dependency findings: blast radius from the *reachability* classification
# (reachability.py) rather than a category guess — a dependency that's
# merely declared spreads nowhere; one with a confirmed, attacker-reachable
# call site can compromise the whole request.
_DEPENDENCY_BLAST_RADIUS = {
    "dependency_present": 0.1,
    "functionality_used": 0.3,
    "reachable_from_input": 0.6,
    "potentially_exploitable": 0.8,
    "confirmed_exploitable": 1.0,
}

# ---------------------------------------------------------------------- 5/5
# Asset Severity fallback per category, used only when the finding has no
# URL/parameter to check against the sensitive-endpoint pattern (e.g. a
# source-code or dependency finding, which concerns the whole application
# rather than one page).
_ASSET_SEVERITY_BY_CATEGORY = {
    "authentication": 0.8,
    "authorization": 0.8,
    "code_security": 0.7,
    "dependency_vulnerability": 0.7,
    "information_exposure": 0.7,
    "attack_surface": 0.3,
}
_DEFAULT_ASSET_SEVERITY = 0.4

# The five weights. Sum to 1.0 by construction — see test_risk_engine.py.
_WEIGHTS = {
    "type_severity": 0.35,
    "confidence": 0.20,
    "exposure": 0.20,
    "blast_radius": 0.15,
    "asset_severity": 0.10,
}


def _type_severity(finding: FindingCandidate) -> float:
    return _SEVERITY_WEIGHT.get(finding.severity, 0.2)


def _confidence(finding: FindingCandidate) -> float:
    return _CONFIDENCE_FACTOR.get(finding.confidence, _UNKNOWN_CONFIDENCE_DEFAULT)


def _exposure(finding: FindingCandidate) -> float:
    """0-1, reusing risk_model's own exposure tiers (1.0-1.3x) so "N affected
    URLs" means the same thing here as it does in the aggregate score."""
    from app.services.risk_model import exposure_multiplier

    multiplier = exposure_multiplier(getattr(finding, "affected_urls", 1))
    return max(0.0, min(1.0, (multiplier - 1.0) / 0.3))


def _blast_radius(finding: FindingCandidate) -> float:
    if finding.category == "dependency_vulnerability":
        classification = getattr(finding, "exploitability", "") or "dependency_present"
        return _DEPENDENCY_BLAST_RADIUS.get(classification, 0.2)
    return _BLAST_RADIUS_BY_CATEGORY.get(finding.category, _DEFAULT_BLAST_RADIUS)


def _asset_severity(finding: FindingCandidate) -> float:
    from app.services.security_checks import _SENSITIVE_API_RE

    target = f"{finding.url} {finding.parameter}"
    if target.strip() and _SENSITIVE_API_RE.search(target):
        return 1.0
    return _ASSET_SEVERITY_BY_CATEGORY.get(finding.category, _DEFAULT_ASSET_SEVERITY)


def risk_breakdown(finding: FindingCandidate) -> dict:
    """The five normalised (0-1) factors plus the weighted 0-100 total —
    exposed so a report can show *why* a finding scored the way it did,
    not just the final number."""
    factors = {
        "type_severity": _type_severity(finding),
        "confidence": _confidence(finding),
        "exposure": _exposure(finding),
        "blast_radius": _blast_radius(finding),
        "asset_severity": _asset_severity(finding),
    }
    total = sum(factors[k] * _WEIGHTS[k] for k in _WEIGHTS)
    return {
        "factors": factors,
        "weights": dict(_WEIGHTS),
        "score": round(total * 100, 1),
    }


def score_finding(finding: FindingCandidate) -> float:
    return risk_breakdown(finding)["score"]


def score_all(findings: list[FindingCandidate]) -> None:
    """Score findings in place."""
    for f in findings:
        f.risk_score = score_finding(f)


def level_for_score(score: int) -> str:
    """The one threshold ladder every per-finding/overall score is banded
    against — critical >=80, high >=60, medium >=40, low >=20, else minimal."""
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "minimal"


# A finding may set the overall application risk only when its evidence is
# confirmed or a real (potential) signal — never an uncertain guess or a
# false positive, and never a third-party observation.
_CONFIRMED_CONFIDENCES = {"confirmed", "potential"}


def overall_confirmed_risk(findings: list[FindingCandidate]) -> int:
    """Overall application risk = the highest confirmed/validated finding's
    own 5-factor score (§24/§30). Coverage never enters this number; a scan
    with no confirmed findings is 0. Deterministic."""
    scores = [
        score_finding(f)
        for f in findings
        if f.confidence in _CONFIRMED_CONFIDENCES
        and getattr(f, "contributes_to_risk", True)
    ]
    return int(round(max(scores))) if scores else 0
