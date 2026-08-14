"""
Final report generation.

Produces a structured JSON summary of a completed scan (target, scope,
discovery counts, findings grouped by severity, overall risk). Persisted as a
``Report`` row with the JSON inline in ``file_path`` for now — no filesystem
artifacts, no PDF binary in this phase.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from app.models.finding import Finding
from app.models.scan import Scan
from app.services.finding_types import SEVERITY_ORDER


def _verification_status(
    fingerprint: str,
    *,
    prior_fingerprints: set[str] | None,
    prior_prior_fingerprints: set[str] | None,
) -> str:
    """Classify a current finding against the same target's scan history.

    Never inspects or modifies source code — this is purely a comparison of
    what was reported in earlier scans of this same target.
    """
    if prior_fingerprints is None:
        # No completed prior scan of this target exists at all — there is
        # nothing to compare against.
        return "UNVERIFIED"
    if fingerprint in prior_fingerprints:
        return "OPEN"
    if prior_prior_fingerprints and fingerprint in prior_prior_fingerprints:
        # Absent from the immediately preceding scan (i.e. it was FIXED),
        # but present again now.
        return "REGRESSED"
    return "OPEN"  # newly discovered this scan; nothing to regress from


def build_report(
    scan: Scan,
    findings: list[Finding],
    *,
    prior_fingerprints: set[str] | None = None,
    prior_prior_fingerprints: set[str] | None = None,
) -> dict:
    by_severity: dict[str, list[dict]] = {s: [] for s in SEVERITY_ORDER}
    current_fingerprints = {f.fingerprint for f in findings if f.fingerprint}
    for f in findings:
        entry = {
            "title": f.title,
            "category": f.category,
            "severity": f.severity,
            "confidence": f.confidence,
            "url": f.url,
            "parameter": f.parameter,
            "risk_score": f.risk_score,
            "remediation": f.remediation,
            "parameter_location": f.parameter_location,
            "auth_context": f.auth_context,
            "reproducibility": f.reproducibility,
            "verification_status": (
                _verification_status(
                    f.fingerprint,
                    prior_fingerprints=prior_fingerprints,
                    prior_prior_fingerprints=prior_prior_fingerprints,
                )
                if f.fingerprint else "UNVERIFIED"
            ),
        }
        by_severity.setdefault(f.severity, []).append(entry)

    severity_counts = {s: len(items) for s, items in by_severity.items()}

    # Findings that were present in the prior scan but aren't anymore —
    # reported separately since there's no "current" Finding row for them.
    fixed_count = (
        len(prior_fingerprints - current_fingerprints)
        if prior_fingerprints is not None else 0
    )

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan_id": str(scan.id),
        "target": scan.target.base_url if scan.target else "",
        # Deterministic 5-factor risk: overall = highest confirmed finding's
        # score. Coverage never modifies it — the three numbers are separate
        # so low coverage never masquerades as low risk.
        "risk_score": scan.overall_risk,
        "overall_risk": scan.overall_risk,
        "risk_level": scan.final_risk,
        "assessment_confidence": scan.assessment_confidence,
        "assessment_coverage": scan.assessment_coverage,
        "assessment_warning": scan.assessment_warning,
        "coverage": json.loads(scan.coverage_json or "{}"),
        "attack_coverage": json.loads(scan.attack_coverage_json or "{}"),
        "attack_matrix": json.loads(scan.attack_matrix_json or "[]"),
        "discovery": {
            "urls": scan.urls_discovered,
            "apis": scan.apis_discovered,
            "parameters": scan.parameters_discovered,
            "subdomains": scan.subdomains_discovered,
        },
        "requests_made": scan.requests_made,
        "severity_counts": severity_counts,
        "total_findings": len(findings),
        "findings_by_severity": by_severity,
        "remediation": {
            "has_prior_scan": prior_fingerprints is not None,
            "fixed_since_last_scan": fixed_count,
        },
    }


def render_report_json(report: dict) -> str:
    return json.dumps(report, indent=2, default=str)
