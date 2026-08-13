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


def _ai_block(scan: Scan) -> dict:
    try:
        risk_data = json.loads(scan.risk_factors_json) if scan.risk_factors_json else {}
    except (ValueError, TypeError):
        risk_data = {}
    return {
        "analyzed": scan.ai_analyzed,
        "error": scan.ai_error,
        "summary": scan.ai_summary,
        "recommendation": scan.ai_recommendation,
        "risk_factors": risk_data.get("risk_factors", []),
        "statistics": risk_data.get("statistics", {}),
    }


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
            "llm_verdict": f.llm_verdict,
            "remediation": f.remediation,
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
        # One score for dashboard and report alike: the deterministic engine's.
        "risk_score": scan.risk_score,
        "sentinel_risk": json.loads(scan.sentinel_risk_json or "{}"),
        "risk_level": scan.final_risk if scan.ai_analyzed else None,
        "ai": _ai_block(scan),
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
