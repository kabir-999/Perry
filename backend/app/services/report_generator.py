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


def build_report(scan: Scan, findings: list[Finding]) -> dict:
    by_severity: dict[str, list[dict]] = {s: [] for s in SEVERITY_ORDER}
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
        }
        by_severity.setdefault(f.severity, []).append(entry)

    severity_counts = {s: len(items) for s, items in by_severity.items()}

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
    }


def render_report_json(report: dict) -> str:
    return json.dumps(report, indent=2, default=str)
