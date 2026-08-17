"""
Post-scan analysis.

This layer turns the raw deterministic scan output into a concise summary,
recommendation, and structured risk-factor payload. If a Groq-compatible
analysis endpoint is configured, it is used for the final write-up; otherwise
the backend falls back to a deterministic local summary so the product still
has a useful analysis stage on small deployments.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import json
from typing import Any

import httpx

from app.config import settings
from app.models.finding import Finding
from app.models.scan import Scan
from app.services.secret_redactor import redact_secrets_from_summary


@dataclass
class ScanAnalysisResult:
    ai_analyzed: bool = False
    ai_error: str = ""
    ai_summary: str = ""
    ai_recommendation: str = ""
    risk_factors: dict[str, Any] = field(default_factory=dict)


def _findings_payload(findings: list[Finding]) -> list[dict[str, Any]]:
    payload: list[dict[str, Any]] = []
    for finding in findings[:20]:
        payload.append(
            {
                "title": finding.title,
                "category": finding.category,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "url": finding.url,
                "parameter": finding.parameter,
                "risk_score": finding.risk_score,
                "description": finding.description,
                "impact": finding.impact,
                "remediation": finding.remediation,
                "evidence": finding.evidence,
                "request_summary": finding.request_summary,
                "response_summary": finding.response_summary,
            }
        )
    return payload


def _analysis_context(scan: Scan, findings: list[Finding], report: dict | None) -> dict[str, Any]:
    confirmed = [f for f in findings if f.confidence in {"confirmed", "potential"}]
    low_confidence = [f for f in findings if f.confidence in {"uncertain", "false_positive"}]
    return {
        "scan": {
            "target": scan.target.base_url if scan.target else "",
            "status": scan.status,
            "overall_risk": scan.overall_risk,
            "risk_level": scan.final_risk,
            "assessment_confidence": scan.assessment_confidence,
            "assessment_coverage": scan.assessment_coverage,
            "assessment_warning": scan.assessment_warning,
            "urls_discovered": scan.urls_discovered,
            "apis_discovered": scan.apis_discovered,
            "parameters_discovered": scan.parameters_discovered,
            "subdomains_discovered": scan.subdomains_discovered,
            "findings_count": scan.findings_count,
            "requests_made": scan.requests_made,
        },
        "report": report or {},
        "findings": _findings_payload(findings),
        "counts": {
            "confirmed": len(confirmed),
            "low_confidence": len(low_confidence),
            "total": len(findings),
        },
    }


def _local_analysis(scan: Scan, findings: list[Finding], report: dict | None) -> ScanAnalysisResult:
    confirmed = [f for f in findings if f.confidence in {"confirmed", "potential"}]
    low_confidence = [f for f in findings if f.confidence in {"uncertain", "false_positive"}]
    top_findings = sorted(findings, key=lambda f: f.risk_score, reverse=True)[:3]
    top_labels = [f"{f.title} ({f.severity}, {f.confidence})" for f in top_findings]
    fp_candidates = [
        {
            "title": f.title,
            "reason": "Low-confidence signal that should be reviewed manually.",
            "confidence": f.confidence,
        }
        for f in top_findings
        if f.confidence in {"uncertain", "false_positive"}
    ]

    summary_bits = [
        f"Detected {len(confirmed)} confirmed/potential finding(s) and {len(low_confidence)} low-confidence signal(s).",
        f"Overall risk is {scan.final_risk or 'minimal'} ({scan.overall_risk}/100) with {scan.assessment_confidence or 'unknown'} confidence.",
    ]
    if scan.assessment_warning:
        summary_bits.append(scan.assessment_warning)
    if scan.apis_discovered:
        summary_bits.append(
            f"Parsed {scan.apis_discovered} API endpoint(s) from the target's surfaced backend surface."
        )
    elif scan.urls_discovered:
        summary_bits.append(
            "Backend/API discovery was shallow on this run, so the analysis should be treated as partial."
        )

    recommendation_bits = [
        "Verify the top findings manually in the deployed environment before treating them as final.",
    ]
    if low_confidence:
        recommendation_bits.append(
            "Review the low-confidence signals first; they are the most likely places for false positives."
        )
    if scan.assessment_coverage and scan.assessment_coverage < 80:
        recommendation_bits.append(
            "Increase crawl depth or authenticate the scan to improve backend coverage."
        )
    if report and report.get("remediation", {}).get("fixed_since_last_scan"):
        recommendation_bits.append(
            "Some issues appear fixed relative to the previous scan, so compare before reopening them."
        )

    risk_factors = {
        "confirmed_findings": len(confirmed),
        "low_confidence_findings": len(low_confidence),
        "top_findings": top_labels,
        "false_positive_candidates": fp_candidates,
        "backend_observations": [
            f"{scan.urls_discovered} URLs discovered",
            f"{scan.apis_discovered} APIs discovered",
            f"{scan.parameters_discovered} parameters discovered",
        ],
    }
    return ScanAnalysisResult(
        ai_analyzed=True,
        ai_summary=" ".join(summary_bits),
        ai_recommendation=" ".join(recommendation_bits),
        risk_factors=risk_factors,
    )


def _parse_json_payload(text: str) -> dict[str, Any]:
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`").strip()
        if text.lower().startswith("json"):
            text = text[4:].strip()
    return json.loads(text)


async def analyze_scan(
    scan: Scan,
    findings: list[Finding],
    report: dict | None = None,
) -> ScanAnalysisResult:
    """Produce an analysis payload for a completed scan."""
    base = _local_analysis(scan, findings, report)
    if not settings.GROQ_API_KEY:
        return base

    payload = redact_secrets_from_summary(_analysis_context(scan, findings, report))
    system_prompt = (
        "You are Perry's post-scan analyst. Summarize the scan for a security "
        "engineer. Be concrete, avoid hype, and only call something a likely "
        "false positive when the evidence supports that conclusion. Return a "
        "single JSON object with keys: summary, recommendation, risk_factors. "
        "risk_factors should be an object with confirmed_findings, "
        "low_confidence_findings, top_findings, false_positive_candidates, and "
        "backend_observations."
    )

    body = {
        "model": settings.GROQ_MODEL,
        "temperature": 0.2,
        "max_tokens": 900,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(payload, indent=2, default=str)},
        ],
    }
    headers = {
        "Authorization": f"Bearer {settings.GROQ_API_KEY}",
        "Content-Type": "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=settings.GROQ_TIMEOUT_SECONDS) as client:
            response = await client.post(
                f"{settings.GROQ_BASE_URL.rstrip('/')}/chat/completions",
                headers=headers,
                json=body,
            )
            response.raise_for_status()
    except Exception:
        # Keep the deterministic fallback rather than failing the scan.
        return base

    try:
        document = response.json()
        content = document["choices"][0]["message"]["content"]
        parsed = _parse_json_payload(content)
    except Exception:
        return ScanAnalysisResult(
            ai_analyzed=True,
            ai_error="Groq returned an unreadable analysis payload.",
            ai_summary=base.ai_summary,
            ai_recommendation=base.ai_recommendation,
            risk_factors=base.risk_factors,
        )

    summary = str(parsed.get("summary") or base.ai_summary).strip()
    recommendation = str(parsed.get("recommendation") or base.ai_recommendation).strip()
    risk_factors = parsed.get("risk_factors")
    if not isinstance(risk_factors, dict):
        risk_factors = base.risk_factors
    return ScanAnalysisResult(
        ai_analyzed=True,
        ai_summary=summary or base.ai_summary,
        ai_recommendation=recommendation or base.ai_recommendation,
        risk_factors=risk_factors,
    )
