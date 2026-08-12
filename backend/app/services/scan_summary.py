"""
Unified ScanSummary.

Aggregates every scanner module's output into one compact, structured payload.
This is the single object handed to the Groq analyst — never raw HTML, never
per-request noise, only summarized evidence. It is also the natural place to
guarantee the numbers shown to the user match what the LLM analyzed.
"""
from __future__ import annotations


def _finding_type(category: str, title: str) -> str:
    """A stable machine type for a finding, derived from its category."""
    mapping = {
        "security_headers": "missing_security_headers",
        "information_exposure": "information_exposure",
        "configuration": "configuration",
        "input_validation": "input_validation",
    }
    return mapping.get(category, category or "finding")


def _evidence_strength(f) -> str:
    """How well-supported this finding is, in words the analyst is told to
    respect: "demonstrated" > "observed" > "reported"."""
    if f.category == "dependency_vulnerability":
        return "reported"  # a published advisory, not an observation here
    if f.category == "code_security":
        return "observed"  # a pattern matched in source
    if f.confidence == "confirmed" and (f.request_summary or f.response_summary):
        return "demonstrated"
    return "observed"


def build_scan_summary(scope, fast, deep) -> dict:
    """Assemble the aggregated summary from the scope, fast-scan, and
    deep-scan results."""
    stats = {
        "urls": len(deep.endpoints),
        "apis": sum(
            1 for e in deep.endpoints if e.discovery_method == "api_discovery"
        ),
        "parameters": len(deep.params),
        "subdomains": len(deep.subdomains),
        "requests": deep.requests_made,
    }

    initial_assessment = {
        "http_available": fast.http_available,
        "https_available": fast.https_available,
        "redirect_issues": fast.redirect_issues,
        "technology": fast.technology,
        "security_headers": fast.security_headers,
    }

    findings = []
    for f in deep.findings:
        entry = {
            "type": _finding_type(f.category, f.title),
            "title": f.title,
            "category": f.category,
            "scanner_severity": f.severity,
            "scanner_confidence": f.confidence,
            # Whether the scanner actually demonstrated an attack, or only
            # observed a pattern/advisory. The analyst must not upgrade the
            # latter into the former.
            "evidence_strength": _evidence_strength(f),
            "affected_urls": f.affected_urls,
            "sample_urls": f.affected_url_samples[:5],
            "parameter": f.parameter,
            # Summarized evidence only — never full response bodies.
            "evidence": (f.evidence or "")[:600],
            "response_summary": (f.response_summary or "")[:300],
        }
        if f.exploitability:
            entry["exploitability"] = f.exploitability
        if f.dependency:
            entry["dependency"] = f.dependency
        findings.append(entry)

    discovery = {
        "vhosts": [
            {"hostname": v.hostname, "status": v.status_code}
            for v in getattr(deep, "vhosts", [])
        ],
        "subdomains": [s.hostname for s in deep.subdomains][:20],
    }

    summary = {
        "target": scope.hostname,
        "statistics": stats,
        "initial_assessment": initial_assessment,
        "discovery": discovery,
        "findings": findings,
    }
    
    if hasattr(deep, "repo_info") and deep.repo_info:
        summary["repository"] = deep.repo_info
        
    from app.services.secret_redactor import redact_secrets_from_summary
    return redact_secrets_from_summary(summary)
