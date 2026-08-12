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


def _source_code_section(deep) -> dict:
    """Distinguish "analysed and found nothing" from "not analysed".

    Reporting "0 code issues" when no repository was ever cloned implies a
    clean bill of health that was never established.
    """
    repo = getattr(deep, "repo_info", None)
    if not repo or repo.get("status") != "completed":
        return {
            "available": False,
            "reason": (repo or {}).get("error")
            or "No repository was analyzed for this scan.",
        }
    return {
        "available": True,
        "files_analyzed": repo.get("files_analyzed", 0),
        "code_issues": repo.get("source_findings_count", 0),
        "dependency_issues": repo.get("dependency_findings_count", 0),
        "repository": f"{repo.get('owner')}/{repo.get('name')}",
    }


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
        if not getattr(f, "contributes_to_risk", True):
            continue
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
            "scope_status": getattr(f, "scope_status", ""),
            "origin": getattr(f, "origin", ""),
            "affected_url_samples": f.affected_url_samples[:5],
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

    # The strongest severity the deterministic scanner assigned. The analyst is
    # told not to exceed it, so the per-finding severities shown in the Risk
    # Factors panel cannot contradict the Findings and Security Tests panels.
    _rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    scanner_max = max(
        (f.severity for f in deep.findings
         if getattr(f, "contributes_to_risk", True)),
        key=lambda sev: _rank.get(sev, 0),
        default="minimal",
    )

    summary = {
        "target": scope.hostname,
        "scanner_max_severity": scanner_max,
        "statistics": stats,
        "initial_assessment": initial_assessment,
        "discovery": discovery,
        "findings": findings,
        # Structural risk, so the analyst sees how the score was derived.
        "graph": getattr(deep, "graph_summary", {}),
        "graph_risk": getattr(deep, "graph_risk", {}),
        # Reported separately and explicitly excluded from the target's risk.
        "third_party_observations": getattr(deep, "third_party_observations", []),
        # Source analysis is only "0 issues" when it actually ran.
        "source_code_analysis": _source_code_section(deep),
    }
    
    if hasattr(deep, "repo_info") and deep.repo_info:
        summary["repository"] = deep.repo_info
        
    from app.services.secret_redactor import redact_secrets_from_summary
    return redact_secrets_from_summary(summary)
