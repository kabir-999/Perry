"""
Stage 2 — Deep Scan orchestrator.

Runs in the background after the fast scan has already returned an initial
result. Coordinates discovery (crawler, directory, API, parameter, subdomain),
deterministic security checks, risk scoring, and the Groq analyst — running
independent stages concurrently where safe, all over one shared, budgeted,
bounded-concurrency client.

Progress is streamed out through the ``emit`` callback (persist + SSE); the
orchestrator never touches the DB or the broker directly.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from app.config import settings
from app.services import active_engine, security_checks
from app.services.api_discovery import discover_apis
from app.services.crawler import crawl
from app.services.directory_scanner import discover_directories
from app.services.discovery_types import DiscoveredParam, DiscoveredPath
from app.services.fast_scanner import FastScanResult
from app.services.finding_types import FindingCandidate
from app.services.http_client import Fetcher, build_async_client
from app.services.llm_security_analyst import (
    REASON_NOT_CONFIGURED,
    security_analyst,
)
from app.services.parameter_discovery import consolidate_parameters
from app.services.response_analyzer import analyze, learn_not_found_profile
from app.services.risk_engine import score_all
from app.services.severity_policy import apply_policy
from app.services.scan_summary import build_scan_summary
from app.services.scope import TargetScope
from app.services.security_test_cases import enabled_parameter_test_cases
from app.services.subdomain_scanner import DiscoveredSubdomain, discover_subdomains
from app.services.vhost_scanner import discover_vhosts
from app.services.reachability import (
    CLASSIFICATION_LABEL,
    CLASSIFICATION_MEANING,
    DEPENDENCY_PRESENT,
    FUNCTIONALITY_USED,
    POTENTIALLY_EXPLOITABLE,
    REACHABLE_FROM_INPUT,
)
from app.services.js_analyzer import analyze_bundles
from app.services.repo_discovery import discover_repository, parse_repo_url, RepoCandidate
from app.services.repo_analyzer import analyze_repository, RepoAnalysisResult
from app.services.repo_correlator import correlate

EmitFn = Callable[[dict], Awaitable[None]]
CancelFn = Callable[[], bool]

# Groups shown in the live "Security Checks" panel.
CHECK_GROUPS = ["Headers", "Information Exposure", "Configuration", "Input Validation"]

# Cap active injection probing to keep requests bounded (and latency low).
_MAX_PARAMS_PROBED = 10


@dataclass
class DeepScanResult:
    endpoints: list[DiscoveredPath] = field(default_factory=list)
    params: list[DiscoveredParam] = field(default_factory=list)
    subdomains: list[DiscoveredSubdomain] = field(default_factory=list)
    vhosts: list = field(default_factory=list)
    findings: list[FindingCandidate] = field(default_factory=list)
    test_results: list[dict] = field(default_factory=list)
    requests_made: int = 0
    repo_info: dict | None = None
    source_findings: list[FindingCandidate] = field(default_factory=list)
    raw_repo_analysis: RepoAnalysisResult | None = None
    # AI assessment (authoritative risk comes only from here).
    ai_analyzed: bool = False
    ai_error: str = ""
    final_risk: str = ""  # risk_level from Groq; empty when unavailable
    risk_score: int = 0  # 0-100 from Groq; 0 when unavailable
    ai_summary: str = ""
    ai_recommendation: str = ""
    risk_factors: list[dict] = field(default_factory=list)
    statistics: dict = field(default_factory=dict)


class _Cancelled(Exception):
    pass


async def run_deep_scan(
    scope: TargetScope,
    fast_result: FastScanResult,
    *,
    emit: EmitFn,
    is_cancelled: CancelFn,
    repo_url: str = "",
    passive_only: bool = False,
    include_repo: bool = True,
) -> DeepScanResult:
    client = build_async_client(
        timeout=settings.DEEP_REQUEST_TIMEOUT_SECONDS,
        connect_timeout=settings.FAST_CONNECT_TIMEOUT_SECONDS,
        max_connections=settings.HTTP_MAX_CONNECTIONS,
        max_keepalive=settings.HTTP_MAX_KEEPALIVE,
    )
    fetcher = Fetcher(
        client,
        concurrency=settings.DEEP_CONCURRENCY,
        request_budget=settings.DEEP_MAX_REQUESTS,
        max_response_bytes=settings.DEFAULT_MAX_RESPONSE_BYTES,
    )
    result = DeepScanResult()
    checks_done: list[str] = []

    async def check():
        if is_cancelled():
            raise _Cancelled()

    try:
        # --- Discovery: crawl + subdomains + not-found profile concurrently ---
        await emit({"deep_progress": 5})
        await check()

        not_found = await learn_not_found_profile(fetcher, scope.origin)

        # --- Discovery phase 1 (concurrent): crawl + subdomains + directory ---
        # Directory discovery doesn't depend on the crawl, so it overlaps it.
        crawl_result, subdomains, (dir_paths, dir_findings) = await asyncio.gather(
            crawl(
                fetcher,
                scope,
                seed_url=fast_result.homepage_url or scope.origin,
                seed_html=fast_result.homepage_text or None,
                max_pages=settings.CRAWL_MAX_PAGES,
                max_depth=settings.CRAWL_MAX_DEPTH,
            ),
            discover_subdomains(scope),
            discover_directories(fetcher, scope, not_found),
        )
        result.subdomains = subdomains
        result.findings.extend(dir_findings)

        await emit(
            {
                "deep_progress": 40,
                "urls_discovered": len(crawl_result.pages),
                "subdomains_discovered": len(subdomains),
            }
        )
        await check()

        # --- Discovery phase 2 + active fuzzing + repo analysis (all concurrent) ---
        # API discovery (needs crawl links), VHost (uses subdomains), and the
        # active parameter probes (use crawl params) all run together so their
        # network waits overlap.
        crawl_params = consolidate_parameters(crawl_result.params)
        
        async def repo_pipeline():
            # Source analysis is the developer-only half of the pipeline.
            if not include_repo:
                return None
            # An explicitly supplied repo wins: developers testing their own
            # site usually don't link the repo from the page at all.
            repo_candidate = parse_repo_url(repo_url)
            if repo_candidate is None:
                repo_candidate = await discover_repository(fetcher, scope, crawl_result)
            if not repo_candidate:
                return None
            await emit({"repo_status": f"Found repo: {repo_candidate.owner}/{repo_candidate.name}, analyzing..."})
            analysis = await analyze_repository(repo_candidate, scope)
            return analysis

        (api_paths, api_params), vhosts, active, repo_analysis, js = await asyncio.gather(
            discover_apis(fetcher, scope, not_found, crawl_result.internal_links),
            discover_vhosts(
                fetcher,
                scope,
                extra_hosts=[s.hostname for s in subdomains],
                not_found=not_found,
            ),
            _run_active(fetcher, crawl_params, passive_only),
            repo_pipeline(),
            analyze_bundles(fetcher, scope, crawl_result.script_urls, not_found),
        )

        result.vhosts = vhosts
        result.findings.extend(active)
        # Endpoints mined from the JS bundles (each already probed and
        # confirmed against the not-found profile) plus any exposed source map.
        result.findings.extend(js.findings)
        # File-upload endpoints (detection) + VHost isolation assessment.
        result.findings.extend(_upload_findings(crawl_result.upload_endpoints))
        result.findings.extend(_vhost_findings(vhosts))

        # Merge discovered endpoints (crawler pages + dir hits + api + bundles).
        endpoints: dict[str, DiscoveredPath] = {}
        for path in crawl_result.pages + dir_paths + api_paths + js.endpoints:
            endpoints.setdefault(path.key(), path)
        result.endpoints = list(endpoints.values())
        result.params = consolidate_parameters(crawl_result.params, api_params)

        await emit(
            {
                "deep_progress": 70,
                "urls_discovered": len(result.endpoints),
                "apis_discovered": len(api_paths),
                "parameters_discovered": len(result.params),
                "findings_count": len(result.findings),
            }
        )
        await check()

        # --- Remaining security checks ---
        # Passive checks over crawled pages (cache hits: no new requests).
        passive = await _passive_over_pages(fetcher, crawl_result.pages)
        result.findings.extend(passive)

        # Safe, read-only API security checks over discovered API endpoints.
        api_urls = [
            e.url for e in result.endpoints
            if e.discovery_method in ("api_discovery", "js_bundle")
        ]
        if api_urls:
            result.findings.extend(
                await security_checks.check_api_security(fetcher, api_urls)
            )
            
        if repo_analysis:
            result.repo_info = {
                "provider": repo_analysis.repo.provider,
                "owner": repo_analysis.repo.owner,
                "name": repo_analysis.repo.name,
                "url": repo_analysis.repo.url,
                "confidence": repo_analysis.repo.confidence,
                "discovery_source": repo_analysis.repo.discovery_source,
                "verified": repo_analysis.repo.verified,
                "status": repo_analysis.status,
                "error": repo_analysis.error,
                "files_analyzed": repo_analysis.files_analyzed,
                "source_findings_count": len(repo_analysis.secret_findings) + len(repo_analysis.code_findings),
                "dependency_findings_count": len(repo_analysis.dependency_findings)
            }
            result.raw_repo_analysis = repo_analysis
            # Convert and merge repo findings
            sf = _convert_repo_findings(repo_analysis)
            result.source_findings.extend(sf)
            result.findings.extend(sf)
            
            # Correlation
            correlated = correlate(result.findings, result.endpoints, repo_analysis.secret_findings + repo_analysis.code_findings)
            result.findings.extend(correlated)
            
        checks_done += [
            "Headers", "Information Exposure", "Configuration",
            "API Checks", "Input Validation",
        ]
        await emit(
            {
                "deep_progress": 85,
                "security_checks_completed": len(result.endpoints),
                "findings_count": len(result.findings),
                "checks_done": list(checks_done),
            }
        )
        await check()

        # --- Aggregate + dedup (factual evidence only; no risk scoring here) ---
        result.findings = _dedup_findings(result.findings)
        # Normalise severity and wording against the evidence actually held,
        # before anything scores or summarizes these findings.
        apply_policy(result.findings)
        # Per-finding scores are used only for internal ordering, never as the
        # authoritative risk — that comes solely from the AI analyst.
        score_all(result.findings)
        result.requests_made = fetcher.requests_made

        # Full test matrix: every test that ran and its outcome (pass or a
        # finding of some severity), plus tests that weren't applicable.
        active_ran = not passive_only and any(
            p.param_type == "query" and p.method == "GET" for p in result.params
        )
        result.test_results = build_test_results(
            result.findings,
            active_ran=active_ran,
            api_ran=bool(api_urls),
            fast_result=fast_result,
            passive_only=passive_only,
        )

        await emit(
            {
                "deep_progress": 90,
                "findings_count": len(result.findings),
                "checks_done": list(checks_done),
            }
        )
        await check()

        # --- AI Security Analyst: ONE Groq call on the aggregated summary ---
        summary = build_scan_summary(scope, fast_result, result)
        if security_analyst.enabled:
            await emit(
                {"status": "ai_analysis", "ai_status": "Analyzing findings with AI…"}
            )
            assessment, reason = await security_analyst.analyze(summary)
            if assessment is not None:
                result.ai_analyzed = True
                result.risk_score = assessment.risk_score
                result.final_risk = assessment.risk_level
                result.ai_summary = assessment.summary
                result.ai_recommendation = assessment.overall_recommendation
                result.risk_factors = [rf.model_dump() for rf in assessment.risk_factors]
                result.statistics = assessment.statistics.model_dump()
                await emit(
                    {
                        "status": "ai_analysis",
                        "ai_status": "AI analysis complete.",
                        "final_risk": result.final_risk,
                        "risk_score": result.risk_score,
                        "ai_summary": result.ai_summary,
                        "ai_recommendation": result.ai_recommendation,
                    }
                )
            else:
                # No fabricated score — the assessment is explicitly unavailable.
                result.ai_analyzed = False
                result.ai_error = reason
                await emit({"ai_status": reason})
        else:
            result.ai_analyzed = False
            result.ai_error = REASON_NOT_CONFIGURED
            await emit({"ai_status": REASON_NOT_CONFIGURED})

        await emit({"deep_progress": 100})
        return result

    except _Cancelled:
        result.requests_made = fetcher.requests_made
        raise
    finally:
        await client.aclose()


async def _passive_over_pages(
    fetcher: Fetcher, pages: list[DiscoveredPath]
) -> list[FindingCandidate]:
    findings: list[FindingCandidate] = []
    # Re-fetch is a cache hit; fetch_many keeps concurrency bounded.
    results = await fetcher.fetch_many([p.url for p in pages])
    for res in results:
        if not res.ok:
            continue
        findings += security_checks.run_passive_checks(res, analyze(res))
    return findings


_SENSITIVE_VHOST_LABELS = (
    "admin", "dev", "staging", "stage", "test", "uat", "internal", "beta",
    "preprod", "qa", "backend", "private",
)


def _upload_findings(uploads) -> list[FindingCandidate]:
    from urllib.parse import urlsplit

    out: list[FindingCandidate] = []
    for up in uploads:
        path = urlsplit(up.url).path
        out.append(
            FindingCandidate(
                title="File upload endpoint detected",
                category="configuration",
                severity="low",
                confidence="potential",
                url=up.url,
                method=up.method,
                evidence="Form accepts file uploads (multipart/form-data or "
                "<input type=file>).",
                description="A file-upload endpoint was discovered. Uploads "
                "should be validated for type, size, and safe storage.",
                impact="",
                remediation="",
                dedup_key=f"file_upload|{path}",
            )
        )
    return out


def _vhost_findings(vhosts) -> list[FindingCandidate]:
    """Flag virtual hosts that both differ from the baseline AND carry a
    sensitive label (admin/dev/staging/…) — a possible isolation/exposure
    problem. Groq assigns the final severity."""
    out: list[FindingCandidate] = []
    for v in vhosts:
        label = v.hostname.split(".")[0].lower()
        if label in _SENSITIVE_VHOST_LABELS:
            out.append(
                FindingCandidate(
                    title=f"Virtual host exposes a '{label}' application",
                    category="configuration",
                    severity="medium",
                    confidence="potential",
                    url=v.hostname,
                    evidence=f"Host: {v.hostname} returns a different app "
                    f"(HTTP {v.status_code}, {v.content_length} bytes) than the "
                    "primary host.",
                    description="A different virtual application responds to a "
                    "sensitive Host header value, suggesting weak host "
                    "isolation or an exposed non-production app.",
                    impact="",
                    remediation="",
                    dedup_key=f"vhost|{v.hostname}",
                )
            )
    return out

def _convert_repo_findings(repo_analysis: RepoAnalysisResult) -> list[FindingCandidate]:
    out = []
    for sf in repo_analysis.secret_findings + repo_analysis.code_findings:
        out.append(
            FindingCandidate(
                title=f"Source Code: {sf.finding_type.replace('_', ' ').title()}",
                category="information_exposure" if "secret" in sf.finding_type else "code_security",
                severity=sf.severity,
                confidence=sf.confidence,
                url="",
                evidence=f"File: {sf.file}:{sf.line}\nContext: {sf.code_context}",
                response_summary="Source Code Analysis",
                description="A security vulnerability was found in the public repository associated with this site.",
                impact="Exploitable vulnerability or leaked secret in the source code.",
                remediation="Fix the vulnerable code or rotate the exposed secret.",
                dedup_key=f"repo_code|{sf.file}|{sf.line}|{sf.finding_type}",
            )
        )
    for df in repo_analysis.dependency_findings:
        out.append(_dependency_finding(df))
    return out


def _dependency_finding(df) -> FindingCandidate:
    """Turn one advisory into a finding whose wording matches the evidence.

    Severity comes from what we established about *this* codebase, not from
    the advisory's own rating: an advisory can be Critical while the affected
    function is never called here.
    """
    label = CLASSIFICATION_LABEL.get(df.classification, "Vulnerable Dependency Present")

    # Severity ladder. Only a call reachable from request data earns Medium+,
    # and the advisory's own severity caps it rather than setting it.
    if df.classification == POTENTIALLY_EXPLOITABLE:
        severity = df.severity if df.severity in ("critical", "high", "medium") else "medium"
    elif df.classification == REACHABLE_FROM_INPUT:
        severity = "medium"
    elif df.classification == FUNCTIONALITY_USED:
        severity = "low"
    else:
        severity = "low"

    fixed = df.fixed_version or "no fixed version published"
    remediation = (
        f"Upgrade {df.package} from {df.version} to {fixed}."
        if df.fixed_version
        else f"No patched version is published for {df.package} {df.version}. "
        "Check the advisory for a workaround, or replace the dependency."
    )
    if not df.is_direct:
        remediation += (
            " This is a transitive dependency — update the parent package that "
            "requires it, or pin an override."
        )
    if df.is_development:
        remediation += (
            " It is a development dependency, so it should not be present in a "
            "production build at all."
        )

    evidence_lines = [
        f"Package: {df.package} {df.version} ({df.ecosystem})",
        f"Dependency type: {df.dependency_kind}",
        f"Advisory: {df.advisory_id or 'unknown'}",
        f"Vulnerable range: {df.affected_versions or 'unspecified'}",
        f"Patched version: {fixed}",
        f"Package imported: {'yes' if df.is_used else 'no'}",
        f"Vulnerable functionality named by advisory: "
        + (", ".join(df.vulnerable_symbols[:4]) if df.vulnerable_symbols else "not identified"),
        f"Vulnerable functionality used: {'yes' if df.functionality_used else 'no'}"
        + (f" ({', '.join(df.call_sites[:2])})" if df.call_sites else ""),
        f"Reachable from attacker-controlled input: "
        + (
            f"yes ({', '.join(df.tainted_call_sites[:2])})"
            if df.reachable_from_input
            else "no path found"
        ),
    ]

    impact = CLASSIFICATION_MEANING.get(df.classification, "")
    if df.classification in (DEPENDENCY_PRESENT, FUNCTIONALITY_USED):
        impact += (
            " Keeping it current is good hygiene, but on this evidence it is "
            "not an exploitable vulnerability in this application."
        )

    return FindingCandidate(
        title=f"{label}: {df.package} {df.version}",
        category="dependency_vulnerability",
        severity=severity,
        # Static analysis never confirms exploitability.
        confidence="potential",
        url="",
        evidence="\n".join(evidence_lines),
        response_summary="Software composition analysis (OSV) + reachability",
        description=(
            f"{df.package} {df.version} is affected by {df.advisory_id or 'a published advisory'}"
            + (f": {df.advisory_summary}" if df.advisory_summary else ".")
            + (f" {df.reachability_notes}" if df.reachability_notes else "")
        ),
        impact=impact,
        remediation=remediation,
        dedup_key=f"repo_dep|{df.package}|{df.advisory_id}",
        exploitability=df.classification,
        dependency={
            "package": df.package,
            "version": df.version,
            "ecosystem": df.ecosystem,
            "advisory_id": df.advisory_id,
            "vulnerable_range": df.affected_versions,
            "fixed_version": df.fixed_version,
            "dependency_kind": df.dependency_kind,
            "is_direct": df.is_direct,
            "is_development": df.is_development,
            "is_used": df.is_used,
            "functionality_used": df.functionality_used,
            "reachable_from_input": df.reachable_from_input,
            "vulnerable_symbols": df.vulnerable_symbols[:6],
            "symbols_found": df.symbols_found[:6],
            "call_sites": df.call_sites[:4],
            "tainted_call_sites": df.tainted_call_sites[:4],
            "classification": df.classification,
        },
    )
    if not df.is_direct:
        remediation += (
            " This is a transitive dependency — update the parent package that "
            "requires it, or pin an override."
        )

    evidence_lines = [
        f"Package: {df.package} {df.version} ({df.ecosystem}, {dependency_kind})",
        f"Advisory: {df.advisory_id or 'unknown'}",
        f"Vulnerable range: {df.affected_versions or 'unspecified'}",
        f"Patched version: {fixed}",
        f"Imported in analyzed source: {'yes' if df.is_used else 'no'}",
        f"Externally reachable path: {df.reachability_text}",
    ]
    if df.import_sites:
        evidence_lines.append(f"Import sites: {', '.join(df.import_sites[:3])}")

    return FindingCandidate(
        title=f"{label}: {df.package} {df.version}",
        category="dependency_vulnerability",
        severity=severity,
        # Static analysis never confirms exploitability.
        confidence="potential",
        url="",
        evidence="\n".join(evidence_lines),
        response_summary="Software composition analysis (OSV)",
        description=(
            f"{df.package} {df.version} is affected by {df.advisory_id or 'a published advisory'}"
            + (f": {df.advisory_summary}" if df.advisory_summary else ".")
        ),
        impact=impact,
        remediation=remediation,
        dedup_key=f"repo_dep|{df.package}|{df.advisory_id}",
        exploitability=df.classification,
        dependency={
            "package": df.package,
            "version": df.version,
            "ecosystem": df.ecosystem,
            "advisory_id": df.advisory_id,
            "vulnerable_range": df.affected_versions,
            "fixed_version": df.fixed_version,
            "is_direct": df.is_direct,
            "is_used": df.is_used,
            "externally_reachable": df.externally_reachable,
            "reachability": df.reachability_text,
            "classification": df.classification,
            "import_sites": df.import_sites[:5],
        },
    )


# Canonical catalogue of security tests the scanner performs, in display
# order. Each entry: (display name, always-runs?).
_TEST_CATALOG = [
    ("HTTPS / TLS", True),
    ("Security Headers", True),
    ("Cookie Security", True),
    ("CORS Policy", True),
    ("Version Disclosure", True),
    ("Directory Listing", True),
    ("Debug / Error Exposure", True),
    ("Sensitive Files", True),
    ("Reflected XSS", "active"),
    ("SQL Injection", "active"),
    ("Path Traversal", "active"),
    ("Command Injection", "active"),
    ("Open Redirect", "active"),
    ("HTTP Parameter Pollution", "active"),
    ("File Upload", True),
    ("VHost Assessment", True),
    ("API Security", "api"),
]


def _classify_finding(f: FindingCandidate) -> str:
    """Map a finding to the test that produced it, via its dedup key."""
    k = f.dedup_key
    if k.startswith("security_headers"):
        return "Security Headers"
    if k.startswith("version_disclosure"):
        return "Version Disclosure"
    if k.startswith("insecure_cookie"):
        return "Cookie Security"
    if k.startswith("cors"):
        return "CORS Policy"
    if k.startswith("dir_listing"):
        return "Directory Listing"
    if k.startswith("stack_trace"):
        return "Debug / Error Exposure"
    if k.startswith("sensitive_file"):
        return "Sensitive Files"
    if k.startswith("reflected_xss"):
        return "Reflected XSS"
    if k.startswith("sqli"):
        return "SQL Injection"
    if k.startswith("path_traversal"):
        return "Path Traversal"
    if k.startswith("cmd_injection"):
        return "Command Injection"
    if k.startswith("open_redirect"):
        return "Open Redirect"
    if k.startswith("hpp"):
        return "HTTP Parameter Pollution"
    if k.startswith("file_upload"):
        return "File Upload"
    if k.startswith("vhost"):
        return "VHost Assessment"
    if k.startswith("api_"):
        return "API Security"
    return "Other"


async def _run_active(fetcher, crawl_params, passive_only: bool):
    """Active injection probes send crafted payloads, so they run only for a
    user who has confirmed authorization for the target."""
    if passive_only:
        return []
    return await active_engine.run_active_tests(fetcher, crawl_params)


def build_test_results(
    findings: list[FindingCandidate],
    *,
    active_ran: bool,
    api_ran: bool,
    fast_result,
    passive_only: bool = False,
) -> list[dict]:
    """One row per security test: pass / a finding (with worst severity and
    count) / not-applicable. Gives a complete picture, not just the threats."""
    from app.services.finding_types import SEVERITY_RANK

    grouped: dict[str, list[FindingCandidate]] = {}
    for f in findings:
        grouped.setdefault(_classify_finding(f), []).append(f)

    https_check = next(
        (c for c in (fast_result.checks if fast_result else []) if c.label == "HTTPS"),
        None,
    )

    results: list[dict] = []
    for name, runs in _TEST_CATALOG:
        applicable = (
            runs is True
            or (runs == "active" and active_ran)
            or (runs == "api" and api_ran)
        )
        if not applicable:
            # An active test skipped for lack of authorization is reported as
            # such — the user should see it was not run, not assume it passed.
            if runs == "active" and passive_only:
                results.append(
                    {"name": name, "status": "not_authorized", "severity": "",
                     "count": 0,
                     "detail": "Not run — requires confirming you own this site."}
                )
            else:
                results.append(
                    {"name": name, "status": "not_applicable", "severity": "",
                     "count": 0, "detail": ""}
                )
            continue

        if name == "HTTPS / TLS":
            st = https_check.status if https_check else "info"
            passed = st == "pass"
            results.append(
                {
                    "name": name,
                    "status": "pass" if passed else "finding",
                    "severity": "" if passed else ("medium" if st == "fail" else "low"),
                    "count": 0 if passed else 1,
                    "detail": https_check.detail if https_check else "",
                }
            )
            continue

        fs = grouped.get(name, [])
        if fs:
            worst = min(fs, key=lambda x: SEVERITY_RANK.get(x.severity, 9)).severity
            results.append(
                {"name": name, "status": "finding", "severity": worst,
                 "count": len(fs), "detail": fs[0].title}
            )
        else:
            results.append(
                {"name": name, "status": "pass", "severity": "", "count": 0,
                 "detail": "No issues detected."}
            )
    return results


def _dedup_findings(findings: list[FindingCandidate]) -> list[FindingCandidate]:
    """Collapse duplicate findings, keeping the highest severity and recording
    how many locations each issue affects (so the UI can stay concise while
    remaining accurate)."""
    from app.services.finding_types import SEVERITY_RANK

    seen: dict[str, FindingCandidate] = {}
    samples: dict[str, list[str]] = {}
    count: dict[str, int] = {}
    for f in findings:
        key = f.key()
        if key not in seen:
            seen[key] = f
            samples[key] = [f.url] if f.url else []
            count[key] = 1
        else:
            count[key] += 1
            if f.url and f.url not in samples[key] and len(samples[key]) < 10:
                samples[key].append(f.url)
            # Keep the more severe representative.
            if SEVERITY_RANK.get(f.severity, 9) < SEVERITY_RANK.get(
                seen[key].severity, 9
            ):
                # preserve the accumulated url of the previous representative
                prev_url = seen[key].url
                seen[key] = f
                if prev_url and prev_url not in samples[key] and len(samples[key]) < 10:
                    samples[key].append(prev_url)

    for key, cand in seen.items():
        cand.affected_urls = count[key]
        cand.affected_url_samples = samples[key]
    return list(seen.values())
