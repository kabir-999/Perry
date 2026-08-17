"""
Stage 2 — Deep Scan orchestrator.

The one centralized pipeline (§1):

    scope → static + browser discovery → network interception →
    Attack Surface Inventory → auth discovery → Test Planner →
    12 attack modules → evidence validation → finding dedup →
    5-factor risk scoring → coverage → report

Discovery *sources* populate a single ``AttackSurfaceInventory``; the Test
Planner and the 12 attack modules read only from it — no attack module
crawls. Risk is the pure 5-factor formula (``risk_engine``); overall risk is
the highest confirmed finding; coverage and confidence are separate numbers
that never modify the score.
"""
from __future__ import annotations

import asyncio
import ctypes
import gc
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from app.config import settings
from app.services import (
    active_engine,
    anomaly_engine,
    attack_graph,
    attack_logger,
    security_checks,
)
from app.services.api_discovery import discover_apis
from app.services.assessment import compute_assessment
from app.services.attacks import catalog as C
from app.services.attacks.executor import AttackContext, execute_plan
from app.services.auth_discovery import detect_auth_surface
from app.services.browser_crawler import browser_crawl
from app.services.coverage import build_test_matrix, compute_coverage, per_attack_coverage
from app.services.crawler import crawl
from app.services.debug_log import debug_log
from app.services.directory_scanner import discover_directories
from app.services.discovery_types import BrowserCrawlResult, DiscoveredParam, DiscoveredPath
from app.services.fast_scanner import FastScanResult
from app.services.finding_types import FindingCandidate
from app.services.http_client import Fetcher, build_async_client
from app.services.inventory import (
    API,
    FORM,
    PAGE,
    REDIRECT,
    UPLOAD,
    AttackSurfaceInventory,
)
from app.services.js_analyzer import analyze_bundles
from app.services.network_classifier import API as _NET_API, GRAPHQL as _NET_GRAPHQL, classify_request
from app.services.parameter_discovery import consolidate_parameters, extract_params_from_network
from app.services.response_analyzer import analyze, learn_not_found_profile
from app.services.risk_engine import score_all
from app.services.risk_model import deduplicate
from app.services.scope import InvalidTargetError, TargetScope, build_scope
from app.services.scope_policy import attribute as attribute_scope
from app.services.severity_policy import apply_policy
from app.services.subdomain_scanner import DiscoveredSubdomain, discover_subdomains
from app.services.test_planner import plan_tests
from app.services.vhost_scanner import discover_vhosts

EmitFn = Callable[[dict], Awaitable[None]]
CancelFn = Callable[[], bool]

_REDIRECT_STATUSES = {301, 302, 303, 307, 308}


@dataclass
class DeepScanResult:
    # Discovery (persisted to discovered_endpoints / parameters).
    endpoints: list[DiscoveredPath] = field(default_factory=list)
    params: list[DiscoveredParam] = field(default_factory=list)
    subdomains: list[DiscoveredSubdomain] = field(default_factory=list)
    vhosts: list = field(default_factory=list)

    findings: list[FindingCandidate] = field(default_factory=list)
    requests_made: int = 0

    # Attack surface inventory (in-memory; not persisted wholesale).
    inventory: AttackSurfaceInventory | None = None

    # Test matrix + per-attack + crawl coverage (§21/§22/§23).
    attack_matrix: list[dict] = field(default_factory=list)
    attack_coverage: dict = field(default_factory=dict)
    coverage: dict = field(default_factory=dict)

    # Production-grade structured JSON logs for every attack attempt
    # (success, clean, skipped, inconclusive, or errored) — persisted and
    # rendered under each attack's box in the UI.
    attack_logs: list[dict] = field(default_factory=list)

    # Per-domain + overall anomaly scores from the baseline-vs-fuzz comparison
    # ({"overall": {...}, "domains": {attack: {...}}}).
    anomaly_scores: dict = field(default_factory=dict)

    # Full attack-surface graph: normalized, de-duplicated endpoints with
    # parent/child edges ({"nodes": [...], "edges": [...], "roots": [...]}).
    attack_graph: dict = field(default_factory=dict)

    # Per-strategy crawl layer: {"bfs": {...}, "dfs": {...}}, each with its own
    # graph, discovery score, stats, and crawl log.
    crawl_strategies: dict = field(default_factory=dict)

    # Deterministic risk (5-factor); overall = highest confirmed finding.
    overall_risk: int = 0
    risk_score: int = 0
    final_risk: str = ""  # risk level derived from overall_risk
    assessment_confidence: str = ""
    assessment_coverage: int = 0
    assessment_warning: str = ""


class _Cancelled(Exception):
    pass


def _release_memory() -> None:
    """Force freed heap back to the OS after a scan.

    A scan's `Fetcher` (response cache), inventory, findings, and network-
    request lists are all local to `run_deep_scan` and become garbage once it
    returns — but on glibc, CPython's allocator does not hand freed memory
    back to the OS by default; it keeps the arena around for reuse. On a
    long-lived process on a memory-constrained container, that means RSS
    creeps up scan after scan even though nothing is actually leaking, until
    a later scan's Chromium launch tips the container over into OOM. gc.
    collect() ensures cyclic garbage (dataclasses with back-references,
    closures in browser_crawler's frontier callbacks) is actually freed
    first; malloc_trim(0) then asks glibc to release those now-empty arenas
    back to the OS. Safe no-op on non-glibc platforms (e.g. macOS dev).
    """
    gc.collect()
    try:
        ctypes.CDLL("libc.so.6").malloc_trim(0)
    except OSError:
        pass


def _strategy_payload(res: BrowserCrawlResult) -> dict:
    """Per-strategy crawl-layer summary: graph + discovery score + stats + log."""
    stats = attack_graph.graph_stats(res.graph or {})
    stats.update({
        "pages_rendered": res.pages_rendered,
        "interactions": res.interactions_performed,
        "network_requests": len(res.network_requests),
        "max_depth_reached": res.max_depth_reached,
        "errors": len(res.errors),
    })
    return {
        "strategy": res.strategy,
        "graph": res.graph or {"nodes": [], "edges": [], "roots": [], "node_count": 0, "edge_count": 0},
        "stats": stats,
        "score": attack_graph.crawl_score(stats, interactions=res.interactions_performed),
        "log": res.log[:500],
    }


async def run_deep_scan(
    scope: TargetScope,
    fast_result: FastScanResult,
    *,
    emit: EmitFn,
    is_cancelled: CancelFn,
    passive_only: bool = False,
    auth_header: str | None = None,
    auth_header_b: str | None = None,
) -> DeepScanResult:
    client = build_async_client(
        timeout=settings.DEEP_REQUEST_TIMEOUT_SECONDS,
        connect_timeout=settings.FAST_CONNECT_TIMEOUT_SECONDS,
        max_connections=settings.HTTP_MAX_CONNECTIONS,
        max_keepalive=settings.HTTP_MAX_KEEPALIVE,
    )
    lite_profile = settings.SCAN_PROFILE.strip().lower() == "lite"
    concurrency = 4 if lite_profile else settings.DEEP_CONCURRENCY
    fetcher = Fetcher(
        client,
        concurrency=concurrency,
        request_budget=settings.DEEP_MAX_REQUESTS,
        max_response_bytes=settings.DEFAULT_MAX_RESPONSE_BYTES,
    )
    result = DeepScanResult()

    # Install the per-scan structured attack-log collector on this async
    # context, so every attack runner's records are attributed to this scan.
    attack_log = attack_logger.start_collector()

    async def check():
        if is_cancelled():
            raise _Cancelled()

    try:
        await emit({"deep_progress": 5})
        await check()

        not_found = await learn_not_found_profile(fetcher, scope.origin)

        browser_auth_headers = None
        if auth_header:
            name, sep, value = auth_header.partition(":")
            browser_auth_headers = {name.strip(): value.strip()} if sep else {"Authorization": auth_header}

        # --- Discovery phase 1: static crawl + subdomains + directories +
        # optional browser crawl (BFS) ---
        #
        # This used to also run a second, DFS-strategy browser crawl —
        # concurrently at first (two full Chromium instances competing for
        # the same CPU/RAM, a real cause of container OOM restarts), then
        # sequentially (safe on memory, but still a second full
        # launch+render+interact cycle added to every scan's wall-clock
        # time). BFS's priority-ordered frontier (highest attack-surface
        # score first) already covers the same ground DFS did within the
        # same page budget, so the second full browser cycle was pure
        # latency with little unique discovery to show for it. The cheap,
        # mostly I/O-bound static-crawl/subdomain/directory work still runs
        # concurrently with the browser crawl when the scan profile allows
        # it.
        _seed = fast_result.homepage_url or scope.origin
        browser_task = (
            browser_crawl(scope, _seed, auth_header=browser_auth_headers)
            if not lite_profile
            else None
        )
        tasks = [
            crawl(
                fetcher, scope,
                seed_url=_seed,
                seed_html=fast_result.homepage_text or None,
                max_pages=settings.CRAWL_MAX_PAGES,
                max_depth=settings.CRAWL_MAX_DEPTH,
            ),
            discover_subdomains(scope),
            discover_directories(fetcher, scope, not_found, passive_only=passive_only),
        ]
        if browser_task is not None:
            tasks.append(browser_task)

        gathered = await asyncio.gather(*tasks)
        crawl_result, subdomains, (dir_paths, dir_findings), *browser_tail = gathered
        if browser_tail:
            browser_result = browser_tail[0]
        else:
            browser_result = BrowserCrawlResult()
            browser_result.errors.append(
                "Browser crawl disabled by SCAN_PROFILE=lite to conserve memory."
            )
            debug_log("BROWSER", browser_result.errors[-1])
        result.subdomains = subdomains
        crawl_limit_reached = (
            len(crawl_result.pages) >= settings.CRAWL_MAX_PAGES
            or len(browser_result.pages) >= settings.BROWSER_CRAWL_MAX_PAGES
        )
        scan_errors = bool([
            e for e in browser_result.errors
            if "not installed" not in e.lower()
            and "disabled by scan_profile=lite" not in e.lower()
        ])
        for p in crawl_result.pages:
            debug_log("CRAWLER", f"page {p.url}")
        debug_log("BROWSER", f"{len(browser_result.pages)} rendered pages, "
                             f"{len(browser_result.network_requests)} network requests")

        await emit({"deep_progress": 40,
                    "urls_discovered": len(crawl_result.pages) + len(browser_result.pages),
                    "subdomains_discovered": len(subdomains)})
        await check()

        # --- Discovery phase 2: API discovery + vhosts + JS bundle mining ---
        script_urls = crawl_result.script_urls | browser_result.js_bundle_urls
        (api_paths, api_params), vhosts, js = await asyncio.gather(
            discover_apis(fetcher, scope, not_found, crawl_result.internal_links),
            discover_vhosts(fetcher, scope, extra_hosts=[s.hostname for s in subdomains], not_found=not_found),
            analyze_bundles(fetcher, scope, script_urls, not_found),
        )
        result.vhosts = vhosts

        # --- Build the ONE Attack Surface Inventory (§2) ---
        inv = AttackSurfaceInventory()
        for p in crawl_result.pages + browser_result.pages:
            inv.add_path(p, kind=PAGE)
        for p in dir_paths:
            inv.add_path(p, kind=PAGE)
        for p in api_paths + js.endpoints:
            inv.add_path(p, kind=API)

        # The browser network layer captures every request the page's JS
        # makes, including calls to a separate backend origin (e.g. a Vercel
        # SPA calling a Render API) — that cross-origin host is exactly what
        # we want to test, so it doesn't get filtered out here. This matches
        # the same trust boundary the primary target already uses (an
        # authorized/active scan proceeds on the caller's "I own this"
        # confirmation, not a separate proof-of-control step): once a scan is
        # authorized to attack at all, a host its own crawl led it to is
        # treated the same way. A passive-only scan (no authorization
        # confirmed) stays strictly on the declared target/subdomains, so an
        # unauthorized scan never reaches out to a third-party host at all.
        network_params = [
            p for p in extract_params_from_network(browser_result.network_requests)
            if not passive_only or scope.in_scope(p.url)
        ]
        for req in browser_result.network_requests:
            inv.add_network_request(req)
            debug_log("NETWORK", f"{req.method} {req.url} [{req.resource_type}]")
            if passive_only and not scope.in_scope(req.url):
                continue
            kind = classify_request(req)
            if kind in (_NET_API, _NET_GRAPHQL):
                ep = inv.add_endpoint(req.url, method=req.method, kind=API,
                                      status_code=req.response_status,
                                      content_type=req.response_content_type)
                debug_log("API", f"{ep.endpoint_id} {ep.method} {ep.normalized_route}")
            if req.response_status in _REDIRECT_STATUSES:
                inv.mark_redirect(req.url)
                inv.add_endpoint(req.url, method=req.method, kind=REDIRECT)

        for dp in consolidate_parameters(crawl_result.params, browser_result.params, api_params, network_params):
            pm = inv.add_discovered_param(dp)
            if pm:
                debug_log("PARAM", f"{pm.parameter_id} {pm.name} [{pm.location}]")
        for form in crawl_result.forms + browser_result.forms:
            inv.add_form(form)
        for up in crawl_result.upload_endpoints:
            inv.add_upload(up)

        inv.js_bundles = set(script_urls)
        inv.subdomains = subdomains
        inv.vhosts = vhosts

        auth_surface = detect_auth_surface(
            crawl_result.pages + browser_result.pages,
            crawl_result.forms + browser_result.forms,
            browser_result.network_requests,
        )
        inv.auth_routes = {
            "login_urls": sorted(auth_surface.login_urls),
            "register_urls": sorted(auth_surface.register_urls),
            "logout_urls": sorted(auth_surface.logout_urls),
            "password_reset_urls": sorted(auth_surface.password_reset_urls),
            "session_cookie_names": sorted(auth_surface.session_cookie_names),
            "bearer_token_seen": auth_surface.bearer_token_seen,
            "jwt_shaped_tokens_seen": auth_surface.jwt_shaped_tokens_seen,
        }
        debug_log("AUTH", f"has_auth_surface={auth_surface.has_auth_surface}")
        result.inventory = inv

        # --- Passive findings (evidence for misconfig / sensitive-info / vhost) ---
        passive_findings: list[FindingCandidate] = []
        passive_findings += dir_findings                       # sensitive files
        passive_findings += await _passive_over_pages(fetcher, crawl_result.pages)  # headers/cookies/cors/dir-listing/debug/version
        passive_findings += js.findings                        # source maps
        passive_findings += _upload_findings(crawl_result.upload_endpoints)
        passive_findings += _vhost_findings(vhosts)
        passive_findings += await _assess_subdomains(fetcher, subdomains, passive_only=passive_only)
        attribute_scope(passive_findings, scope)

        await emit({"deep_progress": 60,
                    "apis_discovered": len(inv.api_endpoints()),
                    "parameters_discovered": len(inv.parameters)})
        await check()

        # --- Test Planner (§7) ---
        auth_available = bool(auth_header) and auth_surface.has_auth_surface
        plan = plan_tests(inv, passive_only=passive_only, auth_available=auth_available)

        # --- Execute the 12 attack modules (§8-19) ---
        ctx = AttackContext(
            fetcher=fetcher, inventory=inv, passive_only=passive_only,
            auth_header=auth_header, auth_header_b=auth_header_b, not_found=not_found,
            passive_findings=passive_findings, subdomains=subdomains, vhosts=vhosts,
        )
        executions = await execute_plan(plan, ctx)
        await check()

        # --- Findings = passive + attack-execution findings ---
        findings = list(passive_findings)
        for e in executions:
            if e.finding is not None:
                findings.append(e.finding)
        findings = deduplicate(findings)
        attribute_scope(findings, scope)
        apply_policy(findings)
        score_all(findings)
        result.findings = findings
        result.requests_made = fetcher.requests_made

        # Persisted discovery lists.
        result.endpoints = _endpoint_paths(inv)
        result.params = _param_list(inv)

        # --- Test matrix + coverage (§21/§22/§23) ---
        result.attack_matrix = build_test_matrix(executions, inv)
        result.attack_coverage = per_attack_coverage(plan, executions)
        result.attack_logs = list(attack_log.records)
        result.anomaly_scores = anomaly_engine.compute_anomaly(executions)

        # --- Full attack-surface graph (§ interaction-driven discovery) ---
        params_by_ep: dict[str, list[str]] = {}
        for pm in inv.parameters:
            params_by_ep.setdefault(pm.endpoint_id, []).append(pm.name)
        endpoints_for_graph = [
            {
                "url": ep.url,
                "method": ep.method or "GET",
                "discovery": ep.kind or "discovery",
                "params": params_by_ep.get(ep.endpoint_id, []),
                "is_api": ep.kind == "api",
                "is_form": ep.kind == "form",
            }
            for ep in inv.endpoints
        ]
        result.attack_graph = attack_graph.build_attack_graph(
            scope.origin, getattr(browser_result, "graph", {}) or {}, endpoints_for_graph,
        )
        # Per-strategy crawl layer — own graph, score, stats, log. DFS was
        # dropped (see the discovery-phase comment above); only BFS remains,
        # so the frontend's "DFS" comparison tab has nothing to key off and
        # won't render.
        result.crawl_strategies = {
            "bfs": _strategy_payload(browser_result),
        }

        cov = compute_coverage(inv, executions)
        result.coverage = cov.to_dict()
        debug_log("COVERAGE", f"ratio={cov.coverage_ratio} tested={cov.security_tests_executed} "
                              f"not_tested={cov.security_tests_not_executed}")

        # --- Risk (5-factor; overall = highest confirmed finding) ---
        assessment = compute_assessment(findings, cov, scan_errors=scan_errors,
                                        crawl_limit_reached=crawl_limit_reached)
        result.overall_risk = assessment.overall_risk
        result.risk_score = assessment.overall_risk
        result.final_risk = assessment.risk_level
        result.assessment_confidence = assessment.assessment_confidence
        result.assessment_coverage = assessment.assessment_coverage
        result.assessment_warning = assessment.warning
        debug_log("RISK", f"overall_risk={assessment.overall_risk} level={assessment.risk_level} "
                          f"confidence={assessment.assessment_confidence} coverage={assessment.assessment_coverage}%")

        await emit({"deep_progress": 100,
                    "findings_count": len(result.findings),
                    "security_checks_completed": len(result.endpoints)})
        return result

    except _Cancelled:
        result.requests_made = fetcher.requests_made
        raise
    finally:
        await client.aclose()
        _release_memory()


# --------------------------------------------------------------------------
# Inventory → persistence shapes
# --------------------------------------------------------------------------

def _endpoint_paths(inv: AttackSurfaceInventory) -> list[DiscoveredPath]:
    method_map = {API: "api_discovery", UPLOAD: "crawler", FORM: "crawler", REDIRECT: "crawler", PAGE: "crawler"}
    out: list[DiscoveredPath] = []
    for ep in inv.endpoints:
        out.append(DiscoveredPath(
            url=ep.url, method=ep.method, status_code=ep.status_code,
            content_type=ep.content_type, source=ep.kind,
            discovery_method=method_map.get(ep.kind, "crawler"),
        ))
    return out


def _param_list(inv: AttackSurfaceInventory) -> list[DiscoveredParam]:
    out: list[DiscoveredParam] = []
    for pm in inv.parameters:
        ep = inv.endpoint(pm.endpoint_id)
        out.append(DiscoveredParam(
            url=ep.url if ep else "", name=pm.name, param_type=pm.location,
            example_value=pm.original_value, method=ep.method if ep else "GET",
        ))
    return out


# --------------------------------------------------------------------------
# Passive discovery helpers (preserved from the previous pipeline)
# --------------------------------------------------------------------------

async def _passive_over_pages(
    fetcher: Fetcher, pages: list[DiscoveredPath]
) -> list[FindingCandidate]:
    findings: list[FindingCandidate] = []
    results = await fetcher.fetch_many([p.url for p in pages])
    for res in results:
        if not res.ok:
            continue
        findings += security_checks.run_passive_checks(res, analyze(res))
    return findings


async def _assess_subdomains(
    fetcher: Fetcher,
    subdomains: list[DiscoveredSubdomain],
    *,
    passive_only: bool,
) -> list[FindingCandidate]:
    """Independent, bounded passive assessment of resolved subdomains — a DNS
    record alone is never a finding; everything goes through the same
    evidence-based checks as the primary target, sharing the one budget."""
    findings: list[FindingCandidate] = []
    for sub in subdomains[: settings.SUBDOMAIN_ASSESS_LIMIT]:
        if fetcher.budget_exhausted:
            break
        try:
            sub_scope = build_scope(f"https://{sub.hostname}")
        except InvalidTargetError:
            continue
        probe = await fetcher.fetch(sub_scope.origin, use_cache=True)
        if not probe.ok:
            try:
                sub_scope = build_scope(f"http://{sub.hostname}")
            except InvalidTargetError:
                continue
            probe = await fetcher.fetch(sub_scope.origin, use_cache=True)
            if not probe.ok:
                continue
        findings += security_checks.run_passive_checks(probe, analyze(probe))
    return findings


def _upload_findings(uploads) -> list[FindingCandidate]:
    from urllib.parse import urlsplit

    out: list[FindingCandidate] = []
    for up in uploads:
        path = urlsplit(up.url).path
        out.append(FindingCandidate(
            title="File upload endpoint detected",
            category="configuration", severity="low", confidence="potential",
            url=up.url, method=up.method,
            evidence="Form accepts file uploads (multipart/form-data or <input type=file>).",
            description="A file-upload endpoint was discovered. Uploads should be validated "
                        "for type, size, and safe storage.",
            dedup_key=f"file_upload|{path}",
        ))
    return out


def _vhost_findings(vhosts) -> list[FindingCandidate]:
    """Report development/admin surfaces that were *observed*, nothing more —
    a distinct application at admin.example.com is a real discovery, but the
    finding states only what was seen and what was not determined."""
    out: list[FindingCandidate] = []
    for v in vhosts:
        if not getattr(v, "distinct", False):
            continue
        if not v.environment:
            out.append(FindingCandidate(
                title=f"Potentially interesting hostname: {v.hostname}",
                category="attack_surface", severity="info", confidence="confirmed",
                url=v.hostname,
                evidence=(f"{v.hostname} serves an application distinct from the primary host "
                          f"and from the catch-all response (HTTP {v.status_code}, "
                          f"{v.content_length} bytes"
                          + (f", title: {v.title!r}" if v.title else "") + ")."),
                response_summary=f"HTTP {v.status_code}, {v.content_length} bytes",
                description="The hostname pattern suggests a non-production or administrative "
                            "deployment, but nothing in the response confirms that. Reported "
                            "for awareness only.",
                impact="Not established. The environment type was inferred from the hostname "
                       "alone, which is not evidence.",
                remediation=f"Confirm what {v.hostname} serves and whether it is meant to be "
                            "publicly reachable.",
                dedup_key=f"vhost|{v.hostname}",
            ))
            continue
        label = v.environment
        out.append(FindingCandidate(
            title=f"Exposed {label} surface detected at {v.hostname}",
            category="attack_surface", severity="low", confidence="confirmed",
            url=v.hostname,
            evidence=(f"Host: {v.hostname} returns HTTP {v.status_code} with a "
                      f"{v.content_length}-byte body that differs from the primary host, so a "
                      "separate application is served here."),
            response_summary=f"HTTP {v.status_code}, {v.content_length} bytes, distinct from the primary host",
            description=f"A separate application responds on {v.hostname}. The '{label}' label "
                        "suggests a non-production or administrative deployment reachable from "
                        "the public internet.",
            impact="This widens the attack surface. The scanner did NOT determine whether "
                   "authentication is required, whether administrative functions are reachable, "
                   "whether debug mode is enabled, or whether any sensitive data is exposed.",
            remediation=f"Confirm {v.hostname} is meant to be public; if not, remove the DNS "
                        "record or restrict access.",
            dedup_key=f"vhost|{v.hostname}",
        ))
    return out
