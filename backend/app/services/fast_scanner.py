"""
Stage 1 — Fast Scan.

Optimised for *time to first result*: a small, bounded set of high-value
requests run concurrently over one shared client with aggressive timeouts,
producing an initial risk assessment in ~1-2s when the network allows.

It never performs discovery/brute-force here — that is the Deep Scan's job.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from urllib.parse import urlparse

from app.config import settings
from app.services.finding_types import FindingCandidate, FastCheck, SEVERITY_RANK
from app.services.http_client import Fetcher, FetchResult, build_async_client
from app.services.response_analyzer import AnalyzedResponse, analyze
from app.services import security_checks
from app.services.scope import TargetScope


@dataclass
class FastScanResult:
    reachable: bool
    target: str
    initial_risk: str = "minimal"
    checks: list[FastCheck] = field(default_factory=list)
    findings: list[FindingCandidate] = field(default_factory=list)
    server: str = ""
    title: str = ""
    status_code: int | None = None
    error_message: str = ""
    homepage_text: str = ""  # handed to the deep scan to avoid a re-fetch
    homepage_url: str = ""
    redirect_chain: list[tuple[int, str]] = field(default_factory=list)
    redirect_loop: bool = False
    # Structured initial assessment (factual observations only, no risk score).
    https_available: bool = False
    http_available: bool = False
    technology: list[str] = field(default_factory=list)
    security_headers: dict[str, bool] = field(default_factory=dict)
    redirect_issues: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "reachable": self.reachable,
            "target": self.target,
            "initial_risk": self.initial_risk,
            "server": self.server,
            "title": self.title,
            "status_code": self.status_code,
            "error_message": self.error_message,
            "redirect_loop": self.redirect_loop,
            "redirects": [[s, u] for s, u in self.redirect_chain],
            "https_available": self.https_available,
            "http_available": self.http_available,
            "technology": self.technology,
            "security_headers": self.security_headers,
            "redirect_issues": self.redirect_issues,
            "checks": [
                {"label": c.label, "status": c.status, "detail": c.detail}
                for c in self.checks
            ],
        }


_FRIENDLY_ERRORS = {
    "connection_refused": "Unable to reach this website. It refused the "
    "connection — check the URL or that the site is online.",
    "connect_timeout": "This website took too long to respond. Check the URL "
    "or try again.",
    "timeout": "This website took too long to respond. Check the URL or try "
    "again.",
    "invalid_url": "That does not look like a valid website address.",
    "too_many_redirects": "This website redirected too many times to load.",
}


def _friendly_error(code: str | None) -> str:
    if code and code.startswith(("http_error", "unexpected")):
        return "Unable to load this website. Please try again."
    return _FRIENDLY_ERRORS.get(
        code or "", "Unable to reach this website. Please check the URL."
    )


async def run_fast_scan(scope: TargetScope) -> FastScanResult:
    """Run the fast scan for a validated scope."""
    client = build_async_client(
        timeout=settings.FAST_REQUEST_TIMEOUT_SECONDS,
        connect_timeout=settings.FAST_CONNECT_TIMEOUT_SECONDS,
        max_connections=8,
        max_keepalive=8,
    )
    fetcher = Fetcher(
        client,
        concurrency=6,
        # Budget covers manual redirect hops (up to REDIRECT_MAX_DEPTH) for
        # the homepage plus the http/https probes.
        request_budget=8 + settings.REDIRECT_MAX_DEPTH,
        max_response_bytes=settings.FAST_MAX_RESPONSE_BYTES,
    )
    try:
        return await asyncio.wait_for(
            _run(scope, fetcher), timeout=settings.FAST_SCAN_TIMEOUT_SECONDS
        )
    except asyncio.TimeoutError:
        return FastScanResult(
            reachable=False,
            target=scope.hostname,
            error_message="This website took too long to respond. Check the "
            "URL or try again.",
        )
    finally:
        await client.aclose()


async def _run(scope: TargetScope, fetcher: Fetcher) -> FastScanResult:
    host = scope.hostname
    port = f":{scope.port}" if scope.port else ""
    http_url = f"http://{host}{port}/"
    https_url = f"https://{host}{port}/"

    # High-value requests, all concurrent:
    #   home       — the homepage, following redirects manually (loop/scope safe)
    #   http_probe — http:// single hop (HTTP->HTTPS redirect check)
    #   https_probe— https:// availability (TLS)
    home_task = fetcher.fetch_with_redirects(scope.origin, in_scope=scope.in_scope)
    http_task = fetcher.fetch(http_url, follow_redirects=False)
    https_task = fetcher.fetch(https_url, follow_redirects=False)
    home, http_probe, https_probe = await asyncio.gather(
        home_task, http_task, https_task
    )

    if not home.ok:
        # Try the other scheme once before giving up.
        alt = https_probe if scope.scheme == "http" else None
        if alt is None or not alt.ok:
            return FastScanResult(
                reachable=False,
                target=host,
                error_message=_friendly_error(home.error),
            )

    analyzed = analyze(home)
    result = FastScanResult(
        reachable=True,
        target=host,
        status_code=analyzed.status_code,
        title=analyzed.title,
        server=home.headers.get("server", ""),
        homepage_text=home.text,
        # Seed the deep crawl from the final resolved URL, or the origin if a
        # loop meant we never reached a real page.
        homepage_url=(home.url if not home.redirect_loop else scope.origin),
        redirect_chain=home.redirects,
        redirect_loop=home.redirect_loop,
    )

    result.checks.append(_https_check(scope, home, http_probe, https_probe))
    result.checks.append(_headers_check(home, result.findings))
    result.checks.append(_redirect_check(home, http_probe, result.findings))
    result.checks.append(_info_exposure_check(home, analyzed, result.findings))
    result.checks.append(_server_check(home, result.findings))

    # Structured, factual initial assessment (no risk scoring here).
    result.https_available = (
        (https_probe.ok and (https_probe.status_code or 0) < 500)
        or urlparse(home.url).scheme == "https"
    )
    result.http_available = http_probe.ok
    result.security_headers = _header_presence(home)
    # Technology detection is informational: knowing a site runs Cloudflare or
    # nginx is not a finding, and must never be reported as information
    # exposure. Only a disclosed *version* is a finding, and that is handled by
    # check_server_disclosure().
    result.technology = [
        v for v in (home.headers.get("server", ""), home.headers.get("x-powered-by", "")) if v
    ]
    if home.redirect_loop:
        result.redirect_issues.append("redirect_loop")
    if home.out_of_scope_redirect:
        result.redirect_issues.append("off_scope_redirect")

    result.initial_risk = _initial_risk(result.findings, result.checks)
    return result


# Standard security headers, in the snake_case keys the ScanSummary uses.
_HEADER_KEYS = {
    "content_security_policy": "content-security-policy",
    "x_content_type_options": "x-content-type-options",
    "x_frame_options": "x-frame-options",
    "strict_transport_security": "strict-transport-security",
    "referrer_policy": "referrer-policy",
}


def _header_presence(home: FetchResult) -> dict[str, bool]:
    return {key: (hval in home.headers) for key, hval in _HEADER_KEYS.items()}


def _https_check(
    scope: TargetScope,
    home: FetchResult,
    http_probe: FetchResult,
    https_probe: FetchResult,
) -> FastCheck:
    """Report what is actually observed, distinguishing 'HTTPS is used' from
    'HTTPS merely answers on 443'. A site served over plain HTTP is not a
    pass just because an HTTPS port happens to respond."""
    final_scheme = urlparse(home.url).scheme if home.ok else scope.scheme
    https_serves = https_probe.ok and (https_probe.status_code or 0) < 500
    http_redirects_https = (
        http_probe.ok
        and http_probe.status_code in (301, 302, 303, 307, 308)
        and http_probe.headers.get("location", "").lower().startswith("https://")
    )

    # The page the user actually got is over HTTPS, or HTTP redirects to it.
    if final_scheme == "https" or http_redirects_https:
        return FastCheck("HTTPS", "pass", "Site is served over HTTPS.")

    # Served over HTTP. HTTPS may still answer, but it is not enforced.
    if https_serves:
        return FastCheck(
            "HTTPS",
            "warning",
            "Served over HTTP — HTTPS is available but not enforced (no "
            "redirect to HTTPS).",
        )
    return FastCheck(
        "HTTPS", "fail", "Served over HTTP — HTTPS is not available."
    )


def _headers_check(
    home: FetchResult, sink: list[FindingCandidate]
) -> FastCheck:
    findings = security_checks.check_security_headers(home)
    sink.extend(findings)
    if not findings:
        return FastCheck("Security Headers", "pass", "Key headers present.")
    detail = findings[0].evidence
    status = "fail" if findings[0].severity in ("medium", "high") else "warning"
    return FastCheck("Security Headers", status, detail)


def _redirect_check(
    home: FetchResult, http_probe: FetchResult, sink: list[FindingCandidate]
) -> FastCheck:
    # Redirect loop takes precedence — reported as a finding, not a failure.
    if home.redirect_loop:
        chain_str = " -> ".join(u for _, u in home.redirects) or "self"
        sink.append(
            FindingCandidate(
                title="Redirect loop detected",
                category="configuration",
                severity="low",
                confidence="confirmed",
                url=home.requested_url,
                evidence=f"{len(home.redirects)} redirects, looping: {chain_str}"[:400],
                response_summary=chain_str[:400],
                description="Following redirects from the target returned to a "
                "previously visited URL, forming a loop.",
                impact="Visitors cannot load the page; often caused by "
                "misconfigured HTTP/HTTPS or www/non-www redirects.",
                remediation="Fix the redirect rules so the URL resolves to a "
                "single stable final response.",
                dedup_key="redirect_loop",
            )
        )
        return FastCheck(
            "Redirects",
            "warning",
            f"Redirect loop detected ({len(home.redirects)} redirects).",
        )

    if home.out_of_scope_redirect and home.redirects:
        dest = home.redirects[-1][1]
        return FastCheck(
            "Redirects", "warning", f"Redirects off-scope to {dest[:80]} (not followed)."
        )

    if http_probe.ok and http_probe.status_code in (301, 302, 303, 307, 308):
        location = http_probe.headers.get("location", "")
        if location.startswith("https://"):
            return FastCheck(
                "Redirects", "pass", "HTTP correctly redirects to HTTPS."
            )
        return FastCheck(
            "Redirects", "warning", f"HTTP redirects to {location[:80]}"
        )

    if home.redirects:
        chain = " -> ".join(str(s) for s, _ in home.redirects)
        return FastCheck("Redirects", "pass", f"Redirect chain: {chain}")
    return FastCheck("Redirects", "info", "No redirects observed.")


def _info_exposure_check(
    home: FetchResult, analyzed: AnalyzedResponse, sink: list[FindingCandidate]
) -> FastCheck:
    findings = []
    findings += security_checks.check_debug_trace(analyzed, home)
    findings += security_checks.check_directory_listing(analyzed, home)
    findings += security_checks.check_server_disclosure(home)
    sink.extend(findings)
    if not findings:
        return FastCheck(
            "Information Exposure", "pass", "No obvious information leakage."
        )
    worst = min(findings, key=lambda f: SEVERITY_RANK[f.severity])
    status = "fail" if worst.severity in ("critical", "high", "medium") else "warning"
    return FastCheck("Information Exposure", status, worst.title)


def _server_check(
    home: FetchResult, sink: list[FindingCandidate]
) -> FastCheck:
    server = home.headers.get("server", "")
    powered = home.headers.get("x-powered-by", "")
    tech = ", ".join(v for v in (server, powered) if v) or "not disclosed"
    return FastCheck("Technology", "info", tech)


def _initial_risk(
    findings: list[FindingCandidate], checks: list[FastCheck]
) -> str:
    if any(f.severity == "critical" for f in findings):
        return "critical"
    if any(f.severity == "high" for f in findings):
        return "high"
    if any(c.status == "fail" for c in checks) or any(
        f.severity == "medium" for f in findings
    ):
        return "medium"
    if any(f.severity == "low" for f in findings) or any(
        c.status == "warning" for c in checks
    ):
        return "low"
    return "minimal"
