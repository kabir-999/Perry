"""
Directory / file discovery.

Probes a short, high-signal wordlist concurrently, using the learned
not-found profile to reject soft-404s, and content-verifies sensitive files
before reporting them. Bounded by the shared request budget.
"""
from __future__ import annotations

from app.services.discovery_types import DiscoveredPath
from app.services.finding_types import FindingCandidate
from app.services.http_client import Fetcher
from app.services.response_analyzer import NotFoundProfile, analyze
from app.services.scope import TargetScope
from app.services import security_checks
from app.services.wordlists import DIRECTORY_WORDLIST, SENSITIVE_FILES


async def discover_directories(
    fetcher: Fetcher,
    scope: TargetScope,
    not_found: NotFoundProfile,
) -> tuple[list[DiscoveredPath], list[FindingCandidate]]:
    origin = scope.origin
    dir_urls = [f"{origin}/{path}" for path in DIRECTORY_WORDLIST]
    file_urls = [f"{origin}/{path}" for path in SENSITIVE_FILES]

    dir_results = await fetcher.fetch_many(dir_urls)
    file_results = await fetcher.fetch_many(file_urls)

    discovered: list[DiscoveredPath] = []
    findings: list[FindingCandidate] = []

    for res, path in zip(dir_results, DIRECTORY_WORDLIST):
        analyzed = analyze(res)
        # The path is passed so an SPA shell served for /admin, /dashboard,
        # /login etc. is classified as a fallback rather than a discovery.
        if not not_found.is_real_hit(analyzed, path):
            continue
        discovered.append(
            DiscoveredPath(
                url=res.url,
                status_code=res.status_code,
                content_type=res.content_type,
                response_size=res.body_bytes,
                source="directory_scan",
                discovery_method="directory_scan",
            )
        )
        # Passive checks on the hit (dir listing, debug output, headers).
        findings += security_checks.check_directory_listing(analyzed, res)
        findings += security_checks.check_debug_trace(analyzed, res)

    for res, path in zip(file_results, SENSITIVE_FILES):
        analyzed = analyze(res)
        if analyzed.status_code != 200:
            continue
        if not_found.looks_like_not_found(analyzed, path):
            continue
        file_findings = security_checks.check_sensitive_file_validated(res, path, not_found)
        if file_findings:
            discovered.append(
                DiscoveredPath(
                    url=res.url,
                    status_code=res.status_code,
                    content_type=res.content_type,
                    response_size=res.body_bytes,
                    source="directory_scan",
                    discovery_method="sensitive_file",
                )
            )
            findings += file_findings

    return discovered, findings
