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


_TRAVERSAL_CANDIDATE_EXTENSIONS = (
    ".pdf", ".txt", ".csv", ".zip", ".log", ".doc", ".docx", ".xls", ".xlsx",
    ".xml", ".json", ".yml", ".yaml", ".conf", ".cfg", ".ini",
)


def _looks_file_manipulable(path: str) -> bool:
    """Only file-serving-shaped paths are worth a traversal probe — a bare
    directory or a static asset (image/font/script) has no filesystem
    lookup behind it worth testing this way."""
    tail = path.rstrip("/").rsplit("/", 1)[-1].lower()
    dot = tail.rfind(".")
    return dot > 0 and tail[dot:] in _TRAVERSAL_CANDIDATE_EXTENSIONS


async def discover_directories(
    fetcher: Fetcher,
    scope: TargetScope,
    not_found: NotFoundProfile,
    *,
    passive_only: bool = True,
) -> tuple[list[DiscoveredPath], list[FindingCandidate]]:
    origin = scope.origin
    dir_urls = [f"{origin}/{path}" for path in DIRECTORY_WORDLIST]
    file_urls = [f"{origin}/{path}" for path in SENSITIVE_FILES]

    dir_results = await fetcher.fetch_many(dir_urls)
    # Sensitive-file hits are only ever accepted at status 200 below, so a
    # redirect (e.g. /.env -> a login page) can never itself qualify —
    # not following it avoids treating the redirect target's content as if
    # it were the sensitive file's own content.
    file_results = await fetcher.fetch_many(file_urls, follow_redirects=False)

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
                # The path actually probed, not wherever a redirect landed —
                # `res.url` would misattribute a discovery to a login/error
                # page the request happened to be redirected to.
                url=res.requested_url,
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
        if not passive_only and _looks_file_manipulable(res.requested_url):
            findings += await security_checks.check_path_traversal_on_path(
                fetcher, res.requested_url
            )

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
