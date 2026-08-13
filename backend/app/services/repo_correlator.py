from dataclasses import dataclass, field
from typing import Optional

from app.services.finding_types import FindingCandidate
from app.services.discovery_types import DiscoveredPath

@dataclass
class SourceFinding:
    finding_type: str    # "hardcoded_secret" | "env_secret" | "sql_injection" | ...
    file: str
    line: int
    severity: str
    confidence: str
    evidence: str        # always redacted
    secret_type: str     # "API_KEY" | "PASSWORD" | etc.
    redacted_value: str  # "[REDACTED]"
    code_context: str    # surrounding lines (redacted)
    # True when this secret lives in a file that is gitignored and was never
    # staged/committed — a local-hygiene note, not an exposure. Callers use
    # this to report it as informational rather than a vulnerability.
    local_only: bool = False

@dataclass
class DependencyFinding:
    package: str
    version: str
    ecosystem: str       # "npm" | "pypi" | "maven" | ...
    advisory_id: str     # e.g., "GHSA-xxxx" or "CVE-xxxx"
    severity: str
    affected_versions: str  # vulnerable version range from the advisory
    fixed_version: str
    source: str          # "osv"

    # Exploitability context — see services/dependency_analysis.py. These
    # decide how the advisory is reported, so a CVE against an unused package
    # is never presented as an exploitable vulnerability.
    classification: str = "dependency_present"
    is_direct: bool = False
    is_development: bool = False
    dependency_kind: str = "transitive production"
    is_used: bool = False
    # Whether the *specific* functionality the advisory names is called, and
    # whether attacker-controlled input can reach that call.
    functionality_used: bool = False
    reachable_from_input: bool = False
    vulnerable_symbols: list[str] = field(default_factory=list)
    symbols_found: list[str] = field(default_factory=list)
    call_sites: list[str] = field(default_factory=list)
    tainted_call_sites: list[str] = field(default_factory=list)
    import_sites: list[str] = field(default_factory=list)
    advisory_summary: str = ""
    usage_notes: str = ""
    reachability_notes: str = ""


import re


def _path_tokens(path: str) -> set[str]:
    """Break a URL path into its meaningful route segments, lowercased."""
    return {p for p in path.lower().split("/") if p}


def _file_tokens(file: str) -> set[str]:
    """Break a file path into segment/stem tokens for exact comparison.

    Splitting on path separators plus common word-separators and stripping
    the extension means "routes/api/users.js" yields {"routes", "api",
    "users"} — enough to exact-match a route segment without the bare
    substring check spuriously matching e.g. "/api/users" against
    "superusers_backup.js" (which merely *contains* "users").
    """
    stem = file.lower().rsplit(".", 1)[0]
    return {t for t in re.split(r"[/_\-]+", stem) if t}


def correlate(
    website_findings: list[FindingCandidate],
    website_endpoints: list[DiscoveredPath],
    source_findings: list[SourceFinding]
) -> list[FindingCandidate]:
    """
    Match website endpoints against source code findings to create correlated findings.
    This is a single corroborating signal (a route segment matches a filename
    token) — not a demonstrated exploit. It never invents confidence beyond
    what the underlying source finding already had, and it reuses that
    finding's own dedup key so the risk model merges the two into one
    contributor instead of scoring the same issue twice.
    """
    correlated: list[FindingCandidate] = []

    # Extract endpoint paths
    from urllib.parse import urlparse
    live_paths = {urlparse(ep.url).path for ep in website_endpoints}

    # Look for source findings that match live endpoints
    for sf in source_findings:
        # Heuristic: a live route's last path segment exactly matches one of
        # the source file's own path/name tokens.
        # E.g. file is "routes/api/users.js" and live path is "/api/users".
        file_tokens = _file_tokens(sf.file)
        matched_path = None
        for path in live_paths:
            if path == "/":
                continue
            path_parts = [p for p in path.lower().split("/") if p]
            if not path_parts:
                continue

            if path_parts[-1] in file_tokens:
                matched_path = path
                break

        if matched_path:
            # We found a correlation!
            title = ""
            desc = ""
            if sf.finding_type == "sql_injection":
                title = f"Correlated SQL Injection at {matched_path}"
                desc = f"Vulnerable code pattern in `{sf.file}` appears to handle requests to `{matched_path}`."
            elif sf.finding_type in ("hardcoded_secret", "env_secret"):
                # Usually secrets are global, not per-endpoint, but if it's in a route file...
                title = f"Hardcoded Secret exposed at {matched_path}"
                desc = f"Secret found in `{sf.file}` which appears to back `{matched_path}`."
            else:
                title = f"Correlated Vulnerability at {matched_path}"
                desc = f"Code pattern in `{sf.file}` matches live endpoint `{matched_path}`."

            if title:
                # A filename/route-segment match is one signal, not proof.
                # Only carry "confirmed" through if the source finding was
                # already confirmed by its own engine — never manufacture it
                # here.
                confidence = "confirmed" if sf.confidence == "confirmed" else "potential"
                correlated.append(
                    FindingCandidate(
                        title=title,
                        category="source_correlation",
                        severity=sf.severity,
                        confidence=confidence,
                        url=matched_path,
                        evidence=f"File: {sf.file}:{sf.line}\nContext: {sf.code_context}",
                        response_summary=f"Matched endpoint: {matched_path}",
                        description=desc,
                        impact="Vulnerability pattern in source code maps to a live, reachable endpoint.",
                        remediation="Fix the vulnerable code pattern in the source repository.",
                        # Same key the main pipeline already assigns this
                        # source finding (see deep_scan.py's
                        # _convert_repo_findings) so this correlation
                        # annotation merges into that one contributor instead
                        # of being scored as a separate, third finding.
                        dedup_key=f"repo_code|{sf.file}|{sf.line}|{sf.finding_type}",
                    )
                )

    return correlated
