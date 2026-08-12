"""
Scope attribution for findings.

A scan of ``owasp.org`` can easily end up reading a response from
``owasp.atlassian.net`` — the crawler follows a login link, or a redirect
lands there. The missing headers on that response are real, but they are
Atlassian's, not OWASP's. Reporting them under the target is a factual error,
and letting them move the target's risk score is worse.

So every finding is attributed to the origin its *evidence* came from. Only
first-party evidence contributes to the target's score; third-party evidence
is preserved and reported separately, as an observation.
"""
from __future__ import annotations

from urllib.parse import urlsplit

from app.services.finding_types import FindingCandidate
from app.services.scope import EXTERNAL, OUT_OF_SCOPE, SAME_ORIGIN, TargetScope


def _origin_of(url: str) -> str:
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    if not parts.hostname:
        return ""
    return f"{parts.scheme}://{parts.netloc}"


def attribute(findings: list[FindingCandidate], scope: TargetScope) -> None:
    """Tag each finding with the origin of its evidence and whether it counts.

    Also recomputes ``affected_urls`` from the in-scope samples only, so the
    count in the report matches the URLs actually listed under the target.
    """
    for f in findings:
        # Findings without a URL (source-code, dependency) belong to the
        # target by construction — they came from the target's own repository.
        evidence_url = f.url or ""
        if not evidence_url:
            f.origin = scope.origin
            f.scope_status = SAME_ORIGIN
            f.evidence_url = ""
            f.contributes_to_risk = True
            continue

        status = scope.classify_origin(evidence_url)
        f.scope_status = status
        f.origin = _origin_of(evidence_url)
        f.evidence_url = evidence_url
        f.contributes_to_risk = status not in (EXTERNAL, OUT_OF_SCOPE)

        # Recount affected URLs using only in-scope samples.
        samples = f.affected_url_samples or ([evidence_url] if evidence_url else [])
        in_scope_samples = [u for u in samples if scope.contributes_to_risk(u)]
        if f.contributes_to_risk:
            f.affected_url_samples = in_scope_samples or samples[:1]
            # Never claim more affected URLs than in-scope evidence supports.
            if in_scope_samples:
                f.affected_urls = min(f.affected_urls, len(in_scope_samples)) or 1
        else:
            # Keep the third-party evidence intact for the observations panel.
            f.affected_url_samples = samples[:5]
            f.affected_urls = max(1, len(samples))

            f.impact = (
                "This observation concerns an external service and does not "
                "contribute to the target's security risk. "
                + (f.impact or "")
            ).strip()


def split(findings: list[FindingCandidate]) -> tuple[list, list]:
    """Partition into (target findings, third-party observations)."""
    target = [f for f in findings if f.contributes_to_risk]
    third_party = [f for f in findings if not f.contributes_to_risk]
    return target, third_party


def observation_payload(f: FindingCandidate) -> dict:
    """A third-party observation, shaped for the report."""
    return {
        "title": f.title,
        "service": (f.origin or "").replace("https://", "").replace("http://", ""),
        "origin": f.origin,
        "scope_status": f.scope_status,
        "evidence_url": f.evidence_url,
        "evidence": (f.evidence or "")[:400],
        "severity": "informational",
        "contributes_to_risk": False,
        "note": (
            "Observed on an external service reached from the target. "
            "Excluded from the target's risk score."
        ),
    }
