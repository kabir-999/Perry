"""
User-defined custom security test cases.

Deliberately thin: every test runs through the exact same
ParamTarget -> RequestBuilder -> ResponseDiff -> Finding pipeline as the
built-in active tests in active_engine.py — this module adds no new HTTP
handling, response analysis, or scoring, only the translation from a
user-submitted `CustomTestCase` into that pipeline's shapes.

Kept separate from wordlists.py on purpose: a wordlist is a static list of
names reused across every scan; a custom test case is one ad hoc request +
validation rule, scoped to a single scan.
"""
from __future__ import annotations

from urllib.parse import urljoin

from app.services.active_engine import ParamTarget, _send, build_request
from app.services.finding_types import FindingCandidate
from app.services.http_client import Fetcher
from app.services.response_analyzer import analyze
from app.services.scope import TargetScope


async def run_custom_tests(
    fetcher: Fetcher,
    scope: TargetScope,
    test_cases: list[dict],
) -> list[FindingCandidate]:
    """Execute each validated custom test case and return any findings.

    Every test respects scan scope (never sends a request out of scope) and
    the shared Fetcher's own safety limits (budget/concurrency/timeouts) —
    no test here can exceed what a built-in active test could already do.
    """
    findings: list[FindingCandidate] = []
    for case in test_cases:
        url = urljoin(scope.origin, case["path"])
        if not scope.in_scope(url):
            continue

        target = ParamTarget(
            url=url,
            name=case["input"],
            location=case["location"],
            method=case["method"],
            example="1",
        )

        baseline = await fetcher.fetch(url, method=case["method"], use_cache=True)
        result = await _send(fetcher, target, case["test"])
        if not result.ok:
            continue

        if not _validates(case["expected"], baseline, result):
            continue

        findings.append(_to_finding(case, target, result))
    return findings


def _validates(expected: str, baseline, result) -> bool:
    """Evaluate the user-stated validation condition against the response.

    "differs" reuses the same baseline-vs-probe comparison every built-in
    active test already relies on — a custom test cannot claim a finding
    merely because a request succeeded; it must observe the stated
    condition, same as everything else in the pipeline.
    """
    if expected.startswith("contains:"):
        needle = expected[len("contains:"):]
        return bool(needle) and needle in (result.text or "")

    from app.services.active_engine import meaningfully_different

    if not baseline.ok:
        return False
    return meaningfully_different(analyze(baseline), analyze(result))


def _to_finding(case: dict, target: ParamTarget, result) -> FindingCandidate:
    req = build_request(target, case["test"])
    return FindingCandidate(
        title=case["name"],
        category="custom_test",
        severity=case["severity"],
        confidence="potential",
        url=target.url,
        method=target.method,
        parameter=target.name,
        evidence=f"Validation condition '{case['expected']}' was met.",
        request_summary=f"{req.get('method', target.method)} {req.get('url', target.url)}",
        response_summary=f"HTTP {result.status_code}",
        description=case.get("description") or f"User-defined test: {case['name']}",
        impact="",
        remediation="",
        dedup_key=f"custom_test|{case['name']}|{target.url}|{target.name}",
    )
