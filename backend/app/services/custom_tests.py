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

from urllib.parse import urlencode, urljoin

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


# ---------------------------------------------------------------------------
# Attack presets — the "attack=sql injection" shorthand.
#
# Every payload and detector here IS active_engine.py's own _TESTS list, not
# a second copy of them: a preset test uses exactly the same SQLi/XSS/
# traversal/command-injection payloads and the same evidence-based detector
# functions the built-in active engine runs, just against a developer's own
# multi-field request (e.g. a login form's `name`+`password`) instead of a
# single discovered parameter.
# ---------------------------------------------------------------------------

_ATTACK_ALIASES = {
    "sql_injection": "sqli", "sqli": "sqli", "sql": "sqli",
    "xss": "reflected_xss", "cross_site_scripting": "reflected_xss",
    "reflected_xss": "reflected_xss",
    "path_traversal": "path_traversal", "directory_traversal": "path_traversal",
    "traversal": "path_traversal", "lfi": "path_traversal",
    "command_injection": "cmd_injection", "cmd_injection": "cmd_injection",
    "cmd": "cmd_injection", "rce": "cmd_injection",
}


def resolve_attack_preset(name: str):
    """Look up a named attack (any of its aliases) as one of active_engine's
    own `_Test` entries — the same object the built-in engine iterates."""
    import re

    from app.services.active_engine import _TESTS

    key = re.sub(r"[\s_-]+", "_", (name or "").strip().lower())
    prefix = _ATTACK_ALIASES.get(key)
    if not prefix:
        return None
    by_prefix = {t.dedup_prefix: t for t in _TESTS}
    return by_prefix.get(prefix)


def known_attack_names() -> list[str]:
    """For error messages / interactive prompts — the recognized aliases."""
    return sorted(_ATTACK_ALIASES)


async def _send_fields(fetcher: Fetcher, url: str, method: str, location: str, fields: dict):
    if location == "query":
        full_url = f"{url}{'&' if '?' in url else '?'}{urlencode(fields)}" if fields else url
        return await fetcher.fetch(full_url, method=method, use_cache=False, follow_redirects=False)
    if location == "json":
        return await fetcher.fetch(url, method=method, json=fields, use_cache=False, follow_redirects=False)
    if location == "header":
        return await fetcher.fetch(url, method=method, headers=fields, use_cache=False, follow_redirects=False)
    # "form" and any unrecognized location both fall back to form-encoding —
    # a login-style multi-field submission is the common case this is for.
    return await fetcher.fetch(url, method=method, data=fields, use_cache=False, follow_redirects=False)


def _preset_finding(attack_key: str, test, url: str, method: str, field: str,
                     payload: str, evidence: str, *, severity: str | None = None,
                     display_name: str | None = None) -> FindingCandidate:
    return FindingCandidate(
        title=display_name or f"{test.name} (custom test)",
        category=test.category,
        severity=severity or test.severity,
        confidence="potential",
        url=url,
        method=method,
        parameter=field,
        evidence=evidence,
        request_summary=f"{method} {url} — field '{field}' = {payload!r}",
        description=f"A custom '{attack_key}' test injected into the '{field}' "
        f"field produced the same evidence active_engine's own {test.name} "
        "check looks for.",
        remediation="",
        # The display name (2nd segment) must survive severity_policy's
        # title-softening (e.g. "SQL injection" -> "possible SQL injection
        # pattern") — callers that need to know "did spec X fire" should
        # match on this, never on `.title`.
        dedup_key=f"custom_attack_{test.dedup_prefix}|{display_name or test.name}|{field}",
    )


async def run_attack_preset_tests(
    fetcher: Fetcher,
    scope: TargetScope,
    specs: list[dict],
) -> list[FindingCandidate]:
    """Execute shorthand "attack=<name>" test specs.

    Each spec's non-reserved keys are the request's other fields (e.g. a
    login form's `name`/`password` baseline values) — the attack payload is
    substituted into one field at a time (the one named by `target`, or
    every field in turn if `target` wasn't given), keeping the rest at their
    baseline value, mirroring how a real login-form SQLi/XSS probe is
    actually carried out.
    """
    findings: list[FindingCandidate] = []
    for spec in specs:
        test = resolve_attack_preset(spec.get("attack", ""))
        if test is None:
            continue  # unknown attack name — the CLI validates this earlier

        url = urljoin(scope.origin, spec["path"])
        if not scope.in_scope(url):
            continue

        fields: dict = dict(spec.get("fields") or {})
        # GET+query is the safer default even when fields are present — many
        # of the endpoints this shorthand targets (?id=, ?q=) take their
        # data via the query string regardless; a form that truly needs
        # POST should have method set explicitly by the caller.
        method = spec.get("method") or "GET"
        location = spec.get("location") or ("query" if method == "GET" else "form")
        target_fields = [spec["target"]] if spec.get("target") else (list(fields) or ["value"])

        baseline_fields = fields or {target_fields[0]: "1"}
        baseline = await _send_fields(fetcher, url, method, location, baseline_fields)
        if not baseline.ok:
            continue

        for field in target_fields:
            for payload in test.payloads[:4]:
                probe_fields = dict(baseline_fields)
                probe_fields[field] = payload
                result = await _send_fields(fetcher, url, method, location, probe_fields)
                if not result.ok:
                    continue
                evidence = test.detect(payload, baseline.text, result.text)
                if evidence:
                    findings.append(
                        _preset_finding(
                            spec.get("attack", ""), test, url, method, field, payload, evidence,
                            severity=spec.get("severity"),
                            display_name=spec.get("name"),
                        )
                    )
                    break  # this field already fired; stop escalating it
    return findings
