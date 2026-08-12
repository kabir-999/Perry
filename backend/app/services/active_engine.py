"""
Unified active-testing engine.

One place that turns a discovered parameter (in ANY location — query, form,
JSON body, header) into evidence, via:

    ParamTarget -> PayloadStrategy -> RequestBuilder -> ResponseDiff -> Finding

Every active security test (XSS, SQLi, path traversal, open redirect, command
injection, HPP) is expressed against this pipeline, so adding a location or a
test does not touch the crawler or the request client. Bounded, baseline-diff
based, escalates to encoded variants only when the primary probe looks
interesting (keeps it fast and non-brute-force).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import parse_qs, quote, urlencode, urlsplit, urlunsplit

from app.services.discovery_types import DiscoveredParam
from app.services.finding_types import FindingCandidate
from app.services.http_client import Fetcher
from app.services.response_analyzer import AnalyzedResponse, analyze, jaccard

# ---------------------------------------------------------------------------
# ParamTarget — a location-agnostic view of one testable parameter
# ---------------------------------------------------------------------------

_LOCATIONS = ("query", "form", "json", "header")


@dataclass
class ParamTarget:
    url: str
    name: str
    location: str = "query"  # query | form | json | header
    method: str = "GET"
    example: str = "1"

    @classmethod
    def from_discovered(cls, p: DiscoveredParam) -> "ParamTarget":
        loc = p.param_type if p.param_type in _LOCATIONS else "query"
        method = p.method or ("POST" if loc in ("form", "json") else "GET")
        return cls(
            url=p.url, name=p.name, location=loc, method=method.upper(),
            example=p.example_value or "1",
        )

    def key(self) -> str:
        parts = urlsplit(self.url)
        return f"{self.method}:{parts.netloc}{parts.path}:{self.location}:{self.name}"


# ---------------------------------------------------------------------------
# PayloadStrategy — a small, intelligent set of mutations
# ---------------------------------------------------------------------------

def encode_variants(payload: str) -> list[str]:
    """Return the base payload plus a few encoded/mutated forms. Deliberately
    small — used only to *confirm* an interesting primary result."""
    variants = [
        payload,
        quote(payload, safe=""),          # URL encoding
        quote(quote(payload, safe=""), safe=""),  # double URL encoding
        payload.replace("<", "%3C").replace(">", "%3E"),
    ]
    seen: set[str] = set()
    out: list[str] = []
    for v in variants:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


# ---------------------------------------------------------------------------
# RequestBuilder — inject a value at the right location
# ---------------------------------------------------------------------------

def _set_query(url: str, name: str, value: str) -> str:
    parts = urlsplit(url)
    q = parse_qs(parts.query, keep_blank_values=True)
    q[name] = [value]
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/",
                       urlencode(q, doseq=True), ""))


def build_request(target: ParamTarget, value: str) -> dict:
    """Build fetch() kwargs that place ``value`` in ``target``'s location."""
    if target.location == "query":
        return {"url": _set_query(target.url, target.name, value), "method": "GET"}
    if target.location == "form":
        return {"url": target.url, "method": "POST",
                "data": {target.name: value}}
    if target.location == "json":
        return {"url": target.url, "method": "POST",
                "json": {target.name: value}}
    if target.location == "header":
        return {"url": target.url, "method": "GET",
                "headers": {target.name: value}}
    return {"url": _set_query(target.url, target.name, value), "method": "GET"}


async def _send(fetcher: Fetcher, target: ParamTarget, value: str):
    req = build_request(target, value)
    return await fetcher.fetch(
        req["url"], method=req.get("method", "GET"),
        headers=req.get("headers"), json=req.get("json"), data=req.get("data"),
        follow_redirects=False, use_cache=False,
    )


# ---------------------------------------------------------------------------
# ResponseDiff — common comparison for all tests
# ---------------------------------------------------------------------------

def meaningfully_different(a: AnalyzedResponse, b: AnalyzedResponse) -> bool:
    if a.status_code != b.status_code:
        return True
    if abs((a.length or 0) - (b.length or 0)) > 64:
        return True
    return jaccard(a.shingles, b.shingles) < 0.9


# ---------------------------------------------------------------------------
# Detection primitives (evidence only; Groq judges final severity)
# ---------------------------------------------------------------------------

_SQL_ERR = re.compile(
    r"SQL syntax.*?MySQL|Warning.*?\Wmysqli?_|unterminated quoted string|"
    r"PostgreSQL.*?ERROR|ORA-\d{5}|SQLite/JDBCDriver|sqlite3\.OperationalError|"
    r"SQLSTATE\[|Microsoft OLE DB Provider for SQL Server",
    re.IGNORECASE,
)
_PASSWD = re.compile(r"root:.*?:0:0:", re.MULTILINE)
_CMD_EVIDENCE = re.compile(
    r"uid=\d+\([^)]+\)\s+gid=\d+|/bin/(?:sh|bash):|command not found|"
    r"syntax error near unexpected token",
    re.IGNORECASE,
)
_XSS_MARKER = "wf7xq<z>'\""

_PATHISH = {
    "file", "path", "page", "doc", "document", "template", "include",
    "download", "dir", "folder", "load", "read", "filename", "name",
}
_CMDISH = {
    "cmd", "command", "exec", "execute", "ping", "host", "ip", "domain",
    "url", "dns", "query", "run", "system", "shell", "code",
}
_REDIRECTISH = {"url", "redirect", "next", "return", "dest", "u", "to", "target"}


@dataclass
class _Test:
    name: str
    category: str
    dedup_prefix: str
    severity: str
    applies: object  # Callable[[ParamTarget], bool]
    payloads: list  # primary first, then mutated variants to try if negative
    detect: object  # Callable[[str, AnalyzedResponse, AnalyzedResponse], str|None]


# Detectors receive: payload, baseline raw text, test raw text.
def _xss_detect(payload, base_raw, test_raw):
    # Check the RAW response — the marker's angle brackets are stripped from
    # visible_text. Reflected unescaped '<z>' is the positive signal.
    if "<z>" in test_raw and _XSS_MARKER in test_raw:
        return "marker reflected unescaped"
    return None


def _sqli_detect(payload, base_raw, test_raw):
    if _SQL_ERR.search(test_raw) and not _SQL_ERR.search(base_raw):
        return _first(_SQL_ERR, test_raw)
    return None


def _trav_detect(payload, base_raw, test_raw):
    m = _PASSWD.search(test_raw)
    return m.group(0)[:100] if m else None


def _cmd_detect(payload, base_raw, test_raw):
    if _CMD_EVIDENCE.search(test_raw) and not _CMD_EVIDENCE.search(base_raw):
        return _first(_CMD_EVIDENCE, test_raw)
    return None


def _first(rx, text):
    m = rx.search(text)
    return m.group(0)[:120] if m else ""


_TESTS: list[_Test] = [
    _Test("Reflected XSS", "input_validation", "reflected_xss", "high",
          lambda t: True, [_XSS_MARKER], _xss_detect),
    _Test("SQL Injection", "input_validation", "sqli", "high",
          lambda t: True, ["'", "1'\"", "1) OR ('1'='1"], _sqli_detect),
    _Test("Path Traversal", "input_validation", "path_traversal", "high",
          lambda t: t.name.lower() in _PATHISH,
          ["../../../../../../etc/passwd", "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd"],
          _trav_detect),
    _Test("Command Injection", "input_validation", "cmd_injection", "high",
          lambda t: t.name.lower() in _CMDISH,
          [";id", "|id", "`id`", "$(id)"], _cmd_detect),
]


# ---------------------------------------------------------------------------
# Adaptive prioritization — score which tests matter for a target
# ---------------------------------------------------------------------------

def priority(target: ParamTarget, test: _Test) -> int:
    name = target.name.lower()
    score = 10
    if test.dedup_prefix == "cmd_injection" and name in _CMDISH:
        score += 40
    if test.dedup_prefix == "path_traversal" and name in _PATHISH:
        score += 30
    if test.dedup_prefix == "reflected_xss" and name in ("q", "search", "query", "s", "name", "message", "comment"):
        score += 25
    if test.dedup_prefix == "sqli" and name in ("id", "user_id", "uid", "pid", "order", "sort", "cat"):
        score += 25
    if target.location in ("json", "form"):
        score += 5  # bodies are higher-value, less commonly hardened
    return score


# ---------------------------------------------------------------------------
# Engine entry points
# ---------------------------------------------------------------------------

async def run_active_tests(
    fetcher: Fetcher,
    params: list[DiscoveredParam],
    *,
    max_targets: int = 12,
) -> list[FindingCandidate]:
    # Build unique targets across all locations.
    targets: dict[str, ParamTarget] = {}
    for p in params:
        if not p.name:
            continue
        t = ParamTarget.from_discovered(p)
        targets.setdefault(t.key(), t)

    ranked = sorted(
        targets.values(),
        key=lambda t: max((priority(t, tc) for tc in _TESTS), default=0),
        reverse=True,
    )[:max_targets]

    findings: list[FindingCandidate] = []
    for target in ranked:
        findings += await _test_target(fetcher, target)
        findings += await _hpp_test(fetcher, target)
        findings += await _open_redirect(fetcher, target)
    return findings


async def _test_target(fetcher: Fetcher, target: ParamTarget) -> list[FindingCandidate]:
    baseline_res = await _send(fetcher, target, target.example)
    if not baseline_res.ok:
        return []
    base = analyze(baseline_res)
    base_raw = baseline_res.text

    out: list[FindingCandidate] = []
    applicable = sorted(
        [t for t in _TESTS if t.applies(target)],
        key=lambda t: priority(target, t), reverse=True,
    )
    for test in applicable:
        # Primary payload, then mutated variants until one produces evidence
        # (keeps it fast; stops at the first hit).
        for payload in test.payloads[:4]:
            res = await _send(fetcher, target, payload)
            if not res.ok:
                continue
            evidence = test.detect(payload, base_raw, res.text)
            if evidence:
                out.append(
                    _finding(
                        target, test, payload, evidence, "potential", base, analyze(res)
                    )
                )
                break
    return out


async def _open_redirect(fetcher: Fetcher, target: ParamTarget) -> list[FindingCandidate]:
    if target.location != "query" or target.name.lower() not in _REDIRECTISH:
        return []
    marker = "https://external.invalid/wf-redirect"
    res = await _send(fetcher, target, marker)
    if not res.ok or res.status_code not in (301, 302, 303, 307, 308):
        return []
    location = res.headers.get("location", "")
    if "external.invalid" in location:
        return [
            FindingCandidate(
                title="Open redirect (query)",
                category="input_validation",
                severity="medium",
                confidence="confirmed",
                url=target.url,
                parameter=target.name,
                evidence=f"Location: {location}",
                request_summary=f"GET {target.url} [{target.name}={marker}]",
                response_summary=f"HTTP {res.status_code} -> {location}",
                description=f"The '{target.name}' parameter controls the "
                "redirect destination without validation.",
                impact="",
                remediation="",
                dedup_key=f"open_redirect|{urlsplit(target.url).path}|{target.name}",
            )
        ]
    return []


def _finding(target, test, payload, evidence, confidence, base, analyzed):
    loc = target.location
    return FindingCandidate(
        title=f"{test.name} ({loc})",
        category=test.category,
        severity=test.severity,
        confidence=confidence,
        url=target.url,
        method=target.method,
        parameter=target.name,
        evidence=str(evidence)[:300],
        request_summary=f"{target.method} {target.url} [{loc}:{target.name}={payload[:40]}]",
        response_summary=f"HTTP {analyzed.status_code}; baseline HTTP {base.status_code}",
        description=f"The '{target.name}' {loc} parameter shows an indicator "
        f"for {test.name.lower()}.",
        impact="",  # Groq assigns impact from evidence.
        remediation="",
        dedup_key=f"{test.dedup_prefix}|{urlsplit(target.url).path}|{loc}:{target.name}",
    )


async def _hpp_test(fetcher: Fetcher, target: ParamTarget) -> list[FindingCandidate]:
    """HTTP Parameter Pollution: compare single vs duplicate parameter. Only
    query parameters; conservative reporting."""
    if target.location != "query":
        return []
    single = await _send(fetcher, target, "WFA")
    if not single.ok:
        return []
    # Build a duplicated-parameter URL: ?name=WFA&name=WFB
    parts = urlsplit(target.url)
    q = parse_qs(parts.query, keep_blank_values=True)
    q.pop(target.name, None)
    base_q = urlencode(q, doseq=True)
    dup_q = (base_q + "&" if base_q else "") + f"{target.name}=WFA&{target.name}=WFB"
    dup_url = urlunsplit((parts.scheme, parts.netloc, parts.path or "/", dup_q, ""))
    dup = await fetcher.fetch(dup_url, follow_redirects=False, use_cache=False)
    if not dup.ok:
        return []

    a, b = analyze(single), analyze(dup)
    # Only flag when the duplicate meaningfully changes behaviour AND one of
    # the injected values is reflected (a security-relevant signal).
    reflects_b = "WFB" in dup.text
    if meaningfully_different(a, b) and reflects_b:
        return [
            FindingCandidate(
                title="HTTP parameter pollution",
                category="input_validation",
                severity="low",
                confidence="potential",
                url=target.url,
                parameter=target.name,
                evidence=f"Duplicate '{target.name}' changed the response; "
                "second value reflected.",
                request_summary=f"GET {dup_url}",
                response_summary=f"single HTTP {a.status_code} vs dup HTTP {b.status_code}",
                description="Sending the parameter twice produced a different, "
                "value-dependent response.",
                impact="",
                remediation="",
                dedup_key=f"hpp|{parts.path}|{target.name}",
            )
        ]
    return []
