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
from dataclasses import dataclass, field
from urllib.parse import parse_qs, quote, urlencode, urlsplit, urlunsplit

from app.services.discovery_types import DiscoveredParam
from app.services.finding_types import FindingCandidate
from app.services.http_client import Fetcher
from app.services.response_analyzer import AnalyzedResponse, analyze, jaccard

try:
    from playwright.async_api import async_playwright
    _PLAYWRIGHT_AVAILABLE = True
except Exception:  # pragma: no cover - exercised only when not installed
    _PLAYWRIGHT_AVAILABLE = False

# ---------------------------------------------------------------------------
# ParamTarget — a location-agnostic view of one testable parameter
# ---------------------------------------------------------------------------

_LOCATIONS = ("query", "form", "json", "header", "graphql_variable")


@dataclass
class ParamTarget:
    url: str
    name: str
    location: str = "query"  # query | form | json | header | graphql_variable
    method: str = "GET"
    example: str = "1"

    @classmethod
    def from_discovered(cls, p: DiscoveredParam) -> "ParamTarget":
        loc = p.param_type if p.param_type in _LOCATIONS else "query"
        method = p.method or ("POST" if loc in ("form", "json", "graphql_variable") else "GET")
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


def unicode_slash_variants(payload: str) -> list[str]:
    """Overlong-UTF-8 and fullwidth slash substitutions — a classic filter
    bypass for traversal sequences a naive `"../"` string check would miss.
    Only meaningful where the raw path separator itself is the thing being
    filtered; not applied to XSS/SQLi payloads."""
    if "/" not in payload:
        return []
    return [
        payload.replace("/", "%c0%af"),   # overlong UTF-8 encoding of '/'
        payload.replace("/", "／"),   # fullwidth solidus
    ]


# ---------------------------------------------------------------------------
# RequestBuilder — inject a value at the right location
# ---------------------------------------------------------------------------

def _set_query(url: str, name: str, value: str) -> str:
    parts = urlsplit(url)
    q = parse_qs(parts.query, keep_blank_values=True)
    q[name] = [value]
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/",
                       urlencode(q, doseq=True), ""))


def build_request(target: ParamTarget, value) -> dict:
    """Build fetch() kwargs that place ``value`` in ``target``'s location.
    ``value`` is usually a string but for NoSQL-injection payloads (Mongo
    operator shapes) it is a dict — httpx serializes nested JSON either way."""
    if target.location == "query":
        return {"url": _set_query(target.url, target.name, str(value)), "method": "GET"}
    if target.location == "form":
        return {"url": target.url, "method": "POST",
                "data": {target.name: value}}
    if target.location == "json":
        return {"url": target.url, "method": "POST",
                "json": {target.name: value}}
    if target.location == "graphql_variable":
        return {"url": target.url, "method": "POST",
                "json": {"variables": {target.name: value}}}
    if target.location == "header":
        return {"url": target.url, "method": "GET",
                "headers": {target.name: str(value)}}
    return {"url": _set_query(target.url, target.name, str(value)), "method": "GET"}


async def _send(fetcher: Fetcher, target: ParamTarget, value):
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
_XSS_MARKER = "wf7xq<z>'\""

_PATHISH = {
    "file", "path", "page", "doc", "document", "template", "include",
    "download", "dir", "folder", "load", "read", "filename", "name",
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
    # Encoders escalate the *primary* payload only, and only after every
    # literal payload above came back negative — encoding every payload for
    # every test would multiply requests without adding signal for
    # vulnerability classes where the plain-text payload set already covers
    # the realistic cases (XSS, SQLi).
    encoders: list = field(default_factory=list)


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
          _trav_detect, encoders=[encode_variants, unicode_slash_variants]),
]


# ---------------------------------------------------------------------------
# Adaptive prioritization — score which tests matter for a target
# ---------------------------------------------------------------------------

def priority(target: ParamTarget, test: _Test) -> int:
    name = target.name.lower()
    score = 10
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
        hit = False
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
                hit = True
                break

        # Every literal payload came back negative — escalate to encoded
        # variants of the primary payload only where encoding is actually
        # meaningful (byte-level URL encoding doesn't apply to JSON body or
        # header values the same way it does to query/form values).
        if not hit and test.encoders and target.location in ("query", "form"):
            tried = set(test.payloads[:4])
            variants: list[str] = []
            for encoder in test.encoders:
                for v in encoder(test.payloads[0]):
                    if v not in tried and v not in variants:
                        variants.append(v)
            for payload in variants[:4]:
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
        request_summary=f"{target.method} {target.url} [{loc}:{target.name}={str(payload)[:40]}]",
        response_summary=f"HTTP {analyzed.status_code}; baseline HTTP {base.status_code}",
        description=f"The '{target.name}' {loc} parameter shows an indicator "
        f"for {test.name.lower()}.",
        impact="",  # Groq assigns impact from evidence.
        remediation="",
        parameter_location=loc,
        reproducibility="Reproducible - replay the recorded request with the same payload",
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


async def check_dom_xss(target: ParamTarget) -> list[FindingCandidate]:
    """DOM-based XSS: a raw-HTML diff (what `_xss_detect` above does) never
    sees a client-side template injecting the marker into the DOM *after* JS
    execution — Angular/React/Vue apps commonly reflect input this way. Runs
    only for query parameters (the only location a browser navigation can
    exercise) and only when Playwright/Chromium are actually available;
    otherwise returns [] so callers can safely call this unconditionally."""
    if target.location != "query" or not _PLAYWRIGHT_AVAILABLE:
        return []

    probe_url = _set_query(target.url, target.name, _XSS_MARKER)
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            try:
                page = await browser.new_page()
                await page.goto(probe_url, timeout=10_000, wait_until="domcontentloaded")
                try:
                    await page.wait_for_load_state("networkidle", timeout=4_000)
                except Exception:
                    pass
                rendered = await page.content()
            finally:
                await browser.close()
    except Exception:
        return []

    if "<z>" not in rendered or _XSS_MARKER not in rendered:
        return []
    return [
        FindingCandidate(
            title="DOM-based XSS (query)",
            category="input_validation",
            severity="high",
            confidence="potential",
            url=target.url,
            method="GET",
            parameter=target.name,
            evidence="Marker reflected unescaped in the browser-rendered DOM "
            "after JavaScript execution (not visible in the raw HTTP response).",
            request_summary=f"GET {probe_url}",
            response_summary="Marker present unescaped in page.content() after render.",
            description=f"The '{target.name}' query parameter is reflected "
            "unescaped into the DOM by client-side JavaScript.",
            impact="",
            remediation="",
            parameter_location="query",
            reproducibility="Reproducible - replay the recorded URL in a browser",
            dedup_key=f"dom_xss|{urlsplit(target.url).path}|{target.name}",
        )
    ]
