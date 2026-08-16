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
# ProbeRecorder — a log of every payload actually sent, whatever the result
# ---------------------------------------------------------------------------
# A finding is only produced when an attack succeeds, so the fact that a test
# passed (came back "not vulnerable") leaves no trace on its own. The recorder
# captures each attempt — success or negative — so the report can show what was
# tried and what happened, not just the hits. It is optional: when no recorder
# is passed the engine behaves exactly as before.

# Human-readable description of the signal each active test looks for, keyed by
# the test's dedup prefix. Shown in the probe log so a negative result reads as
# "this specific signal was checked and not seen", not just "nothing found".
_PROBE_SIGNAL = {
    "reflected_xss": "marker '<z>' reflected unescaped in the response body",
    "sqli": "database error signature (MySQL/PostgreSQL/Oracle/SQLite/MSSQL) not in baseline",
    "path_traversal": "/etc/passwd content ('root:...:0:0:') in the response",
    "cmd_injection": "OS command output ('uid=...gid=...') not in baseline",
    "open_redirect": "Location header redirects to the external marker host",
    "hpp": "duplicated parameter changed the response and the second value reflected",
}

# Short, human label per attack for the `finding` sentence in each probe entry.
_ATTACK_LABEL = {
    "reflected_xss": "reflected XSS",
    "sqli": "SQL injection",
    "path_traversal": "path traversal",
    "cmd_injection": "OS command injection",
    "open_redirect": "open redirect",
    "hpp": "HTTP parameter pollution",
}

# Stable, machine-readable case names per (attack, payload). Kept as string
# literals (not references to payload constants defined lower in this file) so
# the mapping is import-order independent. Unknown payloads fall back to a
# deterministic `<attack>_probe_<seq>` name.
_CASE_NAME = {
    ("cmd_injection", ";id"): "cmd_injection_semicolon",
    ("cmd_injection", "|id"): "cmd_injection_pipe",
    ("cmd_injection", "`id`"): "cmd_injection_backtick",
    ("cmd_injection", "$(id)"): "cmd_injection_command_substitution",
    ("sqli", "'"): "sqli_single_quote",
    ("sqli", "1'\""): "sqli_quote_pair",
    ("sqli", "1) OR ('1'='1"): "sqli_boolean_or",
    ("reflected_xss", "wf7xq<z>'\""): "xss_reflected_marker",
    ("path_traversal", "../../../../../../etc/passwd"): "path_traversal_etc_passwd",
    ("open_redirect", "https://external.invalid/wf-redirect"): "open_redirect_external_marker",
}


def _case_name(dedup_prefix: str, payload: str, seq: int) -> str:
    name = _CASE_NAME.get((dedup_prefix, payload))
    if name:
        return name
    if dedup_prefix == "hpp":
        return "hpp_duplicate_parameter"
    if dedup_prefix == "path_traversal":
        return f"path_traversal_encoded_{seq}"
    return f"{dedup_prefix}_probe_{seq}"


@dataclass
class ProbeRecorder:
    """Append-only log of active probes. Records the payload, where it was
    injected, the response status/size, and the verdict — for every attempt."""

    entries: list[dict] = field(default_factory=list)
    _seq: int = 0

    def record(self, *, dedup_prefix: str, target: "ParamTarget", payload: str,
               response, evidence, note: str = "") -> None:
        self._seq += 1
        ok = bool(response is not None and getattr(response, "ok", False))
        status = getattr(response, "status_code", None) if ok else None
        if ok:
            size = getattr(response, "body_bytes", None)
            if size is None:
                size = len(getattr(response, "text", "") or "")
        else:
            size = 0
        signal = _PROBE_SIGNAL.get(dedup_prefix, note or "test-specific signal")
        label = _ATTACK_LABEL.get(dedup_prefix, dedup_prefix)
        if evidence:
            verdict = "vulnerable"
            finding = f"{label} confirmed — {signal.split(' not in baseline')[0]} was observed"
        elif not ok:
            verdict = "error"
            finding = f"Request failed; {label} could not be evaluated"
        else:
            verdict = "not_vulnerable"
            finding = f"No {label} evidence; {signal} was not observed"
        self.entries.append({
            "seq": self._seq,
            # Stable, machine-readable case name (e.g. cmd_injection_pipe).
            "name": _case_name(dedup_prefix, payload or "", self._seq),
            "test": dedup_prefix,
            "location": target.location,
            "parameter": target.name,
            "method": target.method,
            "url": target.url,
            # The exact payload sent — kept visible so a finding is reproducible.
            "payload": (payload or "")[:120],
            "response_status": status,
            "response_bytes": size,
            # What the detector expected to see, vs whether it saw it.
            "signal_checked": signal,
            "signal_matched": bool(evidence),
            "verdict": verdict,
            # Concrete, evidence-backed sentence — never "possible vulnerability".
            "finding": finding,
            "evidence": (str(evidence)[:200] if evidence else None),
        })


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
# Windows system-file content (win.ini / boot.ini) — traversal evidence on
# Windows targets, the analogue of /etc/passwd on Unix.
_WININI = re.compile(r"\[fonts\]|\[extensions\]|\[mci extensions\]|for 16-bit app support", re.IGNORECASE)
_CMD_EVIDENCE = re.compile(
    r"uid=\d+\([^)]+\)\s+gid=\d+|/bin/(?:sh|bash):|command not found|"
    r"syntax error near unexpected token",
    re.IGNORECASE,
)
# A harmless, unique command-output canary (`echo CMDCANARY...`). Execution is
# proven when the canary appears WITHOUT the literal `echo ` prefix (i.e. the
# shell ran the echo), never merely because the payload string was reflected.
_CMD_CANARY = "CMDCANARY7f31b9"
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
    # Encoders escalate the *primary* payload only, and only after every
    # literal payload above came back negative — encoding every payload for
    # every test would multiply requests without adding signal for
    # vulnerability classes where the plain-text payload set already covers
    # the realistic cases (XSS, SQLi).
    encoders: list = field(default_factory=list)


# Detectors receive: payload, baseline raw text, test raw text.
def _xss_detect(payload, base_raw, test_raw, content_type=""):
    # A raw '<z>' surviving in the response body is only "reflected XSS" if a
    # browser would ever parse that body as HTML and act on it. An API that
    # replies with, say, a JSON validation error echoing the invalid input
    # back (FastAPI/Pydantic does this by default) contains the exact same
    # raw bytes, but application/json is never rendered as a document — the
    # markersits inert as a JSON string value, not markup. Gating on
    # content-type is what tells these apart; without it every JSON API
    # whose error messages happen to echo bad input reads as "vulnerable".
    if "html" not in content_type.lower():
        return None
    # Check the RAW response — the marker's angle brackets are stripped from
    # visible_text. A raw '<z>' that was NOT in the baseline means the injected
    # markup survived unescaped (an executable HTML context), regardless of
    # which breakout payload (HTML / attribute / tag / script) delivered it.
    if "<z>" in test_raw and "<z>" not in base_raw:
        return "marker '<z>' reflected unescaped in an executable HTML context"
    return None


def _sqli_detect(payload, base_raw, test_raw, content_type=""):
    if _SQL_ERR.search(test_raw) and not _SQL_ERR.search(base_raw):
        return _first(_SQL_ERR, test_raw)
    return None


def _trav_detect(payload, base_raw, test_raw, content_type=""):
    m = _PASSWD.search(test_raw)
    if m:
        return m.group(0)[:100]
    w = _WININI.search(test_raw)
    if w and not _WININI.search(base_raw):
        return f"Windows system-file content returned ({w.group(0)})"
    return None


def _cmd_detect(payload, base_raw, test_raw, content_type=""):
    if _CMD_EVIDENCE.search(test_raw) and not _CMD_EVIDENCE.search(base_raw):
        return _first(_CMD_EVIDENCE, test_raw)
    # Canary echoed as command OUTPUT (appears without the literal `echo `
    # prefix that a mere reflection of the payload would keep).
    if (
        _CMD_CANARY in test_raw
        and ("echo " + _CMD_CANARY) not in test_raw
        and _CMD_CANARY not in base_raw
    ):
        return f"command-output canary {_CMD_CANARY} echoed (execution confirmed)"
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
          _trav_detect, encoders=[encode_variants, unicode_slash_variants]),
    _Test("Command Injection", "input_validation", "cmd_injection", "high",
          lambda t: t.name.lower() in _CMDISH,
          [";id", "|id", "`id`", "$(id)"], _cmd_detect, encoders=[encode_variants]),
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
    recorder: "ProbeRecorder | None" = None,
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
        findings += await _test_target(fetcher, target, recorder=recorder)
        findings += await _hpp_test(fetcher, target, recorder=recorder)
        findings += await _open_redirect(fetcher, target, recorder=recorder)
    return findings


async def _test_target(
    fetcher: Fetcher, target: ParamTarget, *, recorder: "ProbeRecorder | None" = None
) -> list[FindingCandidate]:
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
            evidence = test.detect(payload, base_raw, res.text) if res.ok else None
            if recorder is not None:
                recorder.record(dedup_prefix=test.dedup_prefix, target=target,
                                payload=payload, response=res, evidence=evidence)
            if not res.ok:
                continue
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
                evidence = test.detect(payload, base_raw, res.text) if res.ok else None
                if recorder is not None:
                    recorder.record(dedup_prefix=test.dedup_prefix, target=target,
                                    payload=payload, response=res, evidence=evidence)
                if not res.ok:
                    continue
                if evidence:
                    out.append(
                        _finding(
                            target, test, payload, evidence, "potential", base, analyze(res)
                        )
                    )
                    break
    return out


async def _open_redirect(
    fetcher: Fetcher, target: ParamTarget, *, recorder: "ProbeRecorder | None" = None
) -> list[FindingCandidate]:
    if target.location != "query" or target.name.lower() not in _REDIRECTISH:
        return []
    marker = "https://external.invalid/wf-redirect"
    res = await _send(fetcher, target, marker)
    is_redirect = res.ok and res.status_code in (301, 302, 303, 307, 308)
    location = res.headers.get("location", "") if res.ok else ""
    evidence = f"Location: {location}" if (is_redirect and "external.invalid" in location) else None
    if recorder is not None:
        recorder.record(dedup_prefix="open_redirect", target=target, payload=marker,
                        response=res, evidence=evidence)
    if evidence:
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


async def _hpp_test(
    fetcher: Fetcher, target: ParamTarget, *, recorder: "ProbeRecorder | None" = None
) -> list[FindingCandidate]:
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
    hit = meaningfully_different(a, b) and reflects_b
    if recorder is not None:
        recorder.record(
            dedup_prefix="hpp", target=target,
            payload=f"{target.name}=WFA&{target.name}=WFB", response=dup,
            evidence=("duplicate changed response; second value reflected" if hit else None))
    if hit:
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
