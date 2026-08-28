"""
Phase 2 active detectors.

New web-application vulnerability detectors that follow the same contract as
``security_checks``: each is an ``async`` function that takes a ``Fetcher``
(or FakeFetcher in tests), sends a bounded set of probes, analyses the
*response* for concrete evidence, and returns a list of ``FindingCandidate``.

Design rules (shared with Phase 1):
  * Detection is evidence-based, never "payload string was sent".
  * Every detector has a clear positive/negative boundary.
  * Nothing here executes OS commands or makes unbounded outbound requests;
    the callers decide scope.
"""
from __future__ import annotations

import ipaddress
import json
import uuid
import re
import statistics
import time
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

from app.services.finding_types import FindingCandidate
from app.services.http_client import Fetcher  # noqa: F401  (type reference)
from app.services.response_analyzer import analyze, jaccard
from app.services import security_checks


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _with_param(url: str, param: str, value: str) -> str:
    parts = urlsplit(url)
    query = parse_qs(parts.query, keep_blank_values=True)
    query[param] = [value]
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path or "/", urlencode(query, doseq=True), "")
    )


def _token(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def _path(url: str) -> str:
    return urlsplit(url).path or "/"


def _json_body(res) -> dict | None:
    try:
        data = json.loads(res.text)
        return data if isinstance(data, dict) else None
    except (ValueError, TypeError):
        return None


# --------------------------------------------------------------------------- #
# SSTI — Server-Side Template Injection
# --------------------------------------------------------------------------- #
# Two coprime factors whose product is unlikely to appear in an ordinary page
# by coincidence. Evaluation is proven by the PRODUCT appearing while the raw
# expression does NOT (i.e. the template engine computed it).
_SSTI_A, _SSTI_B = 7919, 7907  # both prime; product = 62_615_533
_SSTI_PRODUCT = str(_SSTI_A * _SSTI_B)


def _ssti_payloads() -> list[tuple[str, str]]:
    expr = f"{_SSTI_A}*{_SSTI_B}"
    return [
        ("{{" + expr + "}}", "jinja2/twig/nunjucks"),
        ("${" + expr + "}", "jsp-el/thymeleaf/freemarker"),
        ("<%= " + expr + " %>", "erb/ejs"),
        ("#{" + expr + "}", "ruby/thymeleaf"),
    ]


async def check_ssti(fetcher, url: str, param: str) -> list[FindingCandidate]:
    """Inject a harmless arithmetic template expression and confirm the engine
    evaluated it (product present, raw expression absent)."""
    expr = f"{_SSTI_A}*{_SSTI_B}"
    for payload, engine in _ssti_payloads():
        probe = _with_param(url, param, payload)
        res = await fetcher.fetch(probe, use_cache=False)
        if not res.ok or not res.text:
            continue
        if _SSTI_PRODUCT in res.text and expr not in res.text:
            return [
                FindingCandidate(
                    title="Server-side template injection",
                    category="input_validation",
                    severity="high",
                    confidence="confirmed",
                    url=url,
                    method="GET",
                    parameter=param,
                    evidence=(
                        f"Template expression {payload!r} evaluated to "
                        f"{_SSTI_PRODUCT} in the response (engine family: {engine})."
                    ),
                    request_summary=f"GET {probe}",
                    response_summary=f"HTTP {res.status_code}; rendered {_SSTI_PRODUCT}",
                    description=(
                        f"Input in '{param}' is evaluated by a server-side template "
                        "engine; a mathematical expression was computed server-side."
                    ),
                    impact="May lead to remote code execution via template sandbox escape.",
                    remediation="Never render user input as a template; use a sandboxed "
                    "engine and pass user data only as bound variables.",
                    dedup_key=f"ssti|{_path(url)}|{param}",
                )
            ]
    return []


# --------------------------------------------------------------------------- #
# SSRF — Server-Side Request Forgery (out-of-band callback oracle)
# --------------------------------------------------------------------------- #
_SSRF_PARAMS = {
    "url", "uri", "target", "destination", "redirect", "callback", "webhook",
    "image", "img", "src", "link", "fetch", "proxy", "endpoint", "feed", "dest",
}


def classify_ssrf_target(value: str) -> str:
    """external | internal | cloud_metadata — based on the destination host."""
    host = (urlsplit(value).hostname or "").lower()
    if not host:
        return "external"
    if host in {"169.254.169.254", "metadata.google.internal", "metadata"}:
        return "cloud_metadata"
    if host in {"localhost", "0.0.0.0"}:
        return "internal"
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return "internal"
    except ValueError:
        pass
    return "external"


def _is_ssrf_candidate(param: str, example: str) -> bool:
    if param.lower() in _SSRF_PARAMS:
        return True
    v = (example or "").lower()
    return v.startswith(("http://", "https://")) or v.startswith("//")


async def check_ssrf(
    fetcher, url: str, param: str, *,
    example: str = "",
    callback_base: str = "http://scanner-callback.internal",
    allow_internal: bool = False,
) -> list[FindingCandidate]:
    """Supply a unique scanner-controlled callback URL and confirm the server
    fetched it (its canary/token echoed back). Internal targets are opt-in."""
    if not _is_ssrf_candidate(param, example):
        return []
    token = _token("ssrf")
    callback = f"{callback_base}/{token}"
    probe = _with_param(url, param, callback)
    res = await fetcher.fetch(probe, use_cache=False)
    if not res.ok:
        return []
    interacted = token in res.text or "SSRF-FETCHED" in res.text
    if not interacted:
        return []
    target_class = classify_ssrf_target(callback)
    if target_class != "external" and not allow_internal:
        # Still a confirmed SSRF, but note internal reach was not exercised.
        target_class = "external"
    return [
        FindingCandidate(
            title="Server-side request forgery (SSRF)",
            category="input_validation",
            severity="high",
            confidence="confirmed",
            url=url,
            method="GET",
            parameter=param,
            evidence=(
                f"The application fetched the scanner callback {callback}; "
                f"token {token} was observed in the response (class: {target_class})."
            ),
            request_summary=f"GET {probe}",
            response_summary=f"HTTP {res.status_code}; server-side fetch confirmed",
            description=f"The '{param}' parameter causes the server to make an "
            "outbound HTTP request to an attacker-controlled URL.",
            impact="Enables access to internal services, cloud metadata, and "
            "blind interaction with internal networks.",
            remediation="Allow-list outbound hosts, resolve and validate targets, "
            "and block link-local/loopback/metadata ranges.",
            dedup_key=f"ssrf|{_path(url)}|{param}",
        )
    ]


# --------------------------------------------------------------------------- #
# NoSQL Injection (MongoDB-style operator / type confusion)
# --------------------------------------------------------------------------- #
def _auth_success(res) -> bool:
    if not res.ok:
        return False
    data = _json_body(res)
    if data is not None:
        if data.get("authenticated") is True or data.get("token") or data.get("success") is True:
            return True
        return False
    t = res.text.lower()
    return res.status_code == 200 and ("welcome" in t or '"authenticated": true' in t)


async def check_nosql_injection(
    fetcher, url: str, *,
    username_field: str = "username", password_field: str = "password",
    username: str = "admin",
) -> list[FindingCandidate]:
    """Compare a normal (wrong) login against an operator-injection login. If the
    operator payload authenticates where the plain wrong password does not, the
    query is being built from unsanitised object input."""
    wrong = await fetcher.fetch(
        url, method="POST",
        json={username_field: username, password_field: "wrong-" + _token("np")},
        use_cache=False,
    )
    inj = await fetcher.fetch(
        url, method="POST",
        json={username_field: username, password_field: {"$ne": None}},
        use_cache=False,
    )
    if not (wrong.ok and inj.ok):
        return []
    if _auth_success(inj) and not _auth_success(wrong):
        return [
            FindingCandidate(
                title="NoSQL injection (operator injection)",
                category="input_validation",
                severity="high",
                confidence="confirmed",
                url=url,
                method="POST",
                parameter=password_field,
                evidence=(
                    f"Authentication succeeded with {{\"{password_field}\": "
                    "{\"$ne\": null}} but failed with a plain wrong password."
                ),
                request_summary=f"POST {url} (json operator payload)",
                response_summary=f"operator HTTP {inj.status_code} authenticated; "
                f"plain HTTP {wrong.status_code} rejected",
                description="The endpoint builds a NoSQL query from unsanitised "
                "object input, allowing operator injection to bypass authentication.",
                impact="Authentication bypass and data exfiltration via query operators.",
                remediation="Reject non-string credential fields; cast inputs to the "
                "expected type before building queries.",
                dedup_key=f"nosqli|{_path(url)}",
            )
        ]
    return []


# --------------------------------------------------------------------------- #
# CRLF / HTTP response splitting
# --------------------------------------------------------------------------- #
_CRLF_MARKER = "phase2"


async def check_crlf(fetcher, url: str, param: str) -> list[FindingCandidate]:
    """Inject a CRLF sequence plus a harmless marker header and confirm the
    server emits it as a real response header (header splitting)."""
    injected = f"probe\r\nX-Scanner-Test: {_CRLF_MARKER}"
    probe = _with_param(url, param, injected)
    res = await fetcher.fetch(probe, use_cache=False)
    if not res.ok:
        return []
    got = (res.headers.get("x-scanner-test") or "").strip()
    if got == _CRLF_MARKER:
        return [
            FindingCandidate(
                title="CRLF injection / HTTP response splitting",
                category="input_validation",
                severity="medium",
                confidence="confirmed",
                url=url,
                method="GET",
                parameter=param,
                evidence=f"Injected header 'X-Scanner-Test: {_CRLF_MARKER}' appeared "
                "in the response headers.",
                request_summary=f"GET {probe}",
                response_summary=f"HTTP {res.status_code}; attacker header reflected",
                description=f"A CR/LF sequence in '{param}' is written into the "
                "response headers, letting an attacker inject headers.",
                impact="Enables response splitting, header injection, cache poisoning, "
                "and cookie manipulation.",
                remediation="Strip CR/LF from any user input used in headers; use a "
                "framework API that rejects control characters.",
                dedup_key=f"crlf|{_path(url)}|{param}",
            )
        ]
    return []


# --------------------------------------------------------------------------- #
# CSRF — state-changing request without anti-CSRF defences
# --------------------------------------------------------------------------- #
_STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}


async def check_csrf(
    fetcher, url: str, *, method: str = "POST",
    data: dict | None = None,
) -> list[FindingCandidate]:
    """Send a state-changing request with a forged cross-site Origin and no
    CSRF token. Flag only if it is accepted AND the session cookie lacks a
    SameSite policy (i.e. no defence-in-depth prevents the forgery)."""
    if method.upper() not in _STATE_CHANGING:
        return []  # safe methods are not CSRF-testable
    forged_origin = "https://evil.example"
    res = await fetcher.fetch(
        url, method=method.upper(),
        headers={"Origin": forged_origin, "Referer": forged_origin + "/"},
        data=data or {"email": "attacker@evil.example"},
        use_cache=False,
    )
    # A bare "non-error status" is a weak, false-positive-prone signal on
    # its own: many SPA/CDN edges (e.g. Netflix) return HTTP 200 with the
    # same page shell for *any* method on *any* route, regardless of
    # whether real backend logic ran — that is not evidence the POST did
    # anything, let alone something state-changing. 201/204 (created/no-
    # content) and a 302 whose Location differs from the request URL are
    # strong "this actually did something" signals on their own; a bare
    # 200 needs corroboration — a same-URL GET baseline distinguishes
    # "the server actually processed this and returned something distinct"
    # from "it just re-served the same page regardless of method."
    redirected_elsewhere = (
        res.status_code == 302
        and res.header("location")
        and res.header("location").rstrip("/") != url.rstrip("/")
    )
    accepted = res.ok and (res.status_code in (201, 204) or redirected_elsewhere)
    if not accepted and res.ok and res.status_code == 200:
        baseline = await fetcher.fetch(url, method="GET", use_cache=True)
        indistinguishable_from_baseline = (
            baseline.ok
            and baseline.status_code == res.status_code
            and abs(len(baseline.text) - len(res.text)) < max(50, 0.05 * max(len(baseline.text), 1))
        )
        accepted = not indistinguishable_from_baseline
    set_cookie = (res.headers.get("set-cookie") or "").lower()
    samesite_absent = ("samesite" not in set_cookie)
    if accepted and samesite_absent:
        return [
            FindingCandidate(
                title="Cross-site request forgery (CSRF)",
                category="configuration",
                severity="medium",
                confidence="potential",
                url=url,
                method=method.upper(),
                parameter="",
                evidence=(
                    f"State-changing {method.upper()} accepted with a cross-site "
                    f"Origin ({forged_origin}) and no anti-CSRF token; session "
                    "cookie has no SameSite attribute."
                ),
                request_summary=f"{method.upper()} {url} [Origin: {forged_origin}]",
                response_summary=f"HTTP {res.status_code}; request accepted",
                description="The endpoint performs a state-changing action without "
                "an anti-CSRF token, Origin validation, or a SameSite cookie.",
                impact="Allows an attacker site to perform actions as the victim.",
                remediation="Require a per-session CSRF token, validate Origin/Referer, "
                "and set SameSite=Lax or Strict on session cookies.",
                dedup_key=f"csrf|{_path(url)}",
            )
        ]
    return []


# --------------------------------------------------------------------------- #
# IDOR / BOLA — object-level authorization
# --------------------------------------------------------------------------- #
async def _get_resource(fetcher, url_template: str, ident: str, *,
                        location: str, param: str, auth_header: str):
    if location == "path":
        target = url_template.replace("{id}", str(ident))
    else:
        target = _with_param(url_template, param, str(ident))
    header_name, _, header_value = (auth_header or "").partition(":")
    headers = {header_name.strip(): header_value.strip()} if auth_header else None
    return await fetcher.fetch(target, headers=headers, use_cache=False), target


def _resource_owner(res) -> str | None:
    data = _json_body(res)
    if data is not None:
        owner = data.get("owner") or data.get("owner_id") or data.get("user")
        return str(owner) if owner is not None else None
    return None


async def check_idor(
    fetcher, url_template: str, *,
    auth_header_a: str, id_a: str, id_b: str,
    identity_a: str = "user_a",
    location: str = "path", param: str = "id",
) -> list[FindingCandidate]:
    """Authenticated as user A, request A's own object (baseline) and then B's
    object. Flag only if B's object is returned to A (owner != A)."""
    own, _ = await _get_resource(
        fetcher, url_template, id_a, location=location, param=param,
        auth_header=auth_header_a,
    )
    if not own.ok or own.status_code != 200:
        return []  # cannot establish an authenticated baseline
    if str(id_a) == str(id_b):
        return []  # accessing one's own resource is not IDOR
    other, target = await _get_resource(
        fetcher, url_template, id_b, location=location, param=param,
        auth_header=auth_header_a,
    )
    if other.status_code != 200 or not other.ok:
        return []  # access correctly denied / not found
    owner = _resource_owner(other)
    if owner is not None and owner != identity_a:
        return [
            FindingCandidate(
                title="Broken object-level authorization (IDOR/BOLA)",
                category="authorization",
                severity="high",
                confidence="confirmed",
                url=target,
                method="GET",
                parameter=param if location != "path" else "id",
                evidence=(
                    f"Authenticated user '{identity_a}' accessed object '{id_b}' "
                    f"owned by '{owner}' (HTTP {other.status_code})."
                ),
                request_summary=f"GET {target} as {identity_a}",
                response_summary=f"HTTP {other.status_code}; returned {owner}'s object",
                description="Object identifiers are not checked against the "
                "authenticated user, so any user can read another user's objects.",
                impact="Horizontal privilege escalation and data exposure across accounts.",
                remediation="Enforce per-object ownership checks on every request; "
                "never trust a client-supplied object id alone.",
                dedup_key=f"idor|{_path(url_template)}",
            )
        ]
    return []


# --------------------------------------------------------------------------- #
# Stored XSS — multi-request persistence + unsafe rendering
# --------------------------------------------------------------------------- #
async def check_stored_xss(
    fetcher, submit_url: str, view_url: str, *,
    field: str = "comment", method: str = "POST",
) -> list[FindingCandidate]:
    """Submit a unique marker that carries HTML metacharacters, then fetch the
    view. Confirmed only when the marker is both persisted AND rendered with a
    raw '<z>' (unescaped); escaped persistence is not reported as exploitable."""
    token = _token("xss_phase2")
    marker = f"{token}<z>"
    await fetcher.fetch(submit_url, method=method.upper(), data={field: marker}, use_cache=False)
    view = await fetcher.fetch(view_url, use_cache=False)
    if not view.ok or not view.text:
        return []
    persisted = token in view.text
    executable = marker in view.text and "<z>" in view.text
    if persisted and executable:
        return [
            FindingCandidate(
                title="Stored (persistent) cross-site scripting",
                category="input_validation",
                severity="high",
                confidence="confirmed",
                url=view_url,
                method="GET",
                parameter=field,
                evidence=f"Marker {marker!r} persisted from {submit_url} and was "
                "rendered unescaped (raw '<z>') at the view URL.",
                request_summary=f"{method.upper()} {submit_url} [{field}] -> GET {view_url}",
                response_summary="marker rendered with raw HTML metacharacters",
                description=f"Input to '{field}' is stored and later rendered without "
                "output encoding, executing in every viewer's browser.",
                impact="Persistent XSS affects all users who view the stored content.",
                remediation="Context-aware output encoding on render; add a strict CSP.",
                dedup_key=f"stored_xss|{_path(view_url)}|{field}",
            )
        ]
    return []


# --------------------------------------------------------------------------- #
# Expanded SQL injection — error / boolean / time based
# --------------------------------------------------------------------------- #
# Database-error fingerprints. Reported only when a signature actually matches.
_DB_SIGNATURES = [
    ("MySQL", re.compile(r"SQL syntax.*MySQL|check the manual that corresponds to your MySQL|"
                         r"Warning.*mysqli?_|MySqlException|valid MySQL result", re.I)),
    ("MariaDB", re.compile(r"MariaDB server version|check the manual that corresponds to your MariaDB", re.I)),
    ("PostgreSQL", re.compile(r"PostgreSQL.*ERROR|pg_query\(\)|PSQLException|"
                              r"unterminated quoted string at or near|syntax error at or near", re.I)),
    ("SQLite", re.compile(r"SQLite/JDBCDriver|sqlite3\.OperationalError|SQLite error|"
                          r"no such column|unrecognized token", re.I)),
    ("Microsoft SQL Server", re.compile(r"Microsoft OLE DB Provider for SQL Server|"
                                        r"SQLServer JDBC Driver|Unclosed quotation mark|"
                                        r"\bmssql_\w+\(", re.I)),
    ("Oracle", re.compile(r"\bORA-\d{5}\b|Oracle error|quoted string not properly terminated", re.I)),
]


def sql_database_family(text: str) -> str | None:
    """Best-effort DB family from an error string; None if no signature matches."""
    for name, rx in _DB_SIGNATURES:
        if rx.search(text or ""):
            return name
    return None


async def check_sqli_error(fetcher, url: str, param: str) -> list[FindingCandidate]:
    """Error-based SQLi. Sends the Phase 1 single-quote probe (reusing the
    shared error regex) and fingerprints the DB family from the *full* response
    text — reported only when a signature actually matches."""
    probe = _with_param(url, param, security_checks._SQLI_PAYLOAD)
    res = await fetcher.fetch(probe, use_cache=False)
    if not res.ok:
        return []
    m = security_checks._SQL_ERROR_RE.search(res.text or "")
    if not m:
        return []
    family = sql_database_family(res.text)
    evidence = m.group(0)[:200]
    if family:
        evidence = f"{evidence} [database: {family}]"
    return [
        FindingCandidate(
            title="SQL error triggered by crafted input (possible SQLi)",
            category="input_validation",
            severity="high",
            confidence="potential",
            url=url, method="GET", parameter=param,
            evidence=evidence,
            request_summary=f"GET {probe}",
            response_summary=f"HTTP {res.status_code}; DB error signature present"
            + (f"; family {family}" if family else ""),
            description=f"Injecting a single quote into '{param}' produced a database "
            "error message." + (f" Database family: {family}." if family else ""),
            impact="Indicates possible SQL injection risking data disclosure or modification.",
            remediation="Use parameterised queries and suppress DB errors from responses.",
            dedup_key=f"sqli|{_path(url)}|{param}",
        )
    ]


async def check_sqli_boolean(
    fetcher, url: str, param: str, *, example: str = "1", threshold: float = 0.9,
) -> list[FindingCandidate]:
    """Boolean-based blind SQLi: a always-true condition tracks the baseline
    while an always-false condition diverges. Similarity uses the shared
    response_analyzer shingles, not just length. ``threshold`` is configurable."""
    pairs = [
        (f"{example} AND 1=1", f"{example} AND 1=2"),
        (f"{example}' AND '1'='1", f"{example}' AND '1'='2"),
    ]
    base = analyze(await fetcher.fetch(_with_param(url, param, example), use_cache=False))
    if base.status_code is None:
        return []
    for true_pl, false_pl in pairs:
        tr = analyze(await fetcher.fetch(_with_param(url, param, true_pl), use_cache=False))
        fa = analyze(await fetcher.fetch(_with_param(url, param, false_pl), use_cache=False))
        if tr.status_code is None or fa.status_code is None:
            continue
        sim_bt = jaccard(base.shingles, tr.shingles)
        sim_bf = jaccard(base.shingles, fa.shingles)
        sim_tf = jaccard(tr.shingles, fa.shingles)
        # TRUE mirrors the baseline; FALSE diverges from both. A page that is
        # simply unstable (all three differ) or static (all three identical) is
        # not flagged.
        if sim_bt >= threshold and sim_tf < threshold and sim_bf < threshold:
            return [
                FindingCandidate(
                    title="Boolean-based blind SQL injection",
                    category="input_validation",
                    severity="high",
                    confidence="confirmed",
                    url=url, method="GET", parameter=param,
                    evidence=(
                        f"TRUE condition ({true_pl!r}) matched the baseline "
                        f"(sim={sim_bt:.2f}) while FALSE ({false_pl!r}) diverged "
                        f"(sim={sim_bf:.2f})."
                    ),
                    request_summary=f"GET {_with_param(url, param, true_pl)}",
                    response_summary=f"true~baseline={sim_bt:.2f}, false~baseline={sim_bf:.2f}",
                    description=f"The '{param}' parameter alters the SQL query's WHERE "
                    "clause: injected boolean conditions change the result set.",
                    impact="Blind data exfiltration one boolean at a time.",
                    remediation="Use parameterised queries; never concatenate input into SQL.",
                    dedup_key=f"sqli|{_path(url)}|{param}",
                )
            ]
    return []


async def _default_measure(fetcher, url, param, payload, clock):
    probe = _with_param(url, param, payload)
    t0 = clock()
    res = await fetcher.fetch(probe, use_cache=False)
    return res, (clock() - t0)


async def check_sqli_time(
    fetcher, url: str, param: str, *, example: str = "1",
    delay_seconds: float = 2.0, threshold: float = 1.5, samples: int = 2,
    clock=time.monotonic, measure=None,
) -> list[FindingCandidate]:
    """Time-based blind SQLi. Compares a zero-delay control against a delay
    payload over ``samples`` runs; conservative — a uniformly slow server does
    not trigger it because the *difference* must exceed ``threshold``.

    ``measure`` (async ``payload -> (response, elapsed)``) is injectable so unit
    tests need no real sleeping."""
    m = measure or (lambda pl: _default_measure(fetcher, url, param, pl, clock))
    control_pl = f"{example} AND SLEEP(0)"
    delay_pl = f"{example} AND SLEEP({delay_seconds})"
    control, delayed = [], []
    for _ in range(max(1, samples)):
        _, e = await m(control_pl)
        control.append(e)
    for _ in range(max(1, samples)):
        _, e = await m(delay_pl)
        delayed.append(e)
    diff = statistics.median(delayed) - statistics.median(control)
    if diff >= threshold:
        return [
            FindingCandidate(
                title="Time-based blind SQL injection",
                category="input_validation",
                severity="high",
                confidence="confirmed",
                url=url, method="GET", parameter=param,
                evidence=(
                    f"A SLEEP({delay_seconds}) payload delayed the response by "
                    f"{diff:.2f}s over the zero-delay control (threshold {threshold}s)."
                ),
                request_summary=f"GET {_with_param(url, param, delay_pl)}",
                response_summary=f"delay median={statistics.median(delayed):.2f}s, "
                f"control median={statistics.median(control):.2f}s",
                description=f"The '{param}' parameter injects into a SQL query where a "
                "timing function controls the response delay.",
                impact="Blind data exfiltration via response timing.",
                remediation="Use parameterised queries; never concatenate input into SQL.",
                dedup_key=f"sqli|{_path(url)}|{param}",
            )
        ]
    return []
