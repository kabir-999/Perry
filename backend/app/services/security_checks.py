"""
Deterministic, non-destructive security checks.

Every function here inspects responses the scanner already has (or sends a
single, safe, crafted request) and returns ``FindingCandidate`` evidence.
Nothing here performs a destructive, brute-force-auth, or DoS action.

The LLM never invents evidence; these functions are the sole source of it.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from app.services.finding_types import FindingCandidate
from app.services.http_client import FetchResult, Fetcher
from app.services.response_analyzer import AnalyzedResponse, NotFoundProfile, analyze
from app.services.secret_redactor import redact_env_values, redact_json_secrets

# ---------------------------------------------------------------------------
# Passive checks (no extra requests)
# ---------------------------------------------------------------------------

SECURITY_HEADERS = {
    "content-security-policy": (
        "Content-Security-Policy",
        "Restricts sources of scripts/styles, mitigating XSS and injection.",
    ),
    "x-content-type-options": (
        "X-Content-Type-Options",
        "Prevents MIME-type sniffing (should be 'nosniff').",
    ),
    "x-frame-options": (
        "X-Frame-Options",
        "Mitigates clickjacking (or use CSP frame-ancestors).",
    ),
    "strict-transport-security": (
        "Strict-Transport-Security",
        "Forces HTTPS for future requests (HSTS).",
    ),
    "referrer-policy": (
        "Referrer-Policy",
        "Controls how much referrer information is shared.",
    ),
}


def _header_impact(missing: list[str]) -> str:
    """Describe what each missing header removes — without claiming an attack.

    A missing header is an absent mitigation. Saying "downgrade attack" states
    something the scanner did not observe, so each header is described in terms
    of the protection that is not present.
    """
    notes = {
        "Content-Security-Policy":
            "Without CSP, the browser applies no restriction on where scripts "
            "may load from, so an injection flaw elsewhere would be less "
            "contained.",
        "Strict-Transport-Security":
            "Without Strict-Transport-Security, browsers that have not "
            "previously received an HSTS policy may be more exposed to HTTPS "
            "downgrade or first-connection interception scenarios. No such "
            "interception was observed.",
        "X-Frame-Options":
            "Without X-Frame-Options (or CSP frame-ancestors), the page may be "
            "framed by another site.",
        "X-Content-Type-Options":
            "Without X-Content-Type-Options: nosniff, browsers may guess a "
            "response's type rather than trusting the declared one.",
        "Referrer-Policy":
            "Without Referrer-Policy, full URLs may be sent to third-party "
            "sites in the Referer header.",
    }
    lines = [notes[m] for m in missing if m in notes]
    return (
        "These are defence-in-depth headers; their absence is not itself an "
        "exploitable vulnerability. " + " ".join(lines)
    )


def check_security_headers(result: FetchResult) -> list[FindingCandidate]:
    """One finding per response summarising missing headers. HSTS is only
    expected on HTTPS origins, so it is skipped for http targets."""
    if not result.ok:
        return []
    scheme = urlparse(result.url).scheme
    missing = []
    for key, (label, _) in SECURITY_HEADERS.items():
        if key == "strict-transport-security" and scheme != "https":
            continue
        if key not in result.headers:
            missing.append(label)
    if not missing:
        return []
    severity = "medium" if len(missing) >= 3 else "low"
    # Dedup by the *set* of missing headers, not the path — a whole site
    # usually shares the same missing headers, so this collapses what would
    # otherwise be one near-identical finding per page into a single one.
    missing_key = ",".join(sorted(missing))
    return [
        FindingCandidate(
            title=f"Missing security headers ({len(missing)})",
            category="security_headers",
            severity=severity,
            confidence="confirmed",
            url=result.url,
            evidence="Missing: " + ", ".join(missing),
            response_summary=f"HTTP {result.status_code}; headers present: "
            + ", ".join(sorted(result.headers.keys()))[:400],
            request_summary=(
                f"final_url={result.url}"
                + (f"; redirects={len(result.redirects)}" if result.redirects else "")
            ),
            description="Responses are missing recommended security "
            "response headers.",
            impact=_header_impact(missing),
            remediation="Add the missing headers: " + ", ".join(missing) + ".",
            dedup_key=f"security_headers|{missing_key}",
        )
    ]


def check_server_disclosure(result: FetchResult) -> list[FindingCandidate]:
    findings = []
    for header in ("server", "x-powered-by", "x-aspnet-version"):
        value = result.headers.get(header, "")
        # Only flag when a version number is disclosed.
        if value and re.search(r"\d+\.\d+", value):
            findings.append(
                FindingCandidate(
                    title=f"Version disclosure via {header} header",
                    category="information_exposure",
                    severity="low",
                    confidence="confirmed",
                    url=result.url,
                    evidence=f"{header}: {value}",
                    response_summary=f"{header}: {value}",
                    description="The server advertises software and version "
                    "information in response headers.",
                    impact="Helps an attacker match the target to known "
                    "vulnerabilities for that exact version.",
                    remediation=f"Suppress or genericise the '{header}' header.",
                    dedup_key=f"version_disclosure|{header}",
                )
            )
    return findings


# Cookie name patterns for context-aware severity.
_SESSION_COOKIE_RE = re.compile(
    r"(?i)(sess|sid|auth|token|jwt|csrf|xsrf|login|remember|phpsessid|"
    r"jsessionid|connect\.sid|asp\.net)"
)
_TRACKING_COOKIE_RE = re.compile(
    r"(?i)(^_ga|^_gid|^_gat|utm|^_fbp|^_hj|mixpanel|amplitude|^ajs|optimizely)"
)


def _cookie_context(name: str) -> str:
    if _SESSION_COOKIE_RE.search(name):
        return "session"
    if _TRACKING_COOKIE_RE.search(name):
        return "tracking"
    return "unknown"


def check_insecure_cookies(result: FetchResult) -> list[FindingCandidate]:
    set_cookie = result.headers.get("set-cookie", "")
    if not set_cookie:
        return []
    lowered = set_cookie.lower()
    name = set_cookie.split("=", 1)[0].strip()
    missing = [
        attr for attr in ("secure", "httponly", "samesite") if attr not in lowered
    ]
    if not missing:
        return []

    context = _cookie_context(name)
    # Severity follows what we actually know about the cookie's role.
    #
    # Medium requires evidence that this is a session/authentication cookie,
    # because that is what makes a missing HttpOnly/Secure attribute
    # consequential. For a cookie whose purpose we cannot determine we do not
    # know that anything sensitive is in it, so the finding stays Low and says
    # so — rather than assuming the worst case and reporting Medium.
    if context == "session":
        severity = "medium" if ("httponly" in missing or "secure" in missing) else "low"
    else:
        severity = "low"

    if context == "session":
        title = "Session cookie set without security attributes"
        description = (
            "A cookie whose name identifies it as a session or authentication "
            "cookie was set without one or more of the Secure, HttpOnly, and "
            "SameSite attributes."
        )
        impact = (
            "Session cookies without HttpOnly can be read by injected "
            "JavaScript; without Secure they can leak over plaintext; without "
            "SameSite they are sent on cross-site requests."
        )
    elif context == "tracking":
        title = "Analytics cookie missing security attributes"
        description = (
            "A cookie matching a known analytics/tracking vendor was set "
            "without one or more of the Secure, HttpOnly, and SameSite "
            "attributes."
        )
        impact = (
            "Tracking cookies do not normally carry credentials, so the "
            "practical impact is limited to the tracking data itself."
        )
    else:
        title = "Unknown cookie missing security attributes"
        description = (
            f"The cookie '{name}' was set without one or more of the Secure, "
            "HttpOnly, and SameSite attributes. The scanner could not determine "
            "what this cookie holds."
        )
        impact = (
            "Not established. The contents and purpose of this cookie are "
            "unknown, so whether the missing attributes matter depends on "
            "whether it carries anything sensitive. If it holds a session or "
            "identity token, treat this as Medium; if it holds a "
            "non-sensitive preference, the missing attributes are hardening "
            "only."
        )

    remediation = (
        "Set Secure, HttpOnly, and SameSite on session cookies."
        if context == "session"
        else "Confirm what this cookie stores. If it carries a session or any "
        "identifying token, set Secure, HttpOnly, and SameSite on it; if it "
        "only stores a non-sensitive preference, adding Secure and SameSite is "
        "still good practice."
    )

    return [
        FindingCandidate(
            title=title,
            category="configuration",
            severity=severity,
            confidence="confirmed",
            url=result.url,
            parameter=name[:256],
            evidence=(
                f"Cookie '{name}' missing: {', '.join(missing)}. "
                f"Role inferred from name: {context}"
                + (
                    " (purpose not determined)"
                    if context == "unknown"
                    else ""
                )
            ),
            response_summary=set_cookie[:200],
            description=description,
            impact=impact,
            remediation=remediation,
            dedup_key=f"insecure_cookie|{context}|{','.join(missing)}",
        )
    ]


def check_cors(result: FetchResult) -> list[FindingCandidate]:
    acao = result.headers.get("access-control-allow-origin", "")
    acac = result.headers.get("access-control-allow-credentials", "").lower()
    if acao == "*" and acac == "true":
        return [
            FindingCandidate(
                title="Permissive CORS with credentials",
                category="configuration",
                severity="high",
                confidence="confirmed",
                url=result.url,
                evidence="Access-Control-Allow-Origin: * with "
                "Access-Control-Allow-Credentials: true",
                response_summary=f"ACAO={acao}, ACAC={acac}",
                description="The endpoint allows any origin to make "
                "credentialed cross-origin requests.",
                impact="Any website can read authenticated responses from "
                "this endpoint on behalf of a logged-in victim.",
                remediation="Never combine a wildcard origin with "
                "credentialed CORS; echo an explicit allow-list instead.",
                dedup_key=f"cors|{urlparse(result.url).path}",
            )
        ]
    return []


_DIR_LISTING_RE = re.compile(r"Index of /|<title>Directory listing for",
                             re.IGNORECASE)


def check_directory_listing(
    analyzed: AnalyzedResponse, result: FetchResult
) -> list[FindingCandidate]:
    if analyzed.status_code == 200 and _DIR_LISTING_RE.search(result.text):
        return [
            FindingCandidate(
                title="Directory listing enabled",
                category="information_exposure",
                severity="medium",
                confidence="confirmed",
                url=result.url,
                evidence=_first_match(_DIR_LISTING_RE, result.text),
                response_summary=analyzed.visible_text[:200],
                description="The server returns an automatic listing of "
                "directory contents.",
                impact="Exposes file and directory names that may include "
                "backups, source, or data files.",
                remediation="Disable automatic directory indexing.",
                dedup_key=f"dir_listing|{urlparse(result.url).path}",
            )
        ]
    return []


_STACK_TRACE_PATTERNS = [
    (r"Traceback \(most recent call last\)", "Python traceback"),
    (r"at [\w.$]+\([\w./]+:\d+\)", "Java/JS stack frame"),
    (r"<b>(?:Fatal error|Warning)</b>:.*?on line \d+", "PHP error"),
    (r"Exception in thread", "JVM exception"),
    (r"System\.[\w.]+Exception", ".NET exception"),
    (r"ORA-\d{5}", "Oracle error"),
]
_STACK_TRACE_RE = [
    (re.compile(p, re.IGNORECASE | re.DOTALL), label)
    for p, label in _STACK_TRACE_PATTERNS
]


def check_debug_trace(
    analyzed: AnalyzedResponse, result: FetchResult
) -> list[FindingCandidate]:
    for regex, label in _STACK_TRACE_RE:
        match = regex.search(result.text)
        if match:
            return [
                FindingCandidate(
                    title="Stack trace / debug output exposed",
                    category="information_exposure",
                    severity="medium",
                    confidence="confirmed",
                    url=result.url,
                    evidence=match.group(0)[:300],
                    response_summary=f"HTTP {analyzed.status_code}; {label}",
                    description="The application returned a stack trace or "
                    "verbose error to the client.",
                    impact="Leaks file paths, framework internals, and "
                    "sometimes credentials, aiding further attacks.",
                    remediation="Disable debug mode in production and return "
                    "generic error pages.",
                    dedup_key=f"stack_trace|{urlparse(result.url).path}",
                )
            ]
    return []


_SQL_ERROR_PATTERNS = [
    r"SQL syntax.*?MySQL",
    r"Warning.*?\Wmysqli?_",
    r"unterminated quoted string",
    r"PostgreSQL.*?ERROR",
    r"psql:.*?ERROR",
    r"ORA-\d{5}",
    r"Microsoft OLE DB Provider for SQL Server",
    r"SQLite/JDBCDriver",
    r"sqlite3.OperationalError",
    r"SQLSTATE\[",
]
_SQL_ERROR_RE = re.compile("|".join(_SQL_ERROR_PATTERNS), re.IGNORECASE)

def check_sensitive_file_validated(
    result: FetchResult, path: str, not_found: NotFoundProfile
) -> list[FindingCandidate]:
    """Called for sensitive-path hits (e.g. /.env, /.git/config). Confirms
    by content, soft-404 profile, and redacts secrets."""
    if not result.ok or result.status_code != 200:
        return []
        
    analyzed = analyze(result)

    # 1. Soft-404 / SPA-fallback check. Passing the path lets the profile
    #    reject an HTML answer to a non-HTML file (/.env served as index.html).
    if not not_found.is_real_hit(analyzed, path):
        return []

    body = result.text.strip()
    if not body:
        return []

    # 2. HTML false-positive check
    # If it claims to be HTML and actually looks like HTML, it's likely a SPA fallback or custom 404
    is_html = "text/html" in result.content_type.lower()
    if is_html and ("<html" in body.lower() or "<body" in body.lower()):
        return []
        
    # 3. Content validation and secret redaction
    confidence = "low"
    evidence = ""
    severity = "high"
    
    if path.endswith(".git/config"):
        if "[core]" in body:
            confidence = "high"
            evidence = "[core] section found in git config."
    elif path.endswith(".env") or path.endswith(".env.local") or path.endswith(".env.production") or ".env" in path:
        # Check for KEY=value pairs
        lines = body.splitlines()
        kv_count = sum(1 for line in lines if "=" in line and not line.strip().startswith("#"))
        
        if kv_count >= 3:
            confidence = "high"
        elif kv_count > 0:
            confidence = "medium"
            
        redacted = redact_env_values(body)
        if "[REDACTED]" in redacted:
            confidence = "critical"
            severity = "critical"
            
        evidence = redacted[:200]
    elif path.endswith(".json"):
        if "{" in body and "}" in body:
            redacted = redact_json_secrets(body)
            if "[REDACTED]" in redacted:
                confidence = "critical"
                severity = "critical"
            elif '"' in body:
                confidence = "medium"
            evidence = redacted[:200]
    else:
        # Generic check for secrets
        redacted = redact_env_values(body)
        if "[REDACTED]" in redacted:
            confidence = "critical"
            severity = "critical"
            evidence = redacted[:200]
        else:
            evidence = body[:200]

    if confidence == "low":
        return []
        
    evidence_str = evidence.replace("\n", " ").strip()
        
    return [
        FindingCandidate(
            title=f"Sensitive file exposed: {path}",
            category="information_exposure",
            severity=severity,
            confidence="confirmed",
            url=result.url,
            evidence=evidence_str,
            response_summary=f"HTTP 200, {result.body_bytes} bytes",
            description=f"The sensitive path {path} is publicly reachable "
            "and returns configuration/secret-like content.",
            impact="Exposes credentials, source control metadata, or "
            "internal configuration.",
            remediation=f"Block public access to {path} and rotate any "
            "exposed secrets.",
            dedup_key=f"sensitive_file|{path}",
        )
    ]


# ---------------------------------------------------------------------------
# Active checks (one crafted request each; safe & non-destructive)
# ---------------------------------------------------------------------------

_XSS_MARKER = "wf7xq<z>'\""


async def check_reflected_xss(
    fetcher: Fetcher, url: str, param: str
) -> list[FindingCandidate]:
    """Inject a benign marker containing HTML metacharacters and check
    whether it is reflected unencoded. Does not execute anything."""
    probe = _with_param(url, param, _XSS_MARKER)
    result = await fetcher.fetch(probe, use_cache=False)
    if not result.ok or not result.text:
        return []
    # Reflected unescaped: the raw '<z>' survives in the body.
    if "<z>" in result.text and _XSS_MARKER in result.text:
        return [
            FindingCandidate(
                title="Reflected input without output encoding (possible XSS)",
                category="input_validation",
                severity="high",
                confidence="potential",
                url=url,
                method="GET",
                parameter=param,
                evidence=f"Marker {_XSS_MARKER!r} reflected with raw '<z>' "
                "in the HTML response.",
                request_summary=f"GET {probe}",
                response_summary=_context_around(result.text, "<z>"),
                description="User input in the '%s' parameter is reflected "
                "into the response without HTML encoding." % param,
                impact="May allow reflected cross-site scripting (XSS) if the "
                "reflection is in an executable HTML context.",
                remediation="Context-aware output encoding for all reflected "
                "user input; add a strict Content-Security-Policy.",
                dedup_key=f"reflected_xss|{urlparse(url).path}|{param}",
            )
        ]
    return []


_SQLI_PAYLOAD = "'"


async def check_sql_injection(
    fetcher: Fetcher, url: str, param: str
) -> list[FindingCandidate]:
    """Send a single quote and look for a database error signature. This is
    an *indicator* check — never a destructive query."""
    probe = _with_param(url, param, _SQLI_PAYLOAD)
    result = await fetcher.fetch(probe, use_cache=False)
    if not result.ok:
        return []
    match = _SQL_ERROR_RE.search(result.text)
    if match:
        return [
            FindingCandidate(
                title="SQL error triggered by crafted input (possible SQLi)",
                category="input_validation",
                severity="high",
                confidence="potential",
                url=url,
                method="GET",
                parameter=param,
                evidence=match.group(0)[:200],
                request_summary=f"GET {probe}",
                response_summary=f"HTTP {result.status_code}; DB error "
                "signature present.",
                description="Injecting a single quote into '%s' produced a "
                "database error message." % param,
                impact="Indicates the parameter may be vulnerable to SQL "
                "injection, risking data disclosure or modification.",
                remediation="Use parameterised queries / prepared statements "
                "and validate input; suppress DB errors from responses.",
                dedup_key=f"sqli|{urlparse(url).path}|{param}",
            )
        ]
    return []


_PASSWD_RE = re.compile(r"root:.*?:0:0:", re.MULTILINE)
_TRAVERSAL_PAYLOAD = "../../../../../../etc/passwd"
_PATHISH_PARAMS = (
    "file", "path", "page", "doc", "document", "template", "include",
    "download", "dir", "folder", "load", "read", "filename", "name",
)


async def check_path_traversal(
    fetcher: Fetcher, url: str, param: str
) -> list[FindingCandidate]:
    """Send a controlled, read-only traversal payload and look for
    passwd-shaped content. Never writes or deletes anything."""
    probe = _with_param(url, param, _TRAVERSAL_PAYLOAD)
    result = await fetcher.fetch(probe, use_cache=False)
    if not result.ok or not result.text:
        return []
    match = _PASSWD_RE.search(result.text)
    if not match:
        return []
    return [
        FindingCandidate(
            title="Path traversal indicator",
            category="input_validation",
            severity="high",
            confidence="potential",
            url=url,
            method="GET",
            parameter=param,
            evidence=match.group(0)[:120],
            request_summary=f"GET {probe}",
            response_summary=f"HTTP {result.status_code}; passwd-shaped content "
            "returned.",
            description="Injecting a directory-traversal sequence into the "
            "'%s' parameter returned content resembling /etc/passwd." % param,
            impact="May allow reading arbitrary files outside the web root, "
            "exposing source, configuration, or credentials.",
            remediation="Resolve and validate paths against an allow-list; "
            "never pass user input to filesystem APIs directly.",
            dedup_key=f"path_traversal|{urlparse(url).path}|{param}",
        )
    ]


def looks_pathish(param_name: str) -> bool:
    return param_name.lower() in _PATHISH_PARAMS


# Paths whose data is sensitive enough that serving it unauthenticated is a
# finding worth surfacing (Groq decides final severity).
_SENSITIVE_API_RE = re.compile(
    r"(?i)/(users?|accounts?|admin|config|settings|secrets?|keys?|tokens?|"
    r"orders?|payments?|invoices?|customers?|profiles?)(/|$|\?)"
)


async def check_api_security(
    fetcher: Fetcher, api_urls: list[str], *, max_endpoints: int = 15
) -> list[FindingCandidate]:
    """Safe, read-only checks over discovered API endpoints: insecure
    transport and sensitive data served without an auth challenge. Never
    attempts auth bypass, brute force, or access to another user's data."""
    findings: list[FindingCandidate] = []
    checked = 0
    for url in api_urls:
        if checked >= max_endpoints:
            break
        checked += 1
        res = await fetcher.fetch(url)
        if not res.ok:
            continue

        path = urlparse(res.url).path

        # Insecure transport for an API.
        if urlparse(res.url).scheme == "http":
            findings.append(
                FindingCandidate(
                    title="API served over plaintext HTTP",
                    category="configuration",
                    severity="medium",
                    confidence="confirmed",
                    url=res.url,
                    evidence="Endpoint reachable over http:// (no TLS).",
                    response_summary=f"HTTP {res.status_code}",
                    description="An API endpoint is served over unencrypted HTTP.",
                    impact="Requests and responses (including tokens) can be "
                    "intercepted on the network.",
                    remediation="Serve all API traffic over HTTPS and redirect "
                    "HTTP to HTTPS.",
                    dedup_key="api_insecure_transport",
                )
            )

        # Sensitive data returned without an auth challenge.
        is_json = "json" in res.content_type.lower()
        has_auth_challenge = (
            res.status_code in (401, 403)
            or "www-authenticate" in res.headers
        )
        if (
            res.status_code == 200
            and is_json
            and not has_auth_challenge
            and _SENSITIVE_API_RE.search(path)
            and res.body_bytes > 2
        ):
            findings.append(
                FindingCandidate(
                    title="Sensitive API endpoint accessible without authentication",
                    category="authentication",
                    severity="high",
                    confidence="potential",
                    url=res.url,
                    evidence=f"GET {path} returned 200 JSON ({res.body_bytes} "
                    "bytes) with no authentication challenge.",
                    response_summary=res.text[:300],
                    description="A sensitive-looking API endpoint returned data "
                    "without requiring authentication.",
                    impact="May expose user, account, or configuration data to "
                    "unauthenticated clients.",
                    remediation="Require authentication and authorization on "
                    "sensitive API endpoints.",
                    dedup_key=f"api_unauthenticated|{path}",
                )
            )
    return findings


async def check_open_redirect(
    fetcher: Fetcher, url: str, param: str
) -> list[FindingCandidate]:
    marker = "https://external.invalid/wf-redirect-test"
    probe = _with_param(url, param, marker)
    result = await fetcher.fetch(probe, follow_redirects=False, use_cache=False)
    if not result.ok or result.status_code not in (301, 302, 303, 307, 308):
        return []
    location = result.headers.get("location", "")
    if location.startswith(marker) or "external.invalid" in location:
        return [
            FindingCandidate(
                title="Open redirect",
                category="input_validation",
                severity="medium",
                confidence="confirmed",
                url=url,
                parameter=param,
                evidence=f"Location: {location}",
                request_summary=f"GET {probe}",
                response_summary=f"HTTP {result.status_code} -> {location}",
                description="The '%s' parameter controls the redirect target "
                "without validation." % param,
                impact="Enables phishing and OAuth token theft by redirecting "
                "victims to attacker-controlled sites.",
                remediation="Allow-list redirect destinations or use relative "
                "paths only.",
                dedup_key=f"open_redirect|{urlparse(url).path}|{param}",
            )
        ]
    return []


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _with_param(url: str, param: str, value: str) -> str:
    from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

    parts = urlsplit(url)
    query = parse_qs(parts.query, keep_blank_values=True)
    query[param] = [value]
    new_query = urlencode(query, doseq=True)
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path or "/", new_query, "")
    )


def _first_match(regex: re.Pattern, text: str) -> str:
    m = regex.search(text)
    return m.group(0)[:120] if m else ""


def _context_around(text: str, needle: str, width: int = 80) -> str:
    idx = text.find(needle)
    if idx < 0:
        return text[:160]
    start = max(0, idx - width)
    end = min(len(text), idx + len(needle) + width)
    return "…" + text[start:end].replace("\n", " ") + "…"


def run_passive_checks(
    result: FetchResult, analyzed: AnalyzedResponse | None = None
) -> list[FindingCandidate]:
    """Run every passive (no-extra-request) check on one response."""
    if not result.ok:
        return []
    analyzed = analyzed or analyze(result)
    findings: list[FindingCandidate] = []
    findings += check_security_headers(result)
    findings += check_server_disclosure(result)
    findings += check_insecure_cookies(result)
    findings += check_cors(result)
    findings += check_directory_listing(analyzed, result)
    findings += check_debug_trace(analyzed, result)
    return findings
