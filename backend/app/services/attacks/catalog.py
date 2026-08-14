"""
The canonical catalogue of the 12 in-scope attacks. This is the single
source of truth for attack identity used by the Test Planner, the attack
modules, coverage, and the report — nothing may add a 13th here without a
deliberate scope change.
"""
from __future__ import annotations

# --- MUST attacks ---
SQL_INJECTION = "sql_injection"
XSS = "xss"
PATH_TRAVERSAL = "path_traversal"
OPEN_REDIRECT = "open_redirect"
SECURITY_MISCONFIGURATION = "security_misconfiguration"
SENSITIVE_INFO_DISCLOSURE = "sensitive_info_disclosure"
AUTH = "authentication_authorization"

# --- ADVANCED attacks ---
API_AUTHENTICATION = "api_authentication"
HPP = "http_parameter_pollution"
FILE_UPLOAD = "file_upload"
VHOST_ISOLATION = "vhost_isolation"
SUBDOMAIN_TAKEOVER = "subdomain_takeover"

# --- Extended attacks (merged from the phase-2 detector suite) ---
COMMAND_INJECTION = "command_injection"
NOSQL_INJECTION = "nosql_injection"
SSRF = "ssrf"
SSTI = "ssti"
CSRF = "csrf"
CRLF = "crlf_injection"
STORED_XSS = "stored_xss"

# Ordered (MUST first, then ADVANCED, then EXTENDED) — the order the report renders.
MUST_ATTACKS = [
    SQL_INJECTION, XSS, PATH_TRAVERSAL, OPEN_REDIRECT,
    SECURITY_MISCONFIGURATION, SENSITIVE_INFO_DISCLOSURE, AUTH,
]
ADVANCED_ATTACKS = [
    API_AUTHENTICATION, HPP, FILE_UPLOAD, VHOST_ISOLATION, SUBDOMAIN_TAKEOVER,
]
EXTENDED_ATTACKS = [
    COMMAND_INJECTION, NOSQL_INJECTION, SSRF, SSTI, CSRF, CRLF, STORED_XSS,
]
ALL_ATTACKS = MUST_ATTACKS + ADVANCED_ATTACKS + EXTENDED_ATTACKS

DISPLAY_NAME = {
    SQL_INJECTION: "SQL Injection",
    XSS: "Cross-Site Scripting (XSS)",
    PATH_TRAVERSAL: "Path Traversal",
    OPEN_REDIRECT: "Open Redirect",
    SECURITY_MISCONFIGURATION: "Security Misconfiguration",
    SENSITIVE_INFO_DISCLOSURE: "Sensitive Information Disclosure",
    AUTH: "Authentication & Authorization",
    API_AUTHENTICATION: "API Authentication",
    HPP: "HTTP Parameter Pollution",
    FILE_UPLOAD: "File Upload",
    VHOST_ISOLATION: "VHost Isolation",
    SUBDOMAIN_TAKEOVER: "Subdomain Takeover",
    COMMAND_INJECTION: "Command Injection",
    NOSQL_INJECTION: "NoSQL Injection",
    SSRF: "Server-Side Request Forgery (SSRF)",
    SSTI: "Server-Side Template Injection (SSTI)",
    CSRF: "Cross-Site Request Forgery (CSRF)",
    CRLF: "CRLF Injection",
    STORED_XSS: "Stored XSS",
}

# Which attacks require the scanner to have authorized credentials to run the
# testing half (discovery still happens without them).
REQUIRES_CREDENTIALS = {AUTH}
