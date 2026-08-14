"""
Authentication surface discovery.

Detects, from what the crawlers already found, whether the target has an
authentication system at all and what shape it takes — never attempts to
log in, register, or otherwise interact with it. Feeds the "Authentication
/ Authorization: N/A" gap directly: a target with no detected login/session/
token surface should report `NOT_APPLICABLE` or `NOT_TESTED` honestly
rather than a misleading `PASS`.

Never attempts to access real users' accounts and never generates or
guesses credentials — this module only observes what is already present in
discovered pages/forms/network traffic.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.services.discovery_types import (
    DiscoveredForm,
    DiscoveredNetworkRequest,
    DiscoveredPath,
)

# Reuses the same session-cookie name shape security_checks.py already uses.
_SESSION_COOKIE_RE = re.compile(
    r"(?i)(sess|sid|auth|token|jwt|csrf|xsrf|login|remember|phpsessid|"
    r"jsessionid|connect\.sid|asp\.net)"
)

_LOGIN_PATH_RE = re.compile(r"(?i)(/log[-_]?in|/signin|/sign[-_]in|/session/?$|/auth(?!or))")
_REGISTER_PATH_RE = re.compile(r"(?i)(/register|/sign[-_]?up|/signup|/create[-_]?account)")
_LOGOUT_PATH_RE = re.compile(r"(?i)(/log[-_]?out|/signout|/sign[-_]out)")
_RESET_PATH_RE = re.compile(r"(?i)(/(password|pwd)[-_]?reset|/forgot[-_]?password)")

_PASSWORD_FIELD_RE = re.compile(r"(?i)pass(word)?")
_EMAIL_OR_USER_FIELD_RE = re.compile(r"(?i)(email|username|user[-_]?name|login)")

_BEARER_HEADER_RE = re.compile(r"(?i)^bearer\s+")
# Three dot-separated base64url segments — the JWT shape, not a decode/verify.
_JWT_SHAPE_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")


@dataclass
class AuthSurface:
    login_urls: set[str] = field(default_factory=set)
    register_urls: set[str] = field(default_factory=set)
    logout_urls: set[str] = field(default_factory=set)
    password_reset_urls: set[str] = field(default_factory=set)
    session_cookie_names: set[str] = field(default_factory=set)
    bearer_token_seen: bool = False
    jwt_shaped_tokens_seen: bool = False

    @property
    def has_auth_surface(self) -> bool:
        """True if the target appears to have *any* authentication system —
        used to decide NOT_TESTED vs. NOT_APPLICABLE for auth-related tests."""
        return bool(
            self.login_urls
            or self.session_cookie_names
            or self.bearer_token_seen
            or self.jwt_shaped_tokens_seen
        )


def _classify_form(form: DiscoveredForm, surface: AuthSurface) -> None:
    url = form.url
    if _LOGIN_PATH_RE.search(url):
        surface.login_urls.add(url)
        return
    if _REGISTER_PATH_RE.search(url):
        surface.register_urls.add(url)
        return
    if _LOGOUT_PATH_RE.search(url):
        surface.logout_urls.add(url)
        return
    if _RESET_PATH_RE.search(url):
        surface.password_reset_urls.add(url)
        return

    # Field-name heuristic: a POST form with both a password field and an
    # email/username field is a login form even if its action URL doesn't
    # say so (many SPAs post to a generic /rest/... endpoint).
    if form.method.upper() != "POST":
        return
    has_password = any(_PASSWORD_FIELD_RE.search(n) for n in form.params)
    has_identity = any(_EMAIL_OR_USER_FIELD_RE.search(n) for n in form.params)
    if has_password and has_identity:
        surface.login_urls.add(url)


def _scan_headers(headers: dict[str, str], surface: AuthSurface) -> None:
    auth = headers.get("authorization") or headers.get("Authorization")
    if auth and _BEARER_HEADER_RE.match(auth):
        surface.bearer_token_seen = True
        token = _BEARER_HEADER_RE.sub("", auth).strip()
        if _JWT_SHAPE_RE.match(token):
            surface.jwt_shaped_tokens_seen = True

    cookie_header = headers.get("cookie") or headers.get("Cookie") or ""
    for part in cookie_header.split(";"):
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        name = name.strip()
        value = value.strip()
        if _SESSION_COOKIE_RE.search(name):
            surface.session_cookie_names.add(name)
        if _JWT_SHAPE_RE.match(value):
            surface.jwt_shaped_tokens_seen = True


def detect_auth_surface(
    pages: list[DiscoveredPath],
    forms: list[DiscoveredForm],
    network_requests: list[DiscoveredNetworkRequest],
) -> AuthSurface:
    """Observes the discovered attack surface for login/register/logout/
    password-reset forms, session cookies, and bearer/JWT-shaped tokens.
    Purely observational — makes no requests of its own."""
    surface = AuthSurface()

    for page in pages:
        if _LOGIN_PATH_RE.search(page.url):
            surface.login_urls.add(page.url)
        elif _REGISTER_PATH_RE.search(page.url):
            surface.register_urls.add(page.url)
        elif _LOGOUT_PATH_RE.search(page.url):
            surface.logout_urls.add(page.url)
        elif _RESET_PATH_RE.search(page.url):
            surface.password_reset_urls.add(page.url)

    for form in forms:
        _classify_form(form, surface)

    for req in network_requests:
        if _LOGIN_PATH_RE.search(req.path):
            surface.login_urls.add(req.url)
        elif _REGISTER_PATH_RE.search(req.path):
            surface.register_urls.add(req.url)
        elif _LOGOUT_PATH_RE.search(req.path):
            surface.logout_urls.add(req.url)
        elif _RESET_PATH_RE.search(req.path):
            surface.password_reset_urls.add(req.url)

        _scan_headers(req.headers, surface)
        for set_cookie_value in (req.response_headers.get("set-cookie", ""),):
            if not set_cookie_value:
                continue
            name = set_cookie_value.split("=", 1)[0].strip()
            if _SESSION_COOKIE_RE.search(name):
                surface.session_cookie_names.add(name)

    return surface
