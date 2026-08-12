"""
Target scope: URL normalization, validation, and the in-scope predicate.

The user only ever types a URL. From that we derive everything: the base
target, the set of in-scope hostnames, and a predicate the crawler uses to
stay on-target. External links are recorded as references but never crawled.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse, urlunparse

# A hostname label / dotted host or a bare IP. Rejects spaces and other junk.
_VALID_HOST_RE = re.compile(
    r"^(?:localhost|"
    r"(?:\d{1,3}\.){3}\d{1,3}|"  # IPv4
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}|"  # dotted DNS
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"  # single label (e.g. an IP host)
    r")$"
)


class InvalidTargetError(ValueError):
    """Raised when a user-supplied URL cannot be turned into a target."""


def normalize_url(raw: str) -> str:
    """Normalize a user-entered URL.

    - adds a scheme (defaults to https) when omitted
    - lowercases the host, strips a trailing dot
    - drops fragments and default ports
    - ensures a path of at least "/"
    """
    if raw is None:
        raise InvalidTargetError("No URL provided.")
    candidate = raw.strip()
    if not candidate:
        raise InvalidTargetError("No URL provided.")

    if "://" not in candidate:
        candidate = "https://" + candidate

    parsed = urlparse(candidate)
    if parsed.scheme not in ("http", "https"):
        raise InvalidTargetError("Only http and https URLs are supported.")

    host = (parsed.hostname or "").rstrip(".").lower()
    if not host:
        raise InvalidTargetError("The URL is missing a hostname.")
    # Reject a host that isn't a valid IP or DNS name (spaces, junk, etc.).
    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        pass
    if not is_ip and not _VALID_HOST_RE.match(host):
        raise InvalidTargetError("That does not look like a valid website address.")

    # Rebuild netloc without default ports or credentials.
    netloc = host
    if parsed.port and not (
        (parsed.scheme == "http" and parsed.port == 80)
        or (parsed.scheme == "https" and parsed.port == 443)
    ):
        netloc = f"{host}:{parsed.port}"

    path = parsed.path or "/"
    return urlunparse((parsed.scheme, netloc, path, "", parsed.query, ""))


# Shared-hosting / PaaS suffixes. Every label under one of these belongs to a
# *different* customer, so `myapp.vercel.app` has no sibling hosts we may
# touch: admin.vercel.app is a stranger's app, not the target's admin panel.
# Treating these as public suffixes keeps scope, VHost probing, and subdomain
# enumeration off other tenants.
SHARED_HOSTING_SUFFIXES = {
    "vercel.app", "netlify.app", "netlify.com", "pages.dev", "workers.dev",
    "github.io", "gitlab.io", "herokuapp.com", "onrender.com", "render.com",
    "fly.dev", "railway.app", "up.railway.app", "azurewebsites.net",
    "appspot.com", "firebaseapp.com", "web.app", "cloudfunctions.net",
    "surge.sh", "glitch.me", "replit.app", "repl.co", "readthedocs.io",
    "amplifyapp.com", "elasticbeanstalk.com", "cloudfront.net",
    "s3-website.amazonaws.com", "ngrok.io", "ngrok-free.app", "trycloudflare.com",
    "vercel.sh", "now.sh", "deno.dev", "val.run", "streamlit.app",
    "pythonanywhere.com", "wixsite.com", "squarespace.com", "myshopify.com",
    "wordpress.com", "blogspot.com", "notion.site", "framer.website",
    "webflow.io", "bubbleapps.io", "godaddysites.com", "duckdns.org",
}

# Multi-label registry suffixes. Without these, `shop.example.co.uk` would
# reduce to a base domain of `co.uk` and put every UK site in scope.
_REGISTRY_SUFFIXES = {
    "co.uk", "org.uk", "me.uk", "ac.uk", "gov.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.za", "org.za", "net.za", "web.za",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "co.kr", "or.kr", "ne.kr", "go.kr",
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in",
    "com.br", "net.br", "org.br", "gov.br",
    "com.mx", "com.ar", "com.co", "com.pe", "com.tr", "com.cn", "com.tw",
    "com.hk", "com.sg", "com.my", "com.ph", "com.vn", "com.pk", "com.ng",
    "com.eg", "com.sa", "com.ua", "com.pl", "com.ru", "com.es", "com.it",
    "co.il", "co.id", "co.th", "or.id", "ac.id", "go.id",
    "gov.in", "nic.in", "res.in", "edu.pl", "gov.pl", "org.pl", "net.pl",
}

_PUBLIC_SUFFIXES = SHARED_HOSTING_SUFFIXES | _REGISTRY_SUFFIXES


def _public_suffix(hostname: str) -> str | None:
    """The longest known public suffix ``hostname`` sits under, if any."""
    best: str | None = None
    for suffix in _PUBLIC_SUFFIXES:
        if hostname == suffix or hostname.endswith("." + suffix):
            if best is None or len(suffix) > len(best):
                best = suffix
    return best


# Where a URL sits relative to the scan target.
SAME_ORIGIN = "SAME_ORIGIN"
SAME_SITE = "SAME_SITE"
EXTERNAL = "EXTERNAL"
OUT_OF_SCOPE = "OUT_OF_SCOPE"


def _registrable_suffix(hostname: str) -> str:
    """An eTLD+1 approximation good enough for scoping subdomains.

    We are not shipping the full public-suffix list, but we do carry the
    suffixes that matter for correctness: shared-hosting platforms and
    multi-label registry suffixes. Under a known suffix the registrable
    domain is that suffix plus one label (`myapp.vercel.app`,
    `example.co.uk`); otherwise the last two labels are used, which keeps
    `api.example.com` in scope for `example.com`.
    """
    labels = hostname.split(".")
    suffix = _public_suffix(hostname)
    if suffix is not None:
        if hostname == suffix:
            # The bare platform domain itself — nothing broader is in scope.
            return hostname
        take = len(suffix.split(".")) + 1
        return ".".join(labels[-take:])
    if len(labels) <= 2:
        return hostname
    return ".".join(labels[-2:])


def strip_public_suffix(hostname: str) -> str:
    """``hostname`` without its registry/platform suffix.

    ``myapp.vercel.app`` -> ``myapp``, ``shop.example.co.uk`` -> ``shop.example``,
    ``api.example.com`` -> ``api.example``. Used wherever the platform's own
    name would otherwise be mistaken for the site's name.
    """
    suffix = _public_suffix(hostname)
    if suffix is not None:
        if hostname == suffix:
            return ""
        return hostname[: -(len(suffix) + 1)]
    labels = hostname.split(".")
    return ".".join(labels[:-1]) if len(labels) > 1 else hostname


def is_shared_hosting_host(hostname: str) -> bool:
    """True when the host is a tenant on a shared platform, i.e. its sibling
    labels belong to unrelated owners."""
    suffix = _public_suffix(hostname)
    return suffix in SHARED_HOSTING_SUFFIXES if suffix else False


@dataclass
class TargetScope:
    """Immutable-ish description of what is in scope for one scan."""

    base_url: str
    scheme: str
    hostname: str
    port: int | None
    base_domain: str
    allowed_hosts: set[str] = field(default_factory=set)
    is_ip: bool = False
    is_loopback: bool = False
    # Tenant on a shared platform (*.vercel.app, *.github.io, ...). Sibling
    # hostnames belong to other customers, so host enumeration is meaningless
    # and must not run.
    is_shared_host: bool = False

    @property
    def origin(self) -> str:
        netloc = self.hostname
        if self.port:
            netloc = f"{self.hostname}:{self.port}"
        return f"{self.scheme}://{netloc}"

    def classify_origin(self, url: str) -> str:
        """Where a discovered URL sits relative to the target.

        A finding is only the target's responsibility when the evidence came
        from the target's own origin (or an in-scope sibling). A response from
        github.com or atlassian.net describes *that* service, no matter how the
        scanner arrived at it.
        """
        try:
            parts = urlparse(url)
        except ValueError:
            return OUT_OF_SCOPE
        host = (parts.hostname or "").rstrip(".").lower()
        if not host:
            return OUT_OF_SCOPE

        port = parts.port
        scheme = (parts.scheme or "").lower()
        if host == self.hostname:
            # Same host: an origin match also needs scheme and port to agree.
            same_port = (port or (443 if scheme == "https" else 80)) == (
                self.port or (443 if self.scheme == "https" else 80)
            )
            if scheme == self.scheme and same_port:
                return SAME_ORIGIN
            return SAME_SITE

        if host in self.allowed_hosts:
            return SAME_SITE
        if self.is_ip:
            return EXTERNAL
        if host == self.base_domain or host.endswith("." + self.base_domain):
            return SAME_SITE
        return EXTERNAL

    def contributes_to_risk(self, url: str) -> bool:
        """Only first-party evidence may move the target's risk score."""
        return self.classify_origin(url) in (SAME_ORIGIN, SAME_SITE)

    def in_scope(self, url: str) -> bool:
        """True if ``url`` is on an allowed host (same host, or a subdomain
        of the base domain). External hosts return False."""
        try:
            host = (urlparse(url).hostname or "").rstrip(".").lower()
        except ValueError:
            return False
        if not host:
            return False
        if host in self.allowed_hosts:
            return True
        if self.is_ip:
            return host == self.hostname
        return host == self.base_domain or host.endswith("." + self.base_domain)


def build_scope(raw_url: str) -> TargetScope:
    """Validate a user URL and derive the scan scope from it."""
    normalized = normalize_url(raw_url)
    parsed = urlparse(normalized)
    host = (parsed.hostname or "").lower()

    is_ip = False
    is_loopback = False
    try:
        ip = ipaddress.ip_address(host)
        is_ip = True
        is_loopback = ip.is_loopback
    except ValueError:
        is_loopback = host in ("localhost",)

    base_domain = host if is_ip else _registrable_suffix(host)

    return TargetScope(
        base_url=normalized,
        scheme=parsed.scheme,
        hostname=host,
        port=parsed.port,
        base_domain=base_domain,
        allowed_hosts={host},
        is_ip=is_ip,
        is_loopback=is_loopback,
        is_shared_host=not is_ip and is_shared_hosting_host(host),
    )
