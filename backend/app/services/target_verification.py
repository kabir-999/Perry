"""
Deployment ownership verification.

Active testing sends crafted payloads at a live host. Doing that to a target
the requester does not administer is unauthorized testing, so Sentinel proves
technical control first, by one of three standard challenges:

  DNS   a TXT record at ``_sentinel.<host>`` containing the token
  HTTP  a file at ``/.well-known/sentinel-verification.txt`` containing it
  META  a ``<meta name="sentinel-verification">`` tag on the homepage

Each requires write access to something only an administrator controls. Which
one is easiest depends on the host: a ``*.vercel.app`` subdomain has no DNS the
developer can edit, and some bundlers skip dot-directories when copying static
assets, so the meta tag is often the least friction. Neither
proves *legal* ownership — no scanner can — and the wording says so.

Until a target is VERIFIED, scans of it run in PASSIVE mode: ordinary requests
a browser would make, and nothing crafted.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import dns.asyncresolver
import dns.exception
import httpx

# Verification is re-checked periodically: control of a host can change hands.
VERIFICATION_TTL_DAYS = 90

DNS_PREFIX = "_sentinel"
META_NAME = "sentinel-verification"
HTTP_PATH = "/.well-known/sentinel-verification.txt"
TOKEN_FIELD = "sentinel-verification"

UNVERIFIED = "UNVERIFIED"
VERIFICATION_PENDING = "VERIFICATION_PENDING"
VERIFIED = "VERIFIED"
VERIFICATION_FAILED = "VERIFICATION_FAILED"
EXPIRED = "EXPIRED"

# Hosts that are inherently the developer's own machine: no verification is
# meaningful, and no third party can be harmed.
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


def generate_token() -> str:
    """A per-target nonce. Not a credential, but never logged."""
    return f"sentinel-{secrets.token_urlsafe(24)}"


def is_local_target(hostname: str) -> bool:
    host = (hostname or "").lower()
    if host in _LOCAL_HOSTS or host.endswith(".localhost"):
        return True
    try:
        import ipaddress

        ip = ipaddress.ip_address(host)
        return ip.is_loopback or ip.is_private
    except ValueError:
        return False


@dataclass
class VerificationResult:
    verified: bool
    method: str
    detail: str


def dns_instructions(hostname: str, token: str) -> dict:
    return {
        "method": "dns",
        "record_name": f"{DNS_PREFIX}.{hostname}",
        "record_type": "TXT",
        "record_value": f"{TOKEN_FIELD}={token}",
        "instruction": (
            f"Create a TXT record at {DNS_PREFIX}.{hostname} with the value "
            f"{TOKEN_FIELD}={token}, then press Verify. DNS changes can take a "
            "few minutes to propagate."
        ),
    }


def meta_instructions(hostname: str, token: str) -> dict:
    return {
        "method": "meta",
        "tag": f'<meta name="{META_NAME}" content="{token}">',
        "location": f"the <head> of https://{hostname}/",
        "instruction": (
            f"Add this tag to the <head> of your homepage (index.html), deploy, "
            "then press Verify. One line, no new files or directories."
        ),
    }


def http_instructions(hostname: str, token: str) -> dict:
    return {
        "method": "http",
        "url": f"https://{hostname}{HTTP_PATH}",
        "file_path": HTTP_PATH,
        "file_content": token,
        "instruction": (
            f"Publish a file at {HTTP_PATH} on {hostname} containing exactly "
            f"the token, then press Verify."
        ),
    }


async def verify_dns(hostname: str, token: str) -> VerificationResult:
    """Look for the token in a TXT record at _sentinel.<host>."""
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 8.0
    resolver.timeout = 8.0
    name = f"{DNS_PREFIX}.{hostname}"
    try:
        answer = await resolver.resolve(name, "TXT")
    except dns.exception.DNSException as exc:
        return VerificationResult(
            False, "dns",
            f"No TXT record found at {name} ({type(exc).__name__}).",
        )

    for record in answer:
        raw = b"".join(getattr(record, "strings", [])).decode("utf-8", "ignore")
        if not raw:
            raw = str(record).strip('"')
        if token in raw:
            return VerificationResult(True, "dns", f"Token found in TXT at {name}.")
    return VerificationResult(
        False, "dns", f"TXT record at {name} does not contain the expected token."
    )


async def verify_http(hostname: str, token: str) -> VerificationResult:
    """Look for the token in /.well-known/sentinel-verification.txt."""
    last = "Verification file could not be retrieved."
    for scheme in ("https", "http"):
        url = f"{scheme}://{hostname}{HTTP_PATH}"
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=8.0) as client:
                res = await client.get(url)
        except httpx.HTTPError as exc:
            last = f"Could not fetch {url} ({type(exc).__name__})."
            continue
        if res.status_code != 200:
            last = f"{url} returned HTTP {res.status_code}."
            continue
        if token in (res.text or "")[:4096]:
            return VerificationResult(True, "http", f"Token found at {url}.")
        last = f"{url} did not contain the expected token."
    return VerificationResult(False, "http", last)


_META_RE_TEMPLATE = (
    r"""<meta[^>]+name\s*=\s*["']?{name}["']?[^>]*content\s*=\s*["']([^"']+)["']"""
    r"""|<meta[^>]+content\s*=\s*["']([^"']+)["'][^>]*name\s*=\s*["']?{name}["']?"""
)


async def verify_meta(hostname: str, token: str) -> VerificationResult:
    """Look for the token in a <meta> tag on the homepage.

    Attribute order varies between frameworks and minifiers, so both orderings
    are accepted.
    """
    import re

    pattern = re.compile(
        _META_RE_TEMPLATE.format(name=re.escape(META_NAME)), re.IGNORECASE
    )
    last = "Homepage could not be retrieved."
    for scheme in ("https", "http"):
        url = f"{scheme}://{hostname}/"
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
                res = await client.get(url)
        except httpx.HTTPError as exc:
            last = f"Could not fetch {url} ({type(exc).__name__})."
            continue
        if res.status_code != 200:
            last = f"{url} returned HTTP {res.status_code}."
            continue
        for match in pattern.finditer(res.text or ""):
            content = match.group(1) or match.group(2) or ""
            if token in content:
                return VerificationResult(True, "meta", f"Token found in a meta tag at {url}.")
        last = (
            f"No <meta name=\"{META_NAME}\"> tag containing the token was found "
            f"at {url}. If your app renders the tag client-side, it will not be "
            "visible here — use the file method instead."
        )
    return VerificationResult(False, "meta", last)


async def run_verification(
    hostname: str, token: str, method: str
) -> VerificationResult:
    if method == "dns":
        return await verify_dns(hostname, token)
    if method == "http":
        return await verify_http(hostname, token)
    if method == "meta":
        return await verify_meta(hostname, token)
    return VerificationResult(False, method, "Unknown verification method.")


def expiry_from(now: datetime | None = None) -> datetime:
    return (now or datetime.now(timezone.utc)) + timedelta(days=VERIFICATION_TTL_DAYS)


def is_active_testing_allowed(target) -> tuple[bool, str]:
    """Whether active testing may run against this target, and why not."""
    if target is None:
        return False, (
            "Target verification required. Sentinel scans applications that you "
            "own or are authorized to test. Verify this deployment before "
            "starting an active security scan."
        )
    if target.verification_status != VERIFIED:
        return False, (
            f"Target is {target.verification_status}. Complete verification "
            "before starting an active security scan."
        )
    expires = target.verification_expires_at
    if expires is not None:
        now = datetime.now(timezone.utc)
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires < now:
            return False, "Verification has expired; re-verify this deployment."
    return True, ""
