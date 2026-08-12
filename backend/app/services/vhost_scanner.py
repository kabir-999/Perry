"""
Controlled virtual-host (VHost) discovery.

Sending a different ``Host`` header and getting HTTP 200 proves almost nothing:
most edges answer 200 for *any* Host, wildcard DNS resolves every label, and
CDNs serve one default page to all of them. So a response that merely differs
from the primary host is not a virtual host — it is usually the catch-all.

This module establishes distinctness before reporting anything:

  * Two baselines are captured — the primary host, and a random label that
    cannot exist. Anything resembling the random baseline is the catch-all.
  * A second random label confirms the catch-all is *stable*; if the two
    random probes disagree, per-request variation makes comparison unreliable
    and we report nothing rather than guess.
  * Candidates that look like each other are grouped. A group of near-identical
    responses is one default application answering to many names, not many
    virtual hosts, so the group is collapsed instead of reported N times.
  * Only a response that differs from both baselines *and* from every other
    candidate group survives as a distinct application.

Environment type (dev/staging/admin/…) is never inferred from the hostname.
The label decides only what evidence to look for; the classification requires
corroboration in the response itself.

Purely read-only GETs, bounded by the shared request budget/concurrency.
"""
from __future__ import annotations

import asyncio
import re
import uuid
from dataclasses import dataclass, field

import dns.asyncresolver
import dns.exception

from app.services.http_client import Fetcher
from app.services.response_analyzer import AnalyzedResponse, analyze, jaccard
from app.services.scope import TargetScope
from app.services.wordlists import SUBDOMAIN_WORDLIST

# Two responses this similar are the same application.
_SAME_APP_THRESHOLD = 0.90
# Body sizes within this ratio are treated as the same page.
_SIZE_TOLERANCE = 0.05


@dataclass
class DiscoveredVHost:
    hostname: str
    status_code: int | None
    content_length: int
    differs: bool

    # Whether the response is a genuinely distinct application, having been
    # separated from both baselines and from the other candidates.
    distinct: bool = False
    # Environment type, set ONLY when the response corroborates it.
    environment: str = ""
    environment_evidence: list[str] = field(default_factory=list)
    title: str = ""
    server: str = ""
    redirect_to: str = ""
    resolves: bool = False
    wildcard_dns: bool = False
    # How many candidates shared this exact response shape.
    group_size: int = 1
    reason: str = ""


# Hostname labels worth *looking into*. The label alone never sets the
# environment — it only says which corroborating markers are worth checking.
_INTERESTING_LABELS = {
    "dev": "development",
    "development": "development",
    "staging": "staging",
    "stage": "staging",
    "test": "test",
    "testing": "test",
    "qa": "test",
    "uat": "staging",
    "admin": "administrative",
    "administrator": "administrative",
    "internal": "internal",
    "intranet": "internal",
    "private": "internal",
    "beta": "beta",
    "preprod": "staging",
    "sandbox": "test",
}

# Content that actually corroborates an environment claim.
_ENVIRONMENT_MARKERS: dict[str, list[tuple[str, str]]] = {
    "development": [
        (r"(?i)\bdevelopment\s+(?:environment|server|build)\b", "page states it is a development environment"),
        (r"(?i)\bdebug\s*(?:=|:)?\s*true\b", "debug flag enabled in page content"),
        (r"(?i)werkzeug\s+debugger|django\s+debug|symfony\s+profiler|laravel\s+telescope", "framework debug toolbar present"),
        (r"(?i)webpack-dev-server|vite\s+dev\s+server|hot\s+module\s+replacement", "development server banner"),
    ],
    "staging": [
        (r"(?i)\bstaging\s+(?:environment|server|site)\b", "page states it is a staging environment"),
        (r"(?i)\bpre-?production\b", "page identifies as pre-production"),
        (r"(?i)not\s+for\s+production|test\s+data\s+only", "explicit non-production notice"),
    ],
    "test": [
        (r"(?i)\btest\s+(?:environment|server|site)\b", "page states it is a test environment"),
        (r"(?i)\bsample\s+data\b|\bdummy\s+data\b", "test data notice"),
    ],
    "administrative": [
        (r"(?i)<title[^>]*>[^<]*\badmin(?:istration)?\b", "page title identifies an admin interface"),
        (r"(?i)\b(?:admin|administrator)\s+(?:login|panel|dashboard|console)\b", "admin interface wording"),
        (r"(?i)wp-admin|/administrator/|phpmyadmin|adminer", "known admin application path"),
    ],
    "internal": [
        (r"(?i)\binternal\s+(?:use\s+only|tool|portal|dashboard)\b", "page states it is internal-use"),
        (r"(?i)\bemployees?\s+only\b|\bstaff\s+portal\b", "staff-only wording"),
    ],
    "beta": [
        (r"(?i)\bbeta\s+(?:program|version|release|environment)\b", "page identifies as beta"),
        (r"(?i)\bearly\s+access\b", "early-access wording"),
    ],
}

_PASSWORD_FIELD = re.compile(r"""(?i)<input[^>]+type\s*=\s*["']?password""")
_ENV_HEADERS = ("x-environment", "x-env", "x-deployment", "x-vercel-deployment-url")


def _candidate_hosts(scope: TargetScope, extra: list[str]) -> list[str]:
    hosts: list[str] = []
    seen: set[str] = {scope.hostname}
    base = scope.base_domain
    for label in SUBDOMAIN_WORDLIST:
        h = f"{label}.{base}"
        if h not in seen:
            seen.add(h)
            hosts.append(h)
    for h in extra:
        if h and h not in seen:
            seen.add(h)
            hosts.append(h)
    return hosts[:15]


def _same_application(a: AnalyzedResponse, b: AnalyzedResponse) -> bool:
    """Whether two responses are the same application answering twice."""
    if a.status_code != b.status_code:
        return False
    if a.fingerprint and a.fingerprint == b.fingerprint:
        return True
    if jaccard(a.shingles, b.shingles) >= _SAME_APP_THRESHOLD:
        return True
    # Near-empty bodies defeat shingles; fall back to title + size.
    larger = max(a.length, b.length, 1)
    if a.title == b.title and abs(a.length - b.length) / larger <= _SIZE_TOLERANCE:
        return True
    return False


async def _wildcard_dns(scope: TargetScope) -> bool:
    """Does a label that cannot exist still resolve? Then DNS is a wildcard
    and 'the host resolves' carries no information."""
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 3.0
    resolver.timeout = 3.0
    probe = f"{uuid.uuid4().hex[:12]}.{scope.base_domain}"
    try:
        await resolver.resolve(probe, "A")
        return True
    except (dns.exception.DNSException, ValueError):
        return False


async def _resolves(resolver, hostname: str) -> bool:
    try:
        await resolver.resolve(hostname, "A")
        return True
    except (dns.exception.DNSException, ValueError):
        return False


def _environment_evidence(
    label: str, analyzed: AnalyzedResponse, body: str, headers: dict[str, str]
) -> tuple[str, list[str]]:
    """Corroborate (or refuse to corroborate) an environment type.

    The hostname label chooses which markers to look for; only markers found
    in the response itself can set the environment.
    """
    suspected = _INTERESTING_LABELS.get(label, "")
    if not suspected:
        return "", []

    evidence: list[str] = []
    haystack = f"{analyzed.title}\n{body[:120_000]}"

    for pattern, description in _ENVIRONMENT_MARKERS.get(suspected, []):
        if re.search(pattern, haystack):
            evidence.append(description)

    # A deployment/environment header is corroboration for any environment.
    for header in _ENV_HEADERS:
        value = headers.get(header, "")
        if value:
            evidence.append(f"{header}: {value[:60]}")

    # An authentication interface corroborates an admin/internal surface.
    if suspected in ("administrative", "internal") and _PASSWORD_FIELD.search(body):
        evidence.append("page presents a login form")

    if analyzed.status_code in (401, 403):
        evidence.append(f"host requires authentication (HTTP {analyzed.status_code})")

    return (suspected if evidence else ""), evidence[:4]


async def discover_vhosts(
    fetcher: Fetcher,
    scope: TargetScope,
    *,
    extra_hosts: list[str] | None = None,
    not_found=None,
) -> list[DiscoveredVHost]:
    """Find hostnames that serve a genuinely distinct application."""
    if scope.is_shared_host or scope.is_ip or scope.is_loopback:
        return []

    baseline = await fetcher.fetch(scope.origin)
    if not baseline.ok:
        return []
    primary = analyze(baseline)

    # Two impossible hostnames: the first defines the catch-all response, the
    # second proves the catch-all is stable enough to compare against.
    catch_all_probes = [
        f"{uuid.uuid4().hex[:12]}.{scope.base_domain}",
        f"{uuid.uuid4().hex[:12]}.{scope.base_domain}",
    ]
    probe_results = await asyncio.gather(
        *(
            fetcher.fetch(scope.origin, headers={"Host": h}, use_cache=False)
            for h in catch_all_probes
        ),
        return_exceptions=True,
    )
    catch_alls: list[AnalyzedResponse] = [
        analyze(r)
        for r in probe_results
        if not isinstance(r, Exception) and getattr(r, "ok", False)
    ]

    # If the two impossible hosts disagree, responses vary per request and no
    # comparison here would be trustworthy.
    if len(catch_alls) == 2 and not _same_application(catch_alls[0], catch_alls[1]):
        return []

    wildcard = await _wildcard_dns(scope)
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 3.0
    resolver.timeout = 3.0

    candidates = _candidate_hosts(scope, extra_hosts or [])

    async def probe(host: str):
        res = await fetcher.fetch(scope.origin, headers={"Host": host}, use_cache=False)
        if not res.ok:
            return None
        return host, res, analyze(res)

    probed = [p for p in await asyncio.gather(*(probe(h) for h in candidates)) if p]

    # ---- Separate genuinely distinct responses from the default application.
    survivors: list[tuple[str, object, AnalyzedResponse]] = []
    for host, res, analyzed in probed:
        if any(_same_application(analyzed, c) for c in catch_alls):
            continue  # the catch-all, wearing a different Host header
        if _same_application(analyzed, primary):
            continue  # the primary application, same app on another name
        if not_found is not None and not not_found.is_real_hit(analyzed):
            continue
        survivors.append((host, res, analyzed))

    # ---- Collapse candidates that are identical to each other. N hostnames
    # sharing one response are one fallback application, not N virtual hosts.
    groups: list[list[tuple[str, object, AnalyzedResponse]]] = []
    for item in survivors:
        for group in groups:
            if _same_application(item[2], group[0][2]):
                group.append(item)
                break
        else:
            groups.append([item])

    out: list[DiscoveredVHost] = []
    for group in groups:
        if len(group) > 1:
            # A shared default application. Not reported as virtual hosts —
            # recording it would mean claiming N environments that do not exist.
            continue

        host, res, analyzed = group[0]
        label = host.split(".")[0].lower()
        body = res.text or ""
        environment, evidence = _environment_evidence(
            label, analyzed, body, res.headers
        )

        resolves = await _resolves(resolver, host)
        redirect_to = res.redirects[-1][1] if res.redirects else ""

        out.append(
            DiscoveredVHost(
                hostname=host,
                status_code=analyzed.status_code,
                content_length=analyzed.length,
                differs=True,
                distinct=True,
                environment=environment,
                environment_evidence=evidence,
                title=analyzed.title[:200],
                server=res.headers.get("server", "")[:80],
                redirect_to=redirect_to[:200],
                resolves=resolves,
                wildcard_dns=wildcard,
                group_size=1,
                reason=(
                    f"Distinct from the primary host and from the catch-all "
                    f"response; {'environment corroborated' if evidence else 'no environment markers found'}."
                ),
            )
        )

    return out
