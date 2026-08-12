"""
Controlled virtual-host (VHost) discovery.

Sends the same request to the target with different ``Host`` header values and
compares each response against a baseline. A candidate is reported only when
its response meaningfully differs (status, length bucket, or body fingerprint)
— a different response is a *potential* VHost, never a confirmed one.

Purely read-only GETs, bounded by the shared request budget/concurrency.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass

from app.services.http_client import Fetcher
from app.services.response_analyzer import NotFoundProfile, analyze
from app.services.scope import TargetScope
from app.services.wordlists import SUBDOMAIN_WORDLIST


@dataclass
class DiscoveredVHost:
    hostname: str
    status_code: int | None
    content_length: int
    differs: bool


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


async def discover_vhosts(
    fetcher: Fetcher,
    scope: TargetScope,
    *,
    extra_hosts: list[str] | None = None,
    not_found: NotFoundProfile | None = None,
) -> list[DiscoveredVHost]:
    # On a shared platform every sibling label is a different customer's app,
    # so "a different app answers for this Host" is guaranteed and means
    # nothing. Probing them would also test third parties we have no
    # authorization for.
    if scope.is_shared_host or scope.is_ip or scope.is_loopback:
        return []

    baseline = await fetcher.fetch(scope.origin)
    if not baseline.ok:
        return []
    baseline_analyzed = analyze(baseline)
    baseline_fp = baseline_analyzed.fingerprint
    baseline_len = baseline.body_bytes

    candidates = _candidate_hosts(scope, extra_hosts or [])

    async def probe(host: str) -> DiscoveredVHost | None:
        res = await fetcher.fetch(
            scope.origin, headers={"Host": host}, use_cache=False
        )
        if not res.ok:
            return None
        analyzed = analyze(res)
        # "Meaningfully different": different fingerprint AND a non-trivial
        # length delta, to avoid flagging boilerplate variations.
        differs = (
            analyzed.fingerprint != baseline_fp
            and abs(res.body_bytes - baseline_len) > 64
        )
        if not differs:
            return None
        # A wildcard host that lands on the site's catch-all page is not a
        # separate VHost, even when the shell renders at a slightly
        # different size.
        if not_found is not None and not not_found.is_real_hit(analyzed):
            return None
        return DiscoveredVHost(
            hostname=host,
            status_code=res.status_code,
            content_length=res.body_bytes,
            differs=True,
        )

    results = await asyncio.gather(*(probe(h) for h in candidates))
    return [r for r in results if r is not None]
