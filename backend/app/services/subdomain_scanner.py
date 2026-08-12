"""
Lightweight subdomain discovery via DNS resolution.

Resolves a short wordlist of labels under the base domain concurrently.
Purely passive (DNS lookups only) and skipped for IP / loopback targets,
where subdomains are meaningless. Uses dnspython's async resolver.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass

import dns.asyncresolver
import dns.exception

from app.services.scope import TargetScope
from app.services.wordlists import SUBDOMAIN_WORDLIST


@dataclass
class DiscoveredSubdomain:
    hostname: str
    resolved_ip: str
    source: str = "dns_bruteforce"


async def discover_subdomains(
    scope: TargetScope, *, concurrency: int = 24, timeout: float = 1.5
) -> list[DiscoveredSubdomain]:
    if scope.is_ip or scope.is_loopback:
        return []
    # Sibling labels under a shared platform suffix belong to other tenants.
    if scope.is_shared_host:
        return []

    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout
    sem = asyncio.Semaphore(concurrency)
    base = scope.base_domain

    async def resolve(label: str) -> DiscoveredSubdomain | None:
        hostname = f"{label}.{base}"
        async with sem:
            try:
                answer = await resolver.resolve(hostname, "A")
            except (dns.exception.DNSException, Exception):
                return None
        ips = [r.address for r in answer]
        if not ips:
            return None
        return DiscoveredSubdomain(hostname=hostname, resolved_ip=ips[0])

    results = await asyncio.gather(*(resolve(l) for l in SUBDOMAIN_WORDLIST))
    return [r for r in results if r is not None]
