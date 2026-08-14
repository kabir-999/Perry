"""
Subdomain Takeover detection (detection-only, §19).

For each in-scope discovered subdomain: resolve its CNAME/A records and, when
it points at a known third-party service provider, fetch it and look for that
provider's "unclaimed service" signature (e.g. GitHub Pages' "There isn't a
GitHub Pages site here", S3's "NoSuchBucket"). A takeover is reported ONLY
when a dangling/provider-pointing record AND an unclaimed-service signature
both hold — otherwise INCONCLUSIVE. Never attempts to claim or register the
dangling service; this only observes.
"""
from __future__ import annotations

import asyncio

from app.services.debug_log import debug_log
from app.services.finding_types import FindingCandidate
from app.services.test_status import TestStatus

try:
    import dns.asyncresolver
    _DNS = True
except Exception:  # pragma: no cover
    _DNS = False

# Provider fingerprint: CNAME suffix → (service label, unclaimed-body signature).
# Signatures are the provider's own "no site here" pages — strong evidence the
# DNS record dangles at an unclaimed service.
_FINGERPRINTS: list[tuple[str, str, str]] = [
    ("github.io", "GitHub Pages", "There isn't a GitHub Pages site here"),
    ("herokudns.com", "Heroku", "No such app"),
    ("herokuapp.com", "Heroku", "No such app"),
    ("s3.amazonaws.com", "AWS S3", "NoSuchBucket"),
    ("amazonaws.com", "AWS S3", "NoSuchBucket"),
    ("cloudfront.net", "AWS CloudFront", "ERROR: The request could not be satisfied"),
    ("netlify.app", "Netlify", "Not Found - Request ID"),
    ("netlify.com", "Netlify", "Not Found - Request ID"),
    ("ghost.io", "Ghost", "The thing you were looking for is no longer here"),
    ("wordpress.com", "WordPress", "Do you want to register"),
    ("pantheonsite.io", "Pantheon", "The gods are wise"),
    ("fastly.net", "Fastly", "Fastly error: unknown domain"),
    ("zendesk.com", "Zendesk", "Help Center Closed"),
    ("readthedocs.io", "Read the Docs", "unknown to Read the Docs"),
    ("surge.sh", "Surge", "project not found"),
    ("bitbucket.io", "Bitbucket", "Repository not found"),
    ("azurewebsites.net", "Azure", "404 Web Site not found"),
    ("cloudapp.net", "Azure", "404 Web Site not found"),
]


async def _cname_chain(hostname: str) -> list[str]:
    if not _DNS:
        return []
    chain: list[str] = []
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 3.0
        answer = await resolver.resolve(hostname, "CNAME")
        for rdata in answer:
            chain.append(str(rdata.target).rstrip(".").lower())
    except Exception:
        pass
    return chain


async def check_subdomain_takeover(
    subdomains: list, fetcher
) -> list[tuple[str, FindingCandidate]]:
    """Returns a list of (status, FindingCandidate) — VULNERABLE only with
    both a provider-pointing record and its unclaimed-service signature;
    INCONCLUSIVE for a provider CNAME without a confirmed signature."""
    results: list[tuple[str, FindingCandidate]] = []
    for sub in subdomains:
        hostname = getattr(sub, "hostname", str(sub))
        cnames = await _cname_chain(hostname)
        provider = None
        for cname in cnames:
            for suffix, label, signature in _FINGERPRINTS:
                if cname.endswith(suffix):
                    provider = (label, signature, cname)
                    break
            if provider:
                break
        if provider is None:
            continue

        label, signature, cname = provider
        debug_log("TEST", f"subdomain_takeover: {hostname} → {cname} ({label})")
        body = ""
        status_code = None
        for scheme in ("https", "http"):
            try:
                res = await fetcher.fetch(f"{scheme}://{hostname}/", use_cache=False)
            except Exception:
                continue
            if res.ok:
                body = res.text or ""
                status_code = res.status_code
                break

        if signature.lower() in body.lower():
            debug_log("EVIDENCE", f"subdomain_takeover: {hostname} shows {label} unclaimed signature")
            results.append((TestStatus.VULNERABLE, FindingCandidate(
                title=f"Potential subdomain takeover ({label})",
                category="configuration",
                severity="high",
                confidence="confirmed",
                url=f"https://{hostname}/",
                evidence=(f"{hostname} has a dangling CNAME to {cname} ({label}) and the "
                          f"service returns its unclaimed-resource page: \"{signature}\"."),
                response_summary=f"HTTP {status_code}; matched {label} takeover signature.",
                description=(f"The subdomain {hostname} points (via CNAME {cname}) at {label}, "
                             "but that service has no claimed resource serving it — an attacker "
                             "who registers the resource there could serve content on this subdomain."),
                impact="An attacker could claim the dangling service and host arbitrary content "
                       "on a trusted subdomain (phishing, cookie theft, OAuth abuse).",
                remediation=f"Remove the dangling DNS record for {hostname}, or re-claim the "
                            f"resource at {label}.",
                reproducibility="Reproducible - resolve the CNAME and fetch the subdomain.",
                dedup_key=f"subdomain_takeover|{hostname}",
            )))
        else:
            results.append((TestStatus.INCONCLUSIVE, FindingCandidate(
                title=f"Subdomain points at {label} (takeover unconfirmed)",
                category="configuration",
                severity="low",
                confidence="uncertain",
                url=f"https://{hostname}/",
                evidence=(f"{hostname} has a CNAME to {cname} ({label}) but no unclaimed-service "
                          "signature was observed — the resource appears claimed."),
                dedup_key=f"subdomain_takeover|{hostname}",
            )))
    return results
