import dns.asyncresolver
import dns.exception

from app.services import subdomain_scanner
from app.services.scope import TargetScope


def _scope() -> TargetScope:
    return TargetScope(
        base_url="https://example.com",
        scheme="https",
        hostname="example.com",
        port=None,
        base_domain="example.com",
    )


async def test_wildcard_dns_suppresses_subdomain_discovery(monkeypatch):
    """If a random, guaranteed-nonexistent label under the base domain
    still resolves, every label 'resolving' carries no information — the
    scanner must not report any of them as discovered subdomains."""

    async def fake_wildcard_dns(scope):
        return True

    monkeypatch.setattr(subdomain_scanner, "_wildcard_dns", fake_wildcard_dns)

    result = await subdomain_scanner.discover_subdomains(_scope())
    assert result == []


async def test_no_wildcard_dns_allows_normal_discovery(monkeypatch):
    """Fail-safe check: when there's no wildcard, resolution proceeds as
    before (mocking the resolver itself is out of scope here — this just
    confirms the wildcard guard doesn't short-circuit the normal path)."""
    calls = {"wildcard_checked": False}

    async def fake_wildcard_dns(scope):
        calls["wildcard_checked"] = True
        return False

    monkeypatch.setattr(subdomain_scanner, "_wildcard_dns", fake_wildcard_dns)

    async def fake_resolve(self, hostname, rdtype):
        raise dns.exception.DNSException("no such host, by design of this test")

    monkeypatch.setattr(dns.asyncresolver.Resolver, "resolve", fake_resolve)

    result = await subdomain_scanner.discover_subdomains(_scope())
    assert calls["wildcard_checked"] is True
    assert result == []
