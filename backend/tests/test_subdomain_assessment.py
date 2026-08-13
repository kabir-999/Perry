from app.services import deep_scan
from app.services.response_analyzer import NotFoundProfile
from app.services.subdomain_scanner import DiscoveredSubdomain
from fixtures import FakeFetcher, error_result, ok_result


async def test_unreachable_subdomain_produces_no_finding(monkeypatch):
    """A DNS record alone is never a finding — an unreachable subdomain
    (resolves but nothing answers over HTTP/HTTPS) must be skipped, not
    reported as anything."""
    sub = DiscoveredSubdomain(hostname="dead.example.com", resolved_ip="10.0.0.1")

    called = {"learn_not_found": False}

    async def fake_learn(fetcher, origin):
        called["learn_not_found"] = True
        return NotFoundProfile()

    monkeypatch.setattr(deep_scan, "learn_not_found_profile", fake_learn)

    fetcher = FakeFetcher(lambda url, **kwargs: error_result(url))
    findings = await deep_scan._assess_subdomains(fetcher, [sub], passive_only=True)
    assert findings == []
    assert called["learn_not_found"] is False


async def test_reachable_subdomain_runs_passive_checks(monkeypatch):
    sub = DiscoveredSubdomain(hostname="app.example.com", resolved_ip="10.0.0.2")

    async def fake_learn(fetcher, origin):
        return NotFoundProfile()

    async def fake_discover_apis(fetcher, scope, not_found, links):
        return [], []

    monkeypatch.setattr(deep_scan, "learn_not_found_profile", fake_learn)
    monkeypatch.setattr(deep_scan, "discover_apis", fake_discover_apis)

    def responder(url, **kwargs):
        return ok_result(url, status_code=200, text="hello", headers={})

    fetcher = FakeFetcher(responder)
    findings = await deep_scan._assess_subdomains(fetcher, [sub], passive_only=True)
    # Missing-security-headers is expected from run_passive_checks on a bare
    # 200 response with none of the recommended headers set.
    assert any(f.category == "security_headers" for f in findings)


async def test_stops_once_shared_budget_is_exhausted(monkeypatch):
    subs = [DiscoveredSubdomain(hostname=f"s{i}.example.com", resolved_ip="10.0.0.1") for i in range(3)]

    async def fake_learn(fetcher, origin):
        raise AssertionError("must not run once budget is exhausted")

    monkeypatch.setattr(deep_scan, "learn_not_found_profile", fake_learn)

    fetcher = FakeFetcher(lambda url, **kwargs: ok_result(url), budget_exhausted=True)
    findings = await deep_scan._assess_subdomains(fetcher, subs, passive_only=True)
    assert findings == []
