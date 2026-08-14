from types import SimpleNamespace

import app.services.subdomain_takeover as st
from app.services.test_status import TestStatus
from fixtures import FakeFetcher, ok_result


def _sub(hostname):
    return SimpleNamespace(hostname=hostname)


async def test_dangling_cname_plus_signature_is_vulnerable(monkeypatch):
    async def fake_cname(hostname):
        return ["myapp.github.io"]
    monkeypatch.setattr(st, "_cname_chain", fake_cname)
    fetcher = FakeFetcher(lambda u, **kw: ok_result(u, text="There isn't a GitHub Pages site here."))
    results = await st.check_subdomain_takeover([_sub("gone.example.com")], fetcher)
    assert results and results[0][0] == TestStatus.VULNERABLE
    assert results[0][1].confidence == "confirmed"


async def test_provider_cname_without_signature_is_inconclusive(monkeypatch):
    async def fake_cname(hostname):
        return ["myapp.github.io"]
    monkeypatch.setattr(st, "_cname_chain", fake_cname)
    fetcher = FakeFetcher(lambda u, **kw: ok_result(u, text="<html>a real claimed site</html>"))
    results = await st.check_subdomain_takeover([_sub("claimed.example.com")], fetcher)
    assert results and results[0][0] == TestStatus.INCONCLUSIVE


async def test_no_provider_cname_yields_nothing(monkeypatch):
    async def fake_cname(hostname):
        return ["some-internal-lb.example.com"]
    monkeypatch.setattr(st, "_cname_chain", fake_cname)
    fetcher = FakeFetcher(lambda u, **kw: ok_result(u, text="anything"))
    results = await st.check_subdomain_takeover([_sub("x.example.com")], fetcher)
    assert results == []
