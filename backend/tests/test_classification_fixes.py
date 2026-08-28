"""Regression tests for the classification overhaul: an anomaly/observation
must never automatically become VULNERABLE without attack-specific,
security-impact evidence. Covers the three modules that previously conflated
"something was observed/different" with "this is exploitable":
HPP, VHost Isolation, and Security Misconfiguration (missing headers)."""
from app.services.attacks.modules import (
    run_hpp,
    run_security_misconfiguration,
    run_vhost_isolation,
)
from app.services.finding_types import FindingCandidate
from app.services.inventory import AttackSurfaceInventory
from app.services.test_planner import PlannedTest
from app.services.test_status import TestStatus
from fixtures import FakeFetcher, ok_result


def _ctx(inv, **kw):
    from app.services.attacks.executor import AttackContext
    return AttackContext(fetcher=kw.pop("fetcher", None), inventory=inv, **kw)


# --------------------------------------------------------------------------
# VHost Isolation — a discovered distinct hostname is not itself proof of an
# isolation failure.
# --------------------------------------------------------------------------

async def test_vhost_isolation_never_vulnerable_from_passive_discovery_alone():
    inv = AttackSurfaceInventory()
    ep = inv.add_endpoint("https://example.com/")
    finding = FindingCandidate(
        title="Exposed staging surface detected at staging.example.com",
        category="attack_surface", severity="low", confidence="confirmed",
        url="staging.example.com", dedup_key="vhost|staging.example.com",
    )
    ctx = _ctx(inv, passive_findings=[finding], vhosts=[object()])
    plan = [PlannedTest(test_id="t1", attack="vhost_isolation", endpoint_id=ep.endpoint_id)]

    out = await run_vhost_isolation(plan, ctx)

    assert out[0].status != TestStatus.VULNERABLE
    assert out[0].status == TestStatus.INCONCLUSIVE


async def test_vhost_isolation_not_applicable_when_no_vhosts_discovered():
    inv = AttackSurfaceInventory()
    ep = inv.add_endpoint("https://example.com/")
    ctx = _ctx(inv, passive_findings=[], vhosts=[])
    plan = [PlannedTest(test_id="t1", attack="vhost_isolation", endpoint_id=ep.endpoint_id)]

    out = await run_vhost_isolation(plan, ctx)

    assert out[0].status == TestStatus.NOT_APPLICABLE


# --------------------------------------------------------------------------
# Security Misconfiguration — missing headers/cookie attributes are a real,
# confirmed hardening gap, not an exploit; CORS/dir-listing findings still
# count as VULNERABLE (actual demonstrated exposure).
# --------------------------------------------------------------------------

async def test_missing_headers_is_hardening_not_vulnerable():
    inv = AttackSurfaceInventory()
    ep = inv.add_endpoint("https://example.com/")
    finding = FindingCandidate(
        title="Missing security headers (4)", category="security_headers",
        severity="low", confidence="confirmed", url="https://example.com/",
        dedup_key="security_headers|CSP,Referrer-Policy,X-Frame-Options,Permissions-Policy",
    )
    ctx = _ctx(inv, passive_findings=[finding])
    plan = [PlannedTest(test_id="t1", attack="security_misconfiguration", endpoint_id=ep.endpoint_id)]

    out = await run_security_misconfiguration(plan, ctx)

    assert out[0].status == TestStatus.HARDENING
    assert out[0].status != TestStatus.VULNERABLE


async def test_directory_listing_exposure_remains_vulnerable():
    inv = AttackSurfaceInventory()
    ep = inv.add_endpoint("https://example.com/")
    finding = FindingCandidate(
        title="Directory listing enabled", category="configuration",
        severity="medium", confidence="confirmed", url="https://example.com/uploads/",
        dedup_key="dir_listing|/uploads/",
    )
    ctx = _ctx(inv, passive_findings=[finding])
    plan = [PlannedTest(test_id="t1", attack="security_misconfiguration", endpoint_id=ep.endpoint_id)]

    out = await run_security_misconfiguration(plan, ctx)

    assert out[0].status == TestStatus.VULNERABLE


# --------------------------------------------------------------------------
# HPP — a bare response diff + reflection is a real but unproven observation
# (POTENTIAL/INCONCLUSIVE); only a demonstrated security-control bypass
# (status-code transition) earns VULNERABLE.
# --------------------------------------------------------------------------

def _hpp_inv():
    inv = AttackSurfaceInventory()
    from app.services.discovery_types import DiscoveredParam
    inv.add_discovered_param(DiscoveredParam(
        url="https://example.com/hpp?id=1", name="id", param_type="query", example_value="1",
    ))
    return inv


async def test_hpp_bare_diff_is_inconclusive_not_vulnerable():
    def responder(url, **kwargs):
        vals = url.count("id=")
        if vals > 1:
            return ok_result(url, text="Effective id: WFB. Duplicate detected.")
        return ok_result(url, text="Effective id: WFA.")

    inv = _hpp_inv()
    from app.services.test_planner import plan_tests
    from app.services.attacks import catalog as C
    plan = [p for p in plan_tests(inv, passive_only=False) if p.attack == C.HPP]
    ctx = _ctx(inv, fetcher=FakeFetcher(responder), passive_only=False)

    out = await run_hpp(plan, ctx)

    assert out and out[0].status != TestStatus.VULNERABLE
    assert out[0].status == TestStatus.INCONCLUSIVE


async def test_hpp_security_control_bypass_is_vulnerable():
    def responder(url, **kwargs):
        vals = url.count("id=")
        if vals > 1:
            return ok_result(url, status_code=200, text="Effective id: WFB. Access granted.")
        return ok_result(url, status_code=403, text="Forbidden")

    inv = _hpp_inv()
    from app.services.test_planner import plan_tests
    from app.services.attacks import catalog as C
    plan = [p for p in plan_tests(inv, passive_only=False) if p.attack == C.HPP]
    ctx = _ctx(inv, fetcher=FakeFetcher(responder), passive_only=False)

    out = await run_hpp(plan, ctx)

    assert out and out[0].status == TestStatus.VULNERABLE
    assert out[0].confidence == "confirmed"
