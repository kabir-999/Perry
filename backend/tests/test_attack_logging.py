"""Structured JSON attack-log capture.

Every attack attempt — vulnerable, clean, skipped, inconclusive, or errored —
must produce a structured log record with a timestamp, a level, the attack
identity, and the machine-readable outcome. These tests pin that contract so
the UI's per-attack log boxes always have honest, production-shaped data.
"""
from app.services import attack_logger as alog
from app.services.attacks import catalog as C
from app.services.attacks.executor import AttackContext, execute_plan
from app.services.discovery_types import DiscoveredParam
from app.services.inventory import AttackSurfaceInventory
from app.services.test_planner import plan_tests
from app.services.test_status import TestStatus
from fixtures import FakeFetcher, ok_result

# Fields every emitted record must carry, whatever the outcome.
_REQUIRED = {"seq", "timestamp", "level", "attack", "attack_display", "event", "message"}


def _inv():
    inv = AttackSurfaceInventory()
    inv.add_discovered_param(
        DiscoveredParam(url="https://t/search?q=x", name="q", param_type="query", example_value="x")
    )
    return inv


async def test_vulnerable_and_clean_attacks_are_logged_with_levels():
    inv = _inv()
    plan = plan_tests(inv, passive_only=False)
    collector = alog.start_collector()

    def responder(u, **kw):
        # Trip the SQLi detector; everything else comes back benign.
        if "'" in u or "%27" in u:
            return ok_result(u, text="You have an error in your SQL syntax; MySQL")
        return ok_result(u, text="ok")

    ctx = AttackContext(fetcher=FakeFetcher(responder), inventory=inv, passive_only=False)
    await execute_plan(plan, ctx)

    records = collector.records
    assert records, "no attack log records were collected"
    # Every record carries the full production envelope.
    for rec in records:
        assert _REQUIRED.issubset(rec.keys())
        assert rec["level"] in alog.ALL_LEVELS
        assert rec["timestamp"].endswith("Z")

    # A start and a summary record exist for at least the SQLi attack.
    sqli = [r for r in records if r["attack"] == C.SQL_INJECTION]
    assert any(r["event"] == "attack_start" for r in sqli)
    assert any(r["event"] == "attack_summary" for r in sqli)

    # The vulnerability is logged at ALERT level with the VULNERABLE status.
    vuln = [r for r in sqli if r["status"] == TestStatus.VULNERABLE]
    assert vuln, "SQLi vulnerability was not logged"
    assert vuln[0]["level"] == alog.LEVEL_ALERT
    assert vuln[0]["event"] == "vulnerability_detected"

    # A clean attack (e.g. open redirect) is logged at SUCCESS level.
    clean = [r for r in records if r["status"] == TestStatus.NOT_VULNERABLE]
    assert clean and all(r["level"] == alog.LEVEL_SUCCESS for r in clean)


async def test_passive_scan_logs_every_attack_as_not_tested_warning():
    inv = _inv()
    plan = plan_tests(inv, passive_only=True)
    collector = alog.start_collector()
    ctx = AttackContext(
        fetcher=FakeFetcher(lambda u, **kw: ok_result(u, text="ok")),
        inventory=inv, passive_only=True,
    )
    await execute_plan(plan, ctx)

    skipped = [r for r in collector.records if r["status"] == TestStatus.NOT_TESTED]
    assert skipped, "passive scan produced no NOT_TESTED log records"
    assert all(r["level"] == alog.LEVEL_WARNING for r in skipped)
    assert all(r["event"] == "test_skipped" for r in skipped)


def test_log_attack_is_a_noop_without_a_collector():
    # No collector installed on this (sync) context — logging must not raise.
    alog._current.set(None)
    alog.log_attack(alog.LEVEL_INFO, C.XSS, "attack_start", "no collector here")
