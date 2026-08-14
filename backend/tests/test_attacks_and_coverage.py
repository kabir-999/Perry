from app.services.attacks import catalog as C
from app.services.attacks.executor import AttackContext, execute_plan
from app.services.coverage import build_test_matrix, compute_coverage, per_attack_coverage
from app.services.discovery_types import DiscoveredParam
from app.services.inventory import AttackSurfaceInventory
from app.services.test_planner import plan_tests
from app.services.test_status import TestStatus
from fixtures import FakeFetcher, ok_result


def _inv():
    inv = AttackSurfaceInventory()
    inv.add_discovered_param(DiscoveredParam(url="https://t/search?q=x", name="q", param_type="query", example_value="x"))
    return inv


async def test_sqli_fires_on_db_error_and_records_matrix_and_coverage():
    inv = _inv()
    plan = plan_tests(inv, passive_only=False)

    def responder(u, **kw):
        if "'" in u or "%27" in u:
            return ok_result(u, text="You have an error in your SQL syntax; MySQL")
        return ok_result(u, text="ok")

    ctx = AttackContext(fetcher=FakeFetcher(responder), inventory=inv, passive_only=False)
    execs = await execute_plan(plan, ctx)

    sqli = [e for e in execs if e.attack == C.SQL_INJECTION]
    assert any(e.status == TestStatus.VULNERABLE for e in sqli)
    matrix = build_test_matrix(execs, inv)
    assert any(r["attack"] == C.SQL_INJECTION and r["status"] == TestStatus.VULNERABLE for r in matrix)
    pac = per_attack_coverage(plan, execs)
    assert pac[C.SQL_INJECTION]["vulnerable"] >= 1
    assert pac[C.SQL_INJECTION]["eligible"] == 1


async def test_passive_only_marks_active_attacks_not_tested():
    inv = _inv()
    plan = plan_tests(inv, passive_only=True)
    ctx = AttackContext(fetcher=FakeFetcher(lambda u, **kw: ok_result(u, text="ok")),
                        inventory=inv, passive_only=True)
    execs = await execute_plan(plan, ctx)
    sqli = [e for e in execs if e.attack == C.SQL_INJECTION]
    assert sqli and all(e.status == TestStatus.NOT_TESTED for e in sqli)


async def test_clean_target_is_not_vulnerable_not_silent_pass():
    inv = _inv()
    plan = plan_tests(inv, passive_only=False)
    ctx = AttackContext(fetcher=FakeFetcher(lambda u, **kw: ok_result(u, text="nothing interesting")),
                        inventory=inv, passive_only=False)
    execs = await execute_plan(plan, ctx)
    sqli = [e for e in execs if e.attack == C.SQL_INJECTION]
    assert sqli and all(e.status == TestStatus.NOT_VULNERABLE for e in sqli)


def test_coverage_never_counts_discovered_as_tested():
    # An inventory with params but zero executions: nothing tested.
    inv = _inv()
    cov = compute_coverage(inv, [])
    assert cov.parameters_discovered == 1
    assert cov.parameters_tested == 0
    assert cov.coverage_ratio < 1.0
