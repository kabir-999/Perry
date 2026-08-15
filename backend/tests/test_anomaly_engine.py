"""Baseline-vs-fuzz anomaly scoring."""
from app.services import anomaly_engine as A
from app.services.attacks import catalog as C
from app.services.attacks.executor import AttackContext, TestExecution, execute_plan
from app.services.discovery_types import DiscoveredParam
from app.services.inventory import AttackSurfaceInventory
from app.services.response_analyzer import AnalyzedResponse
from app.services.test_planner import plan_tests
from app.services.test_status import TestStatus
from fixtures import FakeFetcher, ok_result


def _resp(status, length, shingles):
    return AnalyzedResponse(
        url="https://t/x", status_code=status, content_type="text/html",
        length=length, redirected=False, redirect_chain=[], title="",
        visible_text="", fingerprint=f"{status}:{length}", shingles=set(shingles),
    )


def test_probe_anomaly_high_when_signal_and_response_diverges():
    base = _resp(200, 1000, range(0, 100))
    fuzz = _resp(500, 300, range(80, 120))  # status jumped to 5xx, body shrank + diverged
    score, factors = A.probe_anomaly(base, fuzz, signal_matched=True)
    assert score >= 0.8
    assert factors["status_change"] == 1.0
    assert factors["signal"] == 1.0


def test_probe_anomaly_low_when_no_signal_and_identical():
    base = _resp(200, 1000, range(0, 100))
    fuzz = _resp(200, 1000, range(0, 100))  # identical
    score, _ = A.probe_anomaly(base, fuzz, signal_matched=False)
    assert score <= 0.05


def test_status_anomaly_ordering():
    assert A.status_anomaly(TestStatus.VULNERABLE, "confirmed") > A.status_anomaly(TestStatus.INCONCLUSIVE)
    assert A.status_anomaly(TestStatus.INCONCLUSIVE) > A.status_anomaly(TestStatus.NOT_VULNERABLE)


def _ex(attack, status, anomaly=0.0, confidence="potential"):
    return TestExecution(
        test_id=f"{attack}-1", attack=attack, endpoint_id="e1", parameter_id="p1",
        status=status, confidence=confidence, anomaly=anomaly,
    )


def test_compute_anomaly_domains_and_overall():
    execs = [
        _ex(C.SQL_INJECTION, TestStatus.VULNERABLE, anomaly=0.92),
        _ex(C.SQL_INJECTION, TestStatus.NOT_VULNERABLE),
        _ex(C.XSS, TestStatus.NOT_VULNERABLE),
        _ex(C.PATH_TRAVERSAL, TestStatus.NOT_TESTED),  # excluded from scoring
    ]
    result = A.compute_anomaly(execs)
    domains, overall = result["domains"], result["overall"]

    # SQLi has a confirmed, measured anomaly -> high domain score.
    assert domains[C.SQL_INJECTION]["score"] >= 60
    assert domains[C.SQL_INJECTION]["measured"] == 1
    assert domains[C.SQL_INJECTION]["vulnerable"] == 1
    # A clean domain scores low but is still "tested".
    assert domains[C.XSS]["score"] <= 15
    # A not-tested domain carries no score and is excluded from the overall.
    assert domains[C.PATH_TRAVERSAL]["score"] is None
    assert domains[C.PATH_TRAVERSAL]["level"] == "not_tested"

    assert 0 < overall["score"] <= 100
    assert overall["top_domain"] == C.SQL_INJECTION
    assert overall["domains_tested"] == 2  # sqli + xss; traversal excluded
    assert overall["level"] in ("minimal", "low", "medium", "high", "critical")


async def test_compute_anomaly_from_real_execution():
    inv = AttackSurfaceInventory()
    inv.add_discovered_param(
        DiscoveredParam(url="https://t/search?q=x", name="q", param_type="query", example_value="x")
    )
    plan = plan_tests(inv, passive_only=False)

    def responder(u, **kw):
        if "'" in u or "%27" in u:
            return ok_result(u, text="You have an error in your SQL syntax; MySQL")
        return ok_result(u, text="ok")

    ctx = AttackContext(fetcher=FakeFetcher(responder), inventory=inv, passive_only=False)
    execs = await execute_plan(plan, ctx)
    result = A.compute_anomaly(execs)

    # SQLi actually fired against a live baseline/fuzz pair -> measured + high.
    sqli = result["domains"][C.SQL_INJECTION]
    assert sqli["vulnerable"] >= 1
    assert sqli["measured"] >= 1
    assert sqli["score"] >= 60
    assert result["overall"]["score"] > 0
