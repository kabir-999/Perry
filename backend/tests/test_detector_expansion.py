"""Expanded per-domain test cases: richer payload families + detectors."""
from urllib.parse import parse_qs, urlsplit

from app.services.active_engine import _CMD_CANARY, _cmd_detect, _trav_detect, _xss_detect
from app.services.attacks import catalog as C
from app.services.attacks.executor import AttackContext, execute_plan
from app.services.attacks.modules import _CMD_PAYLOADS, _TRAV_PAYLOADS, _XSS_PAYLOADS
from app.services.discovery_types import DiscoveredParam
from app.services.inventory import AttackSurfaceInventory
from app.services.test_planner import plan_tests
from app.services.test_status import TestStatus
from fixtures import FakeFetcher, ok_result


def test_payload_families_are_richer():
    # Traversal: unix + windows + encoded + double-encoded + nested variants.
    assert len(_TRAV_PAYLOADS) >= 6
    assert any("win.ini" in p for p in _TRAV_PAYLOADS)
    assert any("%252f" in p for p in _TRAV_PAYLOADS)  # double-encoded
    # Command injection: harmless echo-canary separators (unix + windows).
    assert any("echo" in p for p in _CMD_PAYLOADS)
    assert not any(x in p for p in _CMD_PAYLOADS for x in ("rm ", "del ", "shutdown", "curl", "wget"))
    # XSS: multiple breakout contexts.
    assert len(_XSS_PAYLOADS) >= 3


def test_trav_detect_windows_and_unix():
    assert _trav_detect("x", "normal page", "root:x:0:0:root:/root")  # unix
    assert _trav_detect("x", "normal page", "; for 16-bit app support\n[fonts]")  # windows
    # Content already in the baseline is not a finding.
    assert _trav_detect("x", "[fonts] base", "[fonts] base") is None
    assert _trav_detect("x", "base", "nothing interesting") is None


def test_cmd_detect_canary_execution_vs_reflection():
    # Canary appears as command OUTPUT -> execution confirmed.
    assert _cmd_detect(";echo x", "base", f"ping...\n{_CMD_CANARY}\n")
    # Canary appears only as the reflected payload (`echo <canary>`) -> not a hit.
    assert _cmd_detect(";echo x", "base", f"you sent: echo {_CMD_CANARY}") is None
    # Classic uid= evidence still detected.
    assert _cmd_detect(";id", "base", "uid=1000(www) gid=1000(www)")


def test_xss_detect_any_context_breakout():
    assert _xss_detect('wf7xq"><z>', "base", '<input value="wf7xq"><z>">')
    assert _xss_detect("wf7xq</script><z>", "base", "<script>x</script><z>")
    # Encoded reflection is safe.
    assert _xss_detect("x", "base", "&lt;z&gt; is encoded") is None


async def test_boolean_sqli_fires_without_an_error_signature():
    """A parameter with no DB error but a clean boolean-differential must still
    be reported VULNERABLE (blind SQLi), not NOT_VULNERABLE."""
    inv = AttackSurfaceInventory()
    inv.add_discovered_param(
        DiscoveredParam(url="https://t/item?id=1", name="id", param_type="query", example_value="1")
    )
    plan = plan_tests(inv, passive_only=False)

    rich = "Welcome user profile dashboard settings orders history invoices reports " * 6

    def responder(u, **kw):
        val = (parse_qs(urlsplit(u).query).get("id") or [""])[0]
        if "=2" in val:  # the always-FALSE boolean condition
            return ok_result(u, text="No records found.")
        return ok_result(u, text=rich)  # baseline + always-TRUE look identical

    ctx = AttackContext(fetcher=FakeFetcher(responder), inventory=inv, passive_only=False)
    execs = await execute_plan(plan, ctx)
    sqli = [e for e in execs if e.attack == C.SQL_INJECTION]
    assert sqli and any(e.status == TestStatus.VULNERABLE for e in sqli)
    assert any("boolean" in (e.evidence or "").lower() or "blind" in (e.evidence or "").lower()
               or e.finding for e in sqli if e.status == TestStatus.VULNERABLE)


async def test_broadened_eligibility_removes_na_for_traversal_and_redirect():
    inv = AttackSurfaceInventory()
    inv.add_discovered_param(
        DiscoveredParam(url="https://t/x?q=1", name="q", param_type="query", example_value="1")
    )
    plan = plan_tests(inv, passive_only=False)
    attacks = {p.attack for p in plan}
    # A plain non-file, non-redirect param is now eligible for both.
    assert C.PATH_TRAVERSAL in attacks
    assert C.OPEN_REDIRECT in attacks
