"""
Coverage — the honest record of what was discovered vs. what was actually
tested (§22/§23/§27). Three products, all derived from real execution, never
hardcoded and never "discovered == tested":

  - the **test matrix**: one row per executed test (endpoint, parameter,
    attack, status) — proof an attack actually ran (§21).
  - **per-attack coverage**: for each of the 12 attacks, eligible / tested /
    skipped / inconclusive / vulnerable / not_vulnerable (§22).
  - **crawl coverage** (`CoverageMetrics`): discovered vs. tested counts +
    the tallies the assessment-confidence ladder reads.
"""
from __future__ import annotations

from dataclasses import dataclass

from app.services.attacks import catalog as C
from app.services.inventory import AttackSurfaceInventory
from app.services.test_status import TestStatus

_EXECUTED = {TestStatus.VULNERABLE, TestStatus.NOT_VULNERABLE}
_NOT_EXECUTED = {TestStatus.NOT_TESTED, TestStatus.NOT_APPLICABLE}


# --------------------------------------------------------------------------
# Test matrix (§21)
# --------------------------------------------------------------------------

def build_test_matrix(executions: list, inventory: AttackSurfaceInventory) -> list[dict]:
    rows: list[dict] = []
    for e in executions:
        ep = inventory.endpoint(e.endpoint_id)
        pm = inventory.parameter(e.parameter_id) if e.parameter_id else None
        rows.append({
            "test_id": e.test_id,
            "attack": e.attack,
            "attack_display": C.DISPLAY_NAME.get(e.attack, e.attack),
            "endpoint": ep.url if ep else "",
            "normalized_route": ep.normalized_route if ep else "",
            "method": ep.method if ep else "",
            "parameter": pm.name if pm else "",
            "location": pm.location if pm else "",
            "status": e.status,
            "confidence": e.confidence,
            "evidence": (e.evidence or "")[:300],
        })
    return rows


# --------------------------------------------------------------------------
# Per-attack coverage (§22)
# --------------------------------------------------------------------------

def per_attack_coverage(plan: list, executions: list) -> dict:
    eligible = {a: 0 for a in C.ALL_ATTACKS}
    for pt in plan:
        eligible[pt.attack] = eligible.get(pt.attack, 0) + 1

    out: dict[str, dict] = {}
    for attack in C.ALL_ATTACKS:
        ex = [e for e in executions if e.attack == attack]
        vulnerable = sum(1 for e in ex if e.status == TestStatus.VULNERABLE)
        not_vuln = sum(1 for e in ex if e.status == TestStatus.NOT_VULNERABLE)
        inconclusive = sum(1 for e in ex if e.status == TestStatus.INCONCLUSIVE)
        not_applicable = sum(1 for e in ex if e.status == TestStatus.NOT_APPLICABLE)
        not_tested = sum(1 for e in ex if e.status == TestStatus.NOT_TESTED)
        tested = vulnerable + not_vuln
        if vulnerable:
            status = TestStatus.VULNERABLE
        elif tested:
            status = TestStatus.NOT_VULNERABLE
        elif inconclusive:
            status = TestStatus.INCONCLUSIVE
        elif eligible.get(attack, 0) == 0 or (not_applicable and not not_tested):
            # Genuinely inapplicable (no eligible targets, or every execution
            # reported the attack doesn't apply).
            status = TestStatus.NOT_APPLICABLE
        else:
            status = TestStatus.NOT_TESTED
        out[attack] = {
            "attack": attack,
            "display": C.DISPLAY_NAME[attack],
            "status": status,
            "eligible": eligible.get(attack, 0),
            "tested": tested,
            "skipped": not_tested + not_applicable,
            "inconclusive": inconclusive,
            "vulnerable": vulnerable,
            "not_vulnerable": not_vuln,
        }
    return out


# --------------------------------------------------------------------------
# Crawl coverage + confidence-ladder tallies (§23)
# --------------------------------------------------------------------------

@dataclass
class CoverageMetrics:
    urls_discovered: int = 0
    apis_discovered: int = 0
    forms_discovered: int = 0
    parameters_discovered: int = 0
    js_bundles_discovered: int = 0
    network_requests_captured: int = 0
    upload_endpoints_discovered: int = 0
    auth_routes_discovered: int = 0
    subdomains_discovered: int = 0
    vhosts_discovered: int = 0

    urls_tested: int = 0
    apis_tested: int = 0
    parameters_tested: int = 0
    forms_tested: int = 0

    security_tests_executed: int = 0
    security_tests_not_executed: int = 0
    inconclusive_tests: int = 0

    def to_dict(self) -> dict:
        d = dict(self.__dict__)
        d["coverage_ratio"] = self.coverage_ratio
        return d

    @property
    def coverage_ratio(self) -> float:
        total = self.security_tests_executed + self.security_tests_not_executed + self.inconclusive_tests
        test_completeness = (self.security_tests_executed / total) if total else 0.0
        breadth = [self.urls_discovered > 0, self.apis_discovered > 0, self.parameters_discovered > 0]
        discovery_breadth = sum(breadth) / len(breadth)
        return round(0.65 * test_completeness + 0.35 * discovery_breadth, 4)


def compute_coverage(
    inventory: AttackSurfaceInventory, executions: list
) -> CoverageMetrics:
    counts = inventory.counts()
    executed = sum(1 for e in executions if e.status in _EXECUTED)
    not_executed = sum(1 for e in executions if e.status in _NOT_EXECUTED)
    inconclusive = sum(1 for e in executions if e.status == TestStatus.INCONCLUSIVE)

    tested_endpoints = {e.endpoint_id for e in executions if e.status in _EXECUTED}
    tested_params = {e.parameter_id for e in executions if e.parameter_id and e.status in _EXECUTED}
    tested_apis = {
        e.endpoint_id for e in executions
        if e.status in _EXECUTED and (inventory.endpoint(e.endpoint_id) or None)
        and inventory.endpoint(e.endpoint_id).kind == "api"
    }

    return CoverageMetrics(
        urls_discovered=counts["urls"],
        apis_discovered=counts["apis"],
        forms_discovered=counts["forms"],
        parameters_discovered=counts["parameters"],
        js_bundles_discovered=counts["js_bundles"],
        network_requests_captured=counts["network_requests"],
        upload_endpoints_discovered=counts["upload_endpoints"],
        auth_routes_discovered=counts["auth_routes"],
        subdomains_discovered=counts["subdomains"],
        vhosts_discovered=counts["vhosts"],
        urls_tested=len(tested_endpoints),
        apis_tested=len(tested_apis),
        parameters_tested=len(tested_params),
        forms_tested=len([e for e in tested_endpoints]),
        security_tests_executed=executed,
        security_tests_not_executed=not_executed,
        inconclusive_tests=inconclusive,
    )
