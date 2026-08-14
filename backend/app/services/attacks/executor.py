"""
Attack execution layer.

Runs a Test Planner plan against the Attack Surface Inventory and produces
one ``TestExecution`` per planned test — the row that proves an attack
actually ran against a specific endpoint/parameter (§20/§21), plus a
``FindingCandidate`` when the evidence establishes a vulnerability.

Attacks split into two kinds, both dispatched here uniformly:
  - probe-driven (SQLi/XSS/traversal/redirect/HPP/upload/API-auth/authz):
    the runner sends crafted requests.
  - evidence-driven (misconfiguration/sensitive-info/vhost/subdomain-takeover):
    the runner reads findings already produced during discovery.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.services.debug_log import debug_log
from app.services.finding_types import FindingCandidate
from app.services.inventory import AttackSurfaceInventory
from app.services.test_planner import PlannedTest
from app.services.test_status import TestStatus


@dataclass
class TestExecution:
    test_id: str
    attack: str
    endpoint_id: str
    parameter_id: str | None
    status: str  # TestStatus.*
    confidence: str = ""  # confirmed | potential | uncertain | ""
    request_summary: str = ""
    baseline_summary: str = ""
    response_summary: str = ""
    evidence: str = ""
    finding: FindingCandidate | None = None


@dataclass
class AttackContext:
    """Everything a runner may need, so a runner never reaches back into the
    orchestrator or crawls on its own."""
    fetcher: object
    inventory: AttackSurfaceInventory
    passive_only: bool = False
    auth_header: str | None = None
    auth_header_b: str | None = None
    not_found: object = None
    # Findings already collected during discovery (headers/cookies/cors/
    # dir-listing/debug/sensitive-files/source-maps/vhost) — the raw material
    # for the evidence-driven attack modules.
    passive_findings: list[FindingCandidate] = field(default_factory=list)
    # Subdomain/vhost discovery objects.
    subdomains: list = field(default_factory=list)
    vhosts: list = field(default_factory=list)


async def execute_plan(
    plan: list[PlannedTest], ctx: AttackContext
) -> list[TestExecution]:
    """Dispatch each attack's planned subset to its runner. Import the
    registry lazily to avoid an import cycle (modules import this file)."""
    from app.services.attacks.modules import ATTACK_RUNNERS

    by_attack: dict[str, list[PlannedTest]] = {}
    for pt in plan:
        by_attack.setdefault(pt.attack, []).append(pt)

    executions: list[TestExecution] = []
    for attack, planned in by_attack.items():
        runner = ATTACK_RUNNERS.get(attack)
        if runner is None:
            # No runner registered — every planned test is NOT_TESTED, never
            # silently a pass.
            for pt in planned:
                executions.append(TestExecution(
                    test_id=pt.test_id, attack=attack, endpoint_id=pt.endpoint_id,
                    parameter_id=pt.parameter_id, status=TestStatus.NOT_TESTED,
                    evidence="No runner registered for this attack.",
                ))
            continue
        debug_log("TEST", f"{attack}: executing {len(planned)} planned test(s)")
        results = await runner(planned, ctx)
        executions.extend(results)

    for e in executions:
        debug_log("RESULT", f"{e.attack} {e.endpoint_id}/{e.parameter_id or '-'} -> {e.status}")
    return executions
