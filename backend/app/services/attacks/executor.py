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

import asyncio
import time
from dataclasses import dataclass, field

from app.services import attack_logger as alog
from app.services.attacks import catalog as C
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
    registry lazily to avoid an import cycle (modules import this file).

    The 19 attack runners are launched concurrently (not one after another) —
    each only ever talks to the target through ``ctx.fetcher``, which already
    enforces its own concurrency cap and request budget, so running the
    runners themselves concurrently is safe and turns what used to be a
    strictly serial (and, for a real multi-endpoint site, very slow) pass
    into one bounded by the fetcher's own limits instead of by attack count.
    """
    from app.services.attacks.modules import ATTACK_RUNNERS

    by_attack: dict[str, list[PlannedTest]] = {}
    for pt in plan:
        by_attack.setdefault(pt.attack, []).append(pt)

    async def run_one(attack: str, planned: list[PlannedTest]) -> list[TestExecution]:
        display = C.DISPLAY_NAME.get(attack, attack)
        alog.log_attack(
            alog.LEVEL_INFO, attack, "attack_start",
            f"Starting {display}: {len(planned)} planned test(s) against the discovered attack surface.",
            attack_display=display, meta={"planned_tests": len(planned)},
        )
        started = time.monotonic()
        runner = ATTACK_RUNNERS.get(attack)
        if runner is None:
            # No runner registered — every planned test is NOT_TESTED, never
            # silently a pass.
            group = [
                TestExecution(
                    test_id=pt.test_id, attack=attack, endpoint_id=pt.endpoint_id,
                    parameter_id=pt.parameter_id, status=TestStatus.NOT_TESTED,
                    evidence="No runner registered for this attack.",
                )
                for pt in planned
            ]
            _log_executions(attack, display, group, ctx)
            _log_attack_summary(attack, display, group, started)
            return group
        debug_log("TEST", f"{attack}: executing {len(planned)} planned test(s)")
        try:
            group = await runner(planned, ctx)
        except Exception as exc:  # a runner must never take the whole scan down
            alog.log_attack(
                alog.LEVEL_ERROR, attack, "attack_error",
                f"{display} runner raised an unexpected error: {exc!r}",
                attack_display=display, evidence=repr(exc),
                meta={"exception": type(exc).__name__},
            )
            raise
        _log_executions(attack, display, group, ctx)
        _log_attack_summary(attack, display, group, started)
        return group

    results = await asyncio.gather(
        *(run_one(attack, planned) for attack, planned in by_attack.items())
    )
    executions: list[TestExecution] = [e for group in results for e in group]

    for e in executions:
        debug_log("RESULT", f"{e.attack} {e.endpoint_id}/{e.parameter_id or '-'} -> {e.status}")
    return executions


# --------------------------------------------------------------------------
# Structured JSON attack logging
# --------------------------------------------------------------------------

def _payload_from_summary(request_summary: str) -> str:
    """Best-effort extraction of the payload from a finding's request summary,
    which the runners format as ``METHOD URL [loc:name=payload]``."""
    if "=" in request_summary and request_summary.endswith("]"):
        return request_summary.rsplit("=", 1)[1][:-1]
    return ""


def _log_executions(
    attack: str, display: str, group: list[TestExecution], ctx: AttackContext
) -> None:
    """Emit one structured record per executed test — vulnerable, clean,
    skipped, inconclusive, or errored alike — so the log captures every attack
    attempt irrespective of outcome."""
    for e in group:
        ep = ctx.inventory.endpoint(e.endpoint_id)
        pm = ctx.inventory.parameter(e.parameter_id) if e.parameter_id else None
        finding = e.finding
        payload = ""
        request_summary = e.request_summary
        response_summary = e.response_summary
        if finding is not None:
            request_summary = request_summary or finding.request_summary
            response_summary = response_summary or finding.response_summary
            payload = _payload_from_summary(finding.request_summary)

        endpoint = ep.url if ep else ""
        method = (ep.method if ep else "") or ""
        parameter = pm.name if pm else ""
        location = pm.location if pm else ""
        target_desc = f"{method} {endpoint}".strip() or "(no endpoint)"
        if parameter:
            target_desc += f" [{location}:{parameter}]"

        level = alog.level_for_status(e.status)
        event = alog.event_for_status(e.status)
        if e.status == TestStatus.VULNERABLE:
            message = f"VULNERABLE — {display} detected on {target_desc}."
        elif e.status == TestStatus.NOT_VULNERABLE:
            message = f"{display} executed on {target_desc}; target not vulnerable."
        elif e.status == TestStatus.INCONCLUSIVE:
            message = f"{display} on {target_desc} was inconclusive."
        elif e.status == TestStatus.NOT_APPLICABLE:
            message = f"{display} does not apply to {target_desc}."
        else:  # NOT_TESTED
            message = f"{display} not tested on {target_desc}."
        # A probe error is reported at ERROR level even though its status is
        # INCONCLUSIVE, so genuine failures stand out in the log.
        if e.status == TestStatus.INCONCLUSIVE and "error" in (e.evidence or "").lower():
            level = alog.LEVEL_ERROR
            event = "test_error"

        alog.log_attack(
            level, attack, event, message,
            attack_display=display, status=e.status, confidence=e.confidence,
            endpoint=endpoint, method=method, parameter=parameter, location=location,
            payload=payload, evidence=e.evidence, test_id=e.test_id,
            request_summary=request_summary, response_summary=response_summary,
            meta={
                "endpoint_id": e.endpoint_id,
                "parameter_id": e.parameter_id,
                "has_finding": finding is not None,
            },
        )


def _log_attack_summary(
    attack: str, display: str, group: list[TestExecution], started: float
) -> None:
    counts: dict[str, int] = {}
    for e in group:
        counts[e.status] = counts.get(e.status, 0) + 1
    vulnerable = counts.get(TestStatus.VULNERABLE, 0)
    elapsed_ms = int((time.monotonic() - started) * 1000)
    level = alog.LEVEL_ALERT if vulnerable else alog.LEVEL_INFO
    message = (
        f"{display} complete: {len(group)} test(s) in {elapsed_ms} ms — "
        f"{vulnerable} vulnerable, "
        f"{counts.get(TestStatus.NOT_VULNERABLE, 0)} clean, "
        f"{counts.get(TestStatus.NOT_TESTED, 0)} not tested, "
        f"{counts.get(TestStatus.INCONCLUSIVE, 0)} inconclusive, "
        f"{counts.get(TestStatus.NOT_APPLICABLE, 0)} n/a."
    )
    alog.log_attack(
        level, attack, "attack_summary", message,
        attack_display=display,
        meta={"counts": counts, "total": len(group), "elapsed_ms": elapsed_ms,
              "vulnerable": vulnerable},
    )
