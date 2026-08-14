"""
Central Test Planner.

After discovery populates the Attack Surface Inventory, the planner decides
which of the 12 attacks apply to which discovered targets — nothing is
tested against everything. This is the one place attack eligibility lives
(previously scattered across ``active_engine`` priority/applies and the
``_TEST_CATALOG`` run-flags).

The planner is pure and deterministic: same inventory in, same plan out. It
never sends a request; it only selects targets. The executor runs the plan.
"""
from __future__ import annotations

from dataclasses import dataclass

from app.services.attacks import catalog as C
from app.services.debug_log import debug_log
from app.services.inventory import API, REDIRECT, UPLOAD, AttackSurfaceInventory, Endpoint, Parameter

# Parameter-name heuristics (reuse the same vocabularies the old engine used).
_PATHISH = {
    "file", "path", "page", "doc", "document", "template", "include",
    "download", "dir", "folder", "load", "read", "filename", "name",
}
_REDIRECTISH = {"url", "redirect", "next", "return", "returnurl", "dest",
                "destination", "u", "to", "target", "continue", "goto"}
_INJECTABLE_LOCATIONS = {"query", "form", "json", "multipart"}

# Attacks whose *testing* half sends crafted/attack payloads, so they only run
# on an authorized (non-passive) scan. Discovery/eligibility still happens.
ACTIVE_ATTACKS = {
    C.SQL_INJECTION, C.XSS, C.PATH_TRAVERSAL, C.OPEN_REDIRECT,
    C.HPP, C.FILE_UPLOAD,
}


@dataclass
class PlannedTest:
    test_id: str
    attack: str
    endpoint_id: str
    parameter_id: str | None = None
    reason: str = ""
    active: bool = False


def _is_pathish(param: Parameter) -> bool:
    return param.location == "path" or param.name.lower() in _PATHISH


def _is_redirectish(param: Parameter) -> bool:
    return param.name.lower() in _REDIRECTISH


def plan_tests(
    inventory: AttackSurfaceInventory,
    *,
    passive_only: bool = False,
    auth_available: bool = False,
) -> list[PlannedTest]:
    """Return the deterministic list of planned tests. ``passive_only`` and
    ``auth_available`` are recorded on the plan but do not remove eligible
    targets — an eligible-but-not-run test is reported NOT_TESTED by the
    executor/coverage, never silently dropped, so 'discovered ≠ tested' stays
    visible (§27)."""
    plan: list[PlannedTest] = []
    counter = 0

    def add(attack: str, endpoint: Endpoint, parameter: Parameter | None, reason: str) -> None:
        nonlocal counter
        counter += 1
        plan.append(PlannedTest(
            test_id=f"t_{counter:04d}",
            attack=attack,
            endpoint_id=endpoint.endpoint_id,
            parameter_id=parameter.parameter_id if parameter else None,
            reason=reason,
            active=attack in ACTIVE_ATTACKS,
        ))

    by_ep: dict[str, Endpoint] = {e.endpoint_id: e for e in inventory.endpoints}

    # --- Parameter-level attacks ---
    for pm in inventory.parameters:
        ep = by_ep.get(pm.endpoint_id)
        if ep is None:
            continue
        injectable = pm.location in _INJECTABLE_LOCATIONS or pm.location == "path"

        if pm.location in _INJECTABLE_LOCATIONS or (pm.location == "path" and pm.value_type in ("int", "uuid", "string")):
            add(C.SQL_INJECTION, ep, pm, f"{pm.location} parameter accepts input")

        if pm.location in _INJECTABLE_LOCATIONS:
            add(C.XSS, ep, pm, f"{pm.location} parameter may reflect into a response")

        if _is_pathish(pm) and injectable:
            add(C.PATH_TRAVERSAL, ep, pm, "parameter name/location references files or resources")

        if _is_redirectish(pm) and pm.location in ("query", "form"):
            add(C.OPEN_REDIRECT, ep, pm, "parameter name controls a navigation/redirect destination")

        if pm.location == "query":
            add(C.HPP, ep, pm, "query parameter accepts duplicate values")

    # --- Endpoint-level attacks ---
    seen_hosts: set[str] = set()
    for ep in inventory.endpoints:
        # Open redirect also applies to endpoints observed returning 3xx.
        if ep.kind == REDIRECT:
            add(C.OPEN_REDIRECT, ep, None, "endpoint observed issuing a redirect")

        if ep.kind == UPLOAD:
            add(C.FILE_UPLOAD, ep, None, "multipart file-upload endpoint")

        if ep.kind == API:
            add(C.API_AUTHENTICATION, ep, None, "API endpoint — check auth enforcement")

        # Security misconfiguration + sensitive info disclosure are assessed
        # once per host (headers/cookies/TLS/exposed resources are host-level,
        # not per-endpoint) — anchor them to the first endpoint seen per host.
        host = ep.normalized_route.split("/", 1)[0]
        if host not in seen_hosts:
            seen_hosts.add(host)
            add(C.SECURITY_MISCONFIGURATION, ep, None, "assess response headers/cookies/TLS/exposed resources")
            add(C.SENSITIVE_INFO_DISCLOSURE, ep, None, "inspect responses/JS/errors/files for exposed data")
            add(C.VHOST_ISOLATION, ep, None, "probe host-header/virtual-host isolation")

    # --- Authentication & Authorization ---
    auth = inventory.auth_routes or {}
    has_auth_surface = bool(
        auth.get("login_urls") or auth.get("session_cookie_names")
        or auth.get("bearer_token_seen") or auth.get("jwt_shaped_tokens_seen")
    )
    if has_auth_surface and inventory.endpoints:
        anchor = inventory.endpoints[0]
        add(C.AUTH, anchor, None,
            "authentication surface discovered" + ("" if auth_available else " (no credential supplied)"))

    # --- Subdomain Takeover ---
    for sub in inventory.subdomains:
        # Anchor to a synthetic reference via the first endpoint; the module
        # reads inventory.subdomains directly.
        if inventory.endpoints:
            add(C.SUBDOMAIN_TAKEOVER, inventory.endpoints[0], None,
                f"discovered subdomain {getattr(sub, 'hostname', sub)}")

    for attack in C.ALL_ATTACKS:
        n = sum(1 for p in plan if p.attack == attack)
        debug_log("TEST-PLANNER", f"{C.DISPLAY_NAME[attack]}: {n} eligible target(s)")

    return plan


def eligible_counts(plan: list[PlannedTest]) -> dict[str, int]:
    """Per-attack eligible-target counts (§22)."""
    counts = {a: 0 for a in C.ALL_ATTACKS}
    for p in plan:
        counts[p.attack] = counts.get(p.attack, 0) + 1
    return counts
