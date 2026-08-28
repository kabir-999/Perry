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
from app.services.inventory import API, FORM, REDIRECT, UPLOAD, AttackSurfaceInventory, Endpoint, Parameter

# Parameter-name heuristics (reuse the same vocabularies the old engine used).
_PATHISH = {
    "file", "path", "page", "doc", "document", "template", "include",
    "download", "dir", "folder", "load", "read", "filename", "name",
}
_REDIRECTISH = {"url", "redirect", "next", "return", "returnurl", "dest",
                "destination", "u", "to", "target", "continue", "goto"}
_INJECTABLE_LOCATIONS = {"query", "form", "json", "multipart"}

# URL-ish parameter names — candidates for SSRF (server fetches the value).
_SSRFISH = {"url", "uri", "link", "src", "source", "dest", "target", "callback",
            "webhook", "fetch", "load", "image", "img", "file", "path", "proxy",
            "feed", "host", "domain", "redirect", "next", "return", "continue"}

# Attacks whose *testing* half sends crafted/attack payloads, so they only run
# on an authorized (non-passive) scan. Discovery/eligibility still happens.
ACTIVE_ATTACKS = {
    C.SQL_INJECTION, C.XSS, C.PATH_TRAVERSAL, C.OPEN_REDIRECT,
    C.HPP, C.FILE_UPLOAD,
    C.COMMAND_INJECTION, C.NOSQL_INJECTION, C.SSRF, C.SSTI, C.CSRF,
    C.CRLF, C.STORED_XSS,
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

        # Path traversal is tried on ANY injectable parameter — a file read can
        # hide behind any name, so name heuristics only prioritise, never gate
        # (the detector confirms via returned file content, so a non-file
        # parameter simply comes back NOT_VULNERABLE rather than N/A).
        if injectable:
            reason = ("parameter name/location references files or resources"
                      if _is_pathish(pm) else "injectable parameter — traversal probed broadly")
            add(C.PATH_TRAVERSAL, ep, pm, reason)

        # Open redirect is tried on any query/form parameter; the detector only
        # flags an actual external Location redirect, so unrelated parameters
        # resolve to NOT_VULNERABLE, not N/A.
        if pm.location in ("query", "form"):
            reason = ("parameter name controls a navigation/redirect destination"
                      if _is_redirectish(pm) else "query/form parameter — redirect probed broadly")
            add(C.OPEN_REDIRECT, ep, pm, reason)

        if pm.location == "query":
            add(C.HPP, ep, pm, "query parameter accepts duplicate values")

        # --- Extended parameter-level attacks (phase-2 detectors) ---
        if pm.location in _INJECTABLE_LOCATIONS:
            add(C.COMMAND_INJECTION, ep, pm, f"{pm.location} parameter may reach a shell")
            add(C.SSTI, ep, pm, f"{pm.location} parameter may reach a template engine")
            add(C.CRLF, ep, pm, f"{pm.location} parameter may be reflected into a header")
        if pm.name.lower() in _SSRFISH:
            add(C.SSRF, ep, pm, "parameter name suggests the server fetches the value")

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

        # CSRF + Stored XSS apply to state-changing form endpoints.
        if ep.kind == FORM and ep.method.upper() in ("POST", "PUT", "PATCH"):
            add(C.CSRF, ep, None, "state-changing form endpoint")
            add(C.STORED_XSS, ep, None, "form may persist and re-render input")

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
        # NoSQL auth-bypass targets a login endpoint specifically.
        login_ep = None
        for url in auth.get("login_urls", []):
            login_ep = next((e for e in inventory.endpoints if e.url == url), None)
            if login_ep:
                break
        add(C.NOSQL_INJECTION, login_ep or anchor, None, "login endpoint — NoSQL operator-injection bypass")

    # --- Subdomain Takeover ---
    # One execution summarises the whole sweep (the runner reads
    # inventory.subdomains directly, not this anchor's URL) — but the anchor
    # itself needs to be one of the actual discovered subdomains, not an
    # unrelated already-existing page endpoint. Anchoring to
    # inventory.endpoints[0] used to make the log/UI show something like
    # "Subdomain Takeover on GET https://example.com/some/random/page",
    # which reads as testing that page for takeover — never true, and
    # confusing (reported as a false-positive-looking mismatch).
    if inventory.subdomains:
        sub = inventory.subdomains[0]
        hostname = getattr(sub, "hostname", str(sub))
        anchor_ep = inventory.add_endpoint(f"https://{hostname}")
        add(C.SUBDOMAIN_TAKEOVER, anchor_ep, None,
            f"{len(inventory.subdomains)} discovered subdomain(s), starting with {hostname}")

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
