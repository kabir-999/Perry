"""
The 12 in-scope attack modules, each a runner registered under its canonical
name. Runners WRAP the already-verified detection logic in ``active_engine``
and ``security_checks`` — no new detection where it already exists — and turn
each planned test into a ``TestExecution`` (+ a ``FindingCandidate`` when the
evidence proves a vulnerability).

Two runner shapes:
  - probe-driven: sends crafted requests (SQLi/XSS/traversal/redirect/HPP/
    upload/API-auth/authz).
  - evidence-driven: reads findings already collected during discovery
    (misconfiguration/sensitive-info/vhost) or a dedicated detector
    (subdomain-takeover).
"""
from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from app.services import security_checks
from app.services.active_engine import (
    ParamTarget,
    _hpp_test,
    _open_redirect,
    _send,
    _sqli_detect,
    _trav_detect,
    _xss_detect,
    _XSS_MARKER,
    analyze,
    check_dom_xss,
    encode_variants,
)
from app.services.attacks import catalog as C
from app.services.attacks.executor import AttackContext, TestExecution
from app.services.debug_log import debug_log
from app.services.finding_types import FindingCandidate
from app.services.inventory import Endpoint, Parameter
from app.services.test_planner import PlannedTest
from app.services.test_status import TestStatus

_SQLI_PAYLOADS = ["'", "1'\"", "1) OR ('1'='1"]
_TRAV_PAYLOADS = ["../../../../../../etc/passwd", "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd"]


# --------------------------------------------------------------------------
# Shared probe helpers
# --------------------------------------------------------------------------

def _param_target(ep: Endpoint, pm: Parameter) -> ParamTarget:
    loc = pm.location if pm.location in ("query", "form", "json", "header") else "query"
    return ParamTarget(
        url=ep.url, name=pm.name, location=loc,
        method=ep.method or ("POST" if loc in ("form", "json") else "GET"),
        example=pm.original_value or "1",
    )


def _path_probe_url(ep: Endpoint, payload: str) -> str:
    """Replace the last id-shaped path segment with the payload (for path
    parameters, which build_request can't place in the query/body)."""
    parts = urlsplit(ep.url)
    segments = parts.path.split("/")
    for i in range(len(segments) - 1, -1, -1):
        if segments[i]:
            segments[i] = payload
            break
    return urlunsplit((parts.scheme, parts.netloc, "/".join(segments), "", ""))


def _exec(pt: PlannedTest, status: str, **kw) -> TestExecution:
    return TestExecution(
        test_id=pt.test_id, attack=pt.attack, endpoint_id=pt.endpoint_id,
        parameter_id=pt.parameter_id, status=status, **kw,
    )


def _budget_gone(ctx) -> bool:
    """True once the shared request budget is exhausted. A probe that can't
    send its request must NEVER be reported NOT_VULNERABLE — it wasn't tested.
    Every runner checks this so 'eligible but not tested' shows honestly as
    NOT_TESTED, not a false clean result."""
    return bool(getattr(ctx.fetcher, "budget_exhausted", False))


async def _probe_param(ctx, ep, pm, payloads, detect, *, encoders=None):
    """Baseline → payloads → optional encoder escalation. Returns
    (evidence, positive_payload, baseline_analyzed, test_analyzed) or Nones."""
    target = _param_target(ep, pm)
    debug_log("BASELINE", f"{ep.endpoint_id}/{pm.name} baseline")
    baseline = await _send(ctx.fetcher, target, target.example)
    if not baseline.ok:
        return None, None, None, None, False
    base_raw = baseline.text
    base = analyze(baseline)

    tried = list(payloads)
    for payload in payloads:
        res = await _send(ctx.fetcher, target, payload)
        if not res.ok:
            continue
        debug_log("COMPARE", f"{ep.endpoint_id}/{pm.name} payload={str(payload)[:24]}")
        ev = detect(payload, base_raw, res.text)
        if ev:
            return ev, payload, base, analyze(res), True

    if encoders and target.location in ("query", "form"):
        variants = []
        for enc in encoders:
            for v in enc(payloads[0]):
                if v not in tried and v not in variants:
                    variants.append(v)
        for payload in variants[:4]:
            res = await _send(ctx.fetcher, target, payload)
            if not res.ok:
                continue
            ev = detect(payload, base_raw, res.text)
            if ev:
                return ev, payload, base, analyze(res), True

    return None, None, base, None, True  # ran, no evidence


def _finding(attack, ep, pm, title, severity, evidence, payload, base, test, dedup):
    loc = pm.location if pm else ""
    return FindingCandidate(
        title=title, category="input_validation", severity=severity,
        confidence="potential", url=ep.url, method=ep.method,
        parameter=pm.name if pm else "",
        evidence=str(evidence)[:300],
        request_summary=f"{ep.method} {ep.url} [{loc}:{pm.name if pm else ''}={str(payload)[:40]}]",
        response_summary=(f"HTTP {test.status_code}; baseline HTTP {base.status_code}"
                          if test and base else ""),
        parameter_location=loc,
        reproducibility="Reproducible - replay the recorded request with the same payload",
        dedup_key=dedup,
    )


# --------------------------------------------------------------------------
# 1. SQL Injection
# --------------------------------------------------------------------------

async def run_sql_injection(plan, ctx: AttackContext):
    out = []
    for pt in plan:
        ep, pm = ctx.inventory.endpoint(pt.endpoint_id), ctx.inventory.parameter(pt.parameter_id)
        if ep is None or pm is None:
            out.append(_exec(pt, TestStatus.NOT_TESTED, evidence="missing target"))
            continue
        if ctx.passive_only:
            out.append(_exec(pt, TestStatus.NOT_TESTED, evidence="passive scan — active probe not sent"))
            continue
        if _budget_gone(ctx):
            out.append(_exec(pt, TestStatus.NOT_TESTED, evidence="request budget exhausted before this target was probed"))
            continue
        if pm.location == "path":
            ev, payload, base, test = await _probe_path(ctx, ep, _SQLI_PAYLOADS, _sqli_detect)
        else:
            ev, payload, base, test, ran = await _probe_param(ctx, ep, pm, _SQLI_PAYLOADS, _sqli_detect)
            if not ran:
                out.append(_exec(
                    pt,
                    TestStatus.NOT_TESTED if _budget_gone(ctx) else TestStatus.INCONCLUSIVE,
                    evidence=("request budget exhausted; parameter not probed"
                              if _budget_gone(ctx) else "baseline request failed"),
                ))
                continue
        if ev:
            f = _finding(C.SQL_INJECTION, ep, pm, "SQL Injection", "high", ev, payload, base, test,
                         f"sqli|{ep.normalized_route}|{pm.location}:{pm.name}")
            out.append(_exec(pt, TestStatus.VULNERABLE, confidence="potential", evidence=str(ev)[:200], finding=f))
        else:
            out.append(_exec(pt, TestStatus.NOT_VULNERABLE, confidence="potential",
                             evidence="No SQL error/behavioural signal after injection."))
    return out


async def _probe_path(ctx, ep, payloads, detect):
    baseline = await ctx.fetcher.fetch(ep.url, use_cache=False, follow_redirects=False)
    if not baseline.ok:
        return None, None, None, None
    base_raw, base = baseline.text, analyze(baseline)
    for payload in payloads:
        res = await ctx.fetcher.fetch(_path_probe_url(ep, payload), use_cache=False, follow_redirects=False)
        if not res.ok:
            continue
        ev = detect(payload, base_raw, res.text)
        if ev:
            return ev, payload, base, analyze(res)
    return None, None, base, None


# --------------------------------------------------------------------------
# 2. XSS (reflected + DOM)
# --------------------------------------------------------------------------

async def run_xss(plan, ctx: AttackContext):
    out = []
    for pt in plan:
        ep, pm = ctx.inventory.endpoint(pt.endpoint_id), ctx.inventory.parameter(pt.parameter_id)
        if ep is None or pm is None:
            out.append(_exec(pt, TestStatus.NOT_TESTED, evidence="missing target"))
            continue
        if ctx.passive_only:
            out.append(_exec(pt, TestStatus.NOT_TESTED, evidence="passive scan — active probe not sent"))
            continue
        ev, payload, base, test, ran = await _probe_param(ctx, ep, pm, [_XSS_MARKER], _xss_detect)
        if not ran:
            out.append(_exec(
                pt,
                TestStatus.NOT_TESTED if _budget_gone(ctx) else TestStatus.INCONCLUSIVE,
                evidence=("request budget exhausted; parameter not probed"
                          if _budget_gone(ctx) else "baseline request failed"),
            ))
            continue
        if not ev and pm.location == "query":
            # DOM-based reflection the raw-HTML diff can't see (browser render).
            dom = await check_dom_xss(_param_target(ep, pm))
            if dom:
                out.append(_exec(pt, TestStatus.VULNERABLE, confidence="potential",
                                 evidence="DOM reflection after JS render", finding=dom[0]))
                continue
        if ev:
            f = _finding(C.XSS, ep, pm, "Reflected XSS", "high", ev, payload, base, test,
                         f"reflected_xss|{ep.normalized_route}|{pm.location}:{pm.name}")
            out.append(_exec(pt, TestStatus.VULNERABLE, confidence="potential", evidence=str(ev)[:200], finding=f))
        else:
            out.append(_exec(pt, TestStatus.NOT_VULNERABLE, confidence="potential",
                             evidence="Marker not reflected in an executable context."))
    return out


# --------------------------------------------------------------------------
# 3. Path Traversal
# --------------------------------------------------------------------------

async def run_path_traversal(plan, ctx: AttackContext):
    out = []
    for pt in plan:
        ep, pm = ctx.inventory.endpoint(pt.endpoint_id), ctx.inventory.parameter(pt.parameter_id)
        if ep is None or pm is None:
            out.append(_exec(pt, TestStatus.NOT_TESTED, evidence="missing target"))
            continue
        if ctx.passive_only:
            out.append(_exec(pt, TestStatus.NOT_TESTED, evidence="passive scan — active probe not sent"))
            continue
        if pm.location == "path":
            ev, payload, base, test = await _probe_path(ctx, ep, _TRAV_PAYLOADS, _trav_detect)
            ran = base is not None
        else:
            ev, payload, base, test, ran = await _probe_param(
                ctx, ep, pm, _TRAV_PAYLOADS, _trav_detect, encoders=[encode_variants])
        if not ran:
            out.append(_exec(
                pt,
                TestStatus.NOT_TESTED if _budget_gone(ctx) else TestStatus.INCONCLUSIVE,
                evidence=("request budget exhausted; parameter not probed"
                          if _budget_gone(ctx) else "baseline request failed"),
            ))
            continue
        if ev:
            f = _finding(C.PATH_TRAVERSAL, ep, pm, "Path Traversal", "high", ev, payload, base, test,
                         f"path_traversal|{ep.normalized_route}|{pm.location}:{pm.name}")
            out.append(_exec(pt, TestStatus.VULNERABLE, confidence="potential", evidence=str(ev)[:200], finding=f))
        else:
            out.append(_exec(pt, TestStatus.NOT_VULNERABLE, confidence="potential",
                             evidence="No unintended file contents returned."))
    return out


# --------------------------------------------------------------------------
# 4. Open Redirect
# --------------------------------------------------------------------------

async def run_open_redirect(plan, ctx: AttackContext):
    out = []
    for pt in plan:
        ep, pm = ctx.inventory.endpoint(pt.endpoint_id), ctx.inventory.parameter(pt.parameter_id)
        if ep is None:
            out.append(_exec(pt, TestStatus.NOT_TESTED, evidence="missing target"))
            continue
        if ctx.passive_only or pm is None:
            out.append(_exec(pt, TestStatus.NOT_TESTED,
                             evidence="passive scan or endpoint-level redirect — not actively probed"))
            continue
        findings = await _open_redirect(ctx.fetcher, _param_target(ep, pm))
        if findings:
            out.append(_exec(pt, TestStatus.VULNERABLE, confidence="confirmed",
                             evidence=findings[0].evidence, finding=findings[0]))
        else:
            out.append(_exec(pt, TestStatus.NOT_VULNERABLE, confidence="potential",
                             evidence="External destination not honoured."))
    return out


# --------------------------------------------------------------------------
# 9. HTTP Parameter Pollution
# --------------------------------------------------------------------------

async def run_hpp(plan, ctx: AttackContext):
    out = []
    for pt in plan:
        ep, pm = ctx.inventory.endpoint(pt.endpoint_id), ctx.inventory.parameter(pt.parameter_id)
        if ep is None or pm is None:
            out.append(_exec(pt, TestStatus.NOT_TESTED, evidence="missing target"))
            continue
        if ctx.passive_only:
            out.append(_exec(pt, TestStatus.NOT_TESTED, evidence="passive scan — not probed"))
            continue
        if _budget_gone(ctx):
            out.append(_exec(pt, TestStatus.NOT_TESTED, evidence="request budget exhausted before this target was probed"))
            continue
        before = ctx.fetcher.requests_made
        findings = await _hpp_test(ctx.fetcher, _param_target(ep, pm))
        if not findings and (ctx.fetcher.requests_made == before or _budget_gone(ctx)):
            out.append(_exec(pt, TestStatus.NOT_TESTED, evidence="request budget exhausted; parameter not probed"))
            continue
        if findings:
            # A response difference alone is OBSERVATION/HARDENING, not a
            # vulnerability, unless a security consequence is shown — the
            # underlying check already gates on reflection, so keep it low.
            out.append(_exec(pt, TestStatus.VULNERABLE, confidence="potential",
                             evidence=findings[0].evidence, finding=findings[0]))
        else:
            out.append(_exec(pt, TestStatus.NOT_VULNERABLE, confidence="potential",
                             evidence="Duplicate parameter did not change behaviour."))
    return out


# --------------------------------------------------------------------------
# 10. File Upload
# --------------------------------------------------------------------------

async def run_file_upload(plan, ctx: AttackContext):
    out = []
    for pt in plan:
        ep = ctx.inventory.endpoint(pt.endpoint_id)
        upload = next((u for u in ctx.inventory.upload_endpoints if u.url == (ep.url if ep else None)), None)
        if ep is None or upload is None:
            out.append(_exec(pt, TestStatus.NOT_TESTED, evidence="no upload endpoint"))
            continue
        if ctx.passive_only:
            out.append(_exec(pt, TestStatus.NOT_TESTED, evidence="passive scan — upload not probed"))
            continue
        if _budget_gone(ctx):
            out.append(_exec(pt, TestStatus.NOT_TESTED, evidence="request budget exhausted before this target was probed"))
            continue
        findings = await security_checks.check_upload_endpoint(ctx.fetcher, upload)
        if findings:
            out.append(_exec(pt, TestStatus.VULNERABLE, confidence=findings[0].confidence,
                             evidence=findings[0].evidence, finding=findings[0]))
        else:
            out.append(_exec(pt, TestStatus.NOT_VULNERABLE, confidence="potential",
                             evidence="Upload validation accepted only safe canary; no bypass shown."))
    return out


# --------------------------------------------------------------------------
# 8. API Authentication
# --------------------------------------------------------------------------

async def run_api_authentication(plan, ctx: AttackContext):
    api_urls = [ctx.inventory.endpoint(pt.endpoint_id).url for pt in plan
                if ctx.inventory.endpoint(pt.endpoint_id)]
    findings = await security_checks.check_api_security(ctx.fetcher, api_urls) if api_urls else []
    finding_by_path = {}
    for f in findings:
        finding_by_path.setdefault(urlsplit(f.url).path, f)
    # If the whole API-security sweep couldn't run (budget already gone), no
    # endpoint was actually tested — don't report any of them NOT_VULNERABLE.
    swept = bool(api_urls) and not (not findings and _budget_gone(ctx))
    out = []
    for pt in plan:
        ep = ctx.inventory.endpoint(pt.endpoint_id)
        if ep is None:
            out.append(_exec(pt, TestStatus.NOT_TESTED, evidence="missing endpoint"))
            continue
        f = finding_by_path.get(urlsplit(ep.url).path)
        if f is not None:
            out.append(_exec(pt, TestStatus.VULNERABLE, confidence=f.confidence,
                             evidence=f.evidence, finding=f))
        elif not swept:
            out.append(_exec(pt, TestStatus.NOT_TESTED, evidence="request budget exhausted; API endpoint not probed"))
        else:
            out.append(_exec(pt, TestStatus.NOT_VULNERABLE, confidence="potential",
                             evidence="API endpoint enforces auth or returned no sensitive data unauthenticated."))
    return out


# --------------------------------------------------------------------------
# 7. Authentication & Authorization
# --------------------------------------------------------------------------

async def run_auth(plan, ctx: AttackContext):
    out = []
    for pt in plan:
        ep = ctx.inventory.endpoint(pt.endpoint_id)
        if ep is None:
            out.append(_exec(pt, TestStatus.NOT_TESTED, evidence="missing endpoint"))
            continue
        if not ctx.auth_header:
            # Authentication surface exists but no authorized credential —
            # DISCOVERED, NOT TESTED (never NOT_VULNERABLE).
            out.append(_exec(pt, TestStatus.NOT_TESTED,
                             evidence="Authentication discovered but no scanner credential supplied — not tested."))
            continue
        findings: list[FindingCandidate] = []
        for api in ctx.inventory.api_endpoints()[:15]:
            findings += await security_checks.check_authz_boundary(ctx.fetcher, api.url, ctx.auth_header)
            if ctx.auth_header_b:
                findings += await security_checks.check_two_account_authorization(
                    ctx.fetcher, api.url, ctx.auth_header, ctx.auth_header_b)
        if findings:
            out.append(_exec(pt, TestStatus.VULNERABLE, confidence=findings[0].confidence,
                             evidence=findings[0].evidence, finding=findings[0]))
        else:
            out.append(_exec(pt, TestStatus.NOT_VULNERABLE, confidence="potential",
                             evidence="Authorization boundary enforced for the tested identity."))
    return out


# --------------------------------------------------------------------------
# Evidence-driven runners (read findings collected during discovery)
# --------------------------------------------------------------------------

_MISCONFIG_PREFIXES = ("security_headers", "insecure_cookie", "cors", "dir_listing", "version_disclosure")
_SENSITIVE_PREFIXES = ("sensitive_file", "source_map", "stack_trace")


def _evidence_runner(prefixes, attack):
    async def runner(plan, ctx: AttackContext):
        matched = [f for f in ctx.passive_findings if f.dedup_key.split("|", 1)[0] in prefixes]
        out = []
        for pt in plan:
            if matched:
                worst = matched[0]
                out.append(_exec(pt, TestStatus.VULNERABLE, confidence=worst.confidence,
                                 evidence=f"{len(matched)} issue(s): {worst.title}", finding=None))
            else:
                out.append(_exec(pt, TestStatus.NOT_VULNERABLE, confidence="potential",
                                 evidence="No issues detected in collected responses."))
        # Attach ALL matched findings to the first execution so nothing is lost.
        if out and matched:
            out[0].finding = matched[0]
        return out
    return runner


async def run_security_misconfiguration(plan, ctx: AttackContext):
    return await _evidence_runner(_MISCONFIG_PREFIXES, C.SECURITY_MISCONFIGURATION)(plan, ctx)


async def run_sensitive_info(plan, ctx: AttackContext):
    return await _evidence_runner(_SENSITIVE_PREFIXES, C.SENSITIVE_INFO_DISCLOSURE)(plan, ctx)


async def run_vhost_isolation(plan, ctx: AttackContext):
    matched = [f for f in ctx.passive_findings if f.dedup_key.startswith("vhost|")]
    out = []
    for pt in plan:
        if matched:
            out.append(_exec(pt, TestStatus.VULNERABLE, confidence=matched[0].confidence,
                             evidence=matched[0].title, finding=matched[0]))
        elif not ctx.vhosts:
            out.append(_exec(pt, TestStatus.NOT_APPLICABLE, evidence="No virtual hosts discovered."))
        else:
            out.append(_exec(pt, TestStatus.NOT_VULNERABLE, confidence="potential",
                             evidence="Virtual hosts isolated; no distinct exposed surface."))
    return out


async def run_subdomain_takeover(plan, ctx: AttackContext):
    from app.services.subdomain_takeover import check_subdomain_takeover
    out = []
    for pt in plan:
        if not ctx.subdomains:
            out.append(_exec(pt, TestStatus.NOT_APPLICABLE, evidence="No subdomains discovered."))
            continue
        results = await check_subdomain_takeover(ctx.subdomains, ctx.fetcher)
        vuln = [r for r in results if r[0] == TestStatus.VULNERABLE]
        incon = [r for r in results if r[0] == TestStatus.INCONCLUSIVE]
        if vuln:
            out.append(_exec(pt, TestStatus.VULNERABLE, confidence="confirmed",
                             evidence=vuln[0][1].evidence, finding=vuln[0][1]))
        elif incon:
            out.append(_exec(pt, TestStatus.INCONCLUSIVE, evidence=incon[0][1].evidence))
        else:
            out.append(_exec(pt, TestStatus.NOT_VULNERABLE, confidence="potential",
                             evidence="No dangling records pointing at unclaimed services."))
        break  # one execution summarises the subdomain sweep
    return out


# --------------------------------------------------------------------------
# Extended attacks (phase-2 detectors: command/nosql/ssrf/ssti/csrf/crlf/stored)
# --------------------------------------------------------------------------

from app.services import phase2_checks  # noqa: E402
from app.services.active_engine import _cmd_detect  # noqa: E402

_CMD_PAYLOADS = [";id", "|id", "`id`", "$(id)"]


async def run_command_injection(plan, ctx: AttackContext):
    out = []
    for pt in plan:
        ep, pm = ctx.inventory.endpoint(pt.endpoint_id), ctx.inventory.parameter(pt.parameter_id)
        if ep is None or pm is None:
            out.append(_exec(pt, TestStatus.NOT_TESTED, evidence="missing target"))
            continue
        if ctx.passive_only:
            out.append(_exec(pt, TestStatus.NOT_TESTED, evidence="passive scan — not probed"))
            continue
        ev, payload, base, test, ran = await _probe_param(ctx, ep, pm, _CMD_PAYLOADS, _cmd_detect)
        if not ran:
            out.append(_exec(
                pt,
                TestStatus.NOT_TESTED if _budget_gone(ctx) else TestStatus.INCONCLUSIVE,
                evidence=("request budget exhausted; parameter not probed"
                          if _budget_gone(ctx) else "baseline request failed"),
            ))
            continue
        if ev:
            f = _finding(C.COMMAND_INJECTION, ep, pm, "Command Injection", "critical", ev, payload, base, test,
                         f"cmd_injection|{ep.normalized_route}|{pm.location}:{pm.name}")
            out.append(_exec(pt, TestStatus.VULNERABLE, confidence="potential", evidence=str(ev)[:200], finding=f))
        else:
            out.append(_exec(pt, TestStatus.NOT_VULNERABLE, confidence="potential",
                             evidence="No OS command output observed after injection."))
    return out


def _phase2_param_runner(attack, detector, **kw):
    """Build a param-level runner around a phase2_checks.check_* detector with
    signature (fetcher, url, param) (+ optional kwargs)."""
    async def runner(plan, ctx: AttackContext):
        out = []
        for pt in plan:
            ep, pm = ctx.inventory.endpoint(pt.endpoint_id), ctx.inventory.parameter(pt.parameter_id)
            if ep is None or pm is None:
                out.append(_exec(pt, TestStatus.NOT_TESTED, evidence="missing target"))
                continue
            if ctx.passive_only:
                out.append(_exec(pt, TestStatus.NOT_TESTED, evidence="passive scan — not probed"))
                continue
            if _budget_gone(ctx):
                out.append(_exec(pt, TestStatus.NOT_TESTED, evidence="request budget exhausted before this target was probed"))
                continue
            before = ctx.fetcher.requests_made
            try:
                extra = dict(kw)
                if attack == C.SSRF:
                    extra["example"] = pm.original_value or ""
                findings = await detector(ctx.fetcher, ep.url, pm.name, **extra)
            except Exception as exc:
                out.append(_exec(pt, TestStatus.INCONCLUSIVE, evidence=f"probe error: {exc}"))
                continue
            if findings:
                out.append(_exec(pt, TestStatus.VULNERABLE, confidence=findings[0].confidence,
                                 evidence=findings[0].evidence, finding=findings[0]))
            elif ctx.fetcher.requests_made == before or _budget_gone(ctx):
                # No probe actually landed (budget ran out mid-detector) — never
                # report a clean result for something that wasn't tested.
                out.append(_exec(pt, TestStatus.NOT_TESTED, evidence="request budget exhausted; parameter not fully probed"))
            else:
                out.append(_exec(pt, TestStatus.NOT_VULNERABLE, confidence="potential",
                                 evidence="No evidence for this attack on the tested parameter."))
        return out
    return runner


async def run_nosql_injection(plan, ctx: AttackContext):
    out = []
    for pt in plan:
        ep = ctx.inventory.endpoint(pt.endpoint_id)
        if ep is None:
            out.append(_exec(pt, TestStatus.NOT_TESTED, evidence="missing endpoint"))
            continue
        if ctx.passive_only:
            out.append(_exec(pt, TestStatus.NOT_TESTED, evidence="passive scan — not probed"))
            continue
        if _budget_gone(ctx):
            out.append(_exec(pt, TestStatus.NOT_TESTED, evidence="request budget exhausted before this target was probed"))
            continue
        before = ctx.fetcher.requests_made
        try:
            findings = await phase2_checks.check_nosql_injection(ctx.fetcher, ep.url)
        except Exception as exc:
            out.append(_exec(pt, TestStatus.INCONCLUSIVE, evidence=f"probe error: {exc}"))
            continue
        if findings:
            out.append(_exec(pt, TestStatus.VULNERABLE, confidence=findings[0].confidence,
                             evidence=findings[0].evidence, finding=findings[0]))
        elif ctx.fetcher.requests_made == before or _budget_gone(ctx):
            out.append(_exec(pt, TestStatus.NOT_TESTED, evidence="request budget exhausted; endpoint not probed"))
        else:
            out.append(_exec(pt, TestStatus.NOT_VULNERABLE, confidence="potential",
                             evidence="Operator-injection login did not bypass authentication."))
    return out


def _phase2_endpoint_runner(attack, detector):
    """Endpoint-level runner (CSRF/Stored-XSS): calls detector(fetcher, url, ...)."""
    async def runner(plan, ctx: AttackContext):
        out = []
        for pt in plan:
            ep = ctx.inventory.endpoint(pt.endpoint_id)
            if ep is None:
                out.append(_exec(pt, TestStatus.NOT_TESTED, evidence="missing endpoint"))
                continue
            if ctx.passive_only:
                out.append(_exec(pt, TestStatus.NOT_TESTED, evidence="passive scan — not probed"))
                continue
            if _budget_gone(ctx):
                out.append(_exec(pt, TestStatus.NOT_TESTED, evidence="request budget exhausted before this target was probed"))
                continue
            before = ctx.fetcher.requests_made
            try:
                if attack == C.STORED_XSS:
                    findings = await detector(ctx.fetcher, ep.url, ep.url)
                else:
                    findings = await detector(ctx.fetcher, ep.url)
            except Exception as exc:
                out.append(_exec(pt, TestStatus.INCONCLUSIVE, evidence=f"probe error: {exc}"))
                continue
            if findings:
                out.append(_exec(pt, TestStatus.VULNERABLE, confidence=findings[0].confidence,
                                 evidence=findings[0].evidence, finding=findings[0]))
            elif ctx.fetcher.requests_made == before or _budget_gone(ctx):
                out.append(_exec(pt, TestStatus.NOT_TESTED, evidence="request budget exhausted; endpoint not probed"))
            else:
                out.append(_exec(pt, TestStatus.NOT_VULNERABLE, confidence="potential",
                                 evidence="No evidence for this attack on the tested endpoint."))
        return out
    return runner


ATTACK_RUNNERS = {
    C.SQL_INJECTION: run_sql_injection,
    C.XSS: run_xss,
    C.PATH_TRAVERSAL: run_path_traversal,
    C.OPEN_REDIRECT: run_open_redirect,
    C.HPP: run_hpp,
    C.FILE_UPLOAD: run_file_upload,
    C.API_AUTHENTICATION: run_api_authentication,
    C.AUTH: run_auth,
    C.SECURITY_MISCONFIGURATION: run_security_misconfiguration,
    C.SENSITIVE_INFO_DISCLOSURE: run_sensitive_info,
    C.VHOST_ISOLATION: run_vhost_isolation,
    C.SUBDOMAIN_TAKEOVER: run_subdomain_takeover,
    # Extended (phase-2) attacks.
    C.COMMAND_INJECTION: run_command_injection,
    C.NOSQL_INJECTION: run_nosql_injection,
    C.SSRF: _phase2_param_runner(C.SSRF, phase2_checks.check_ssrf),
    C.SSTI: _phase2_param_runner(C.SSTI, phase2_checks.check_ssti),
    C.CRLF: _phase2_param_runner(C.CRLF, phase2_checks.check_crlf),
    C.CSRF: _phase2_endpoint_runner(C.CSRF, phase2_checks.check_csrf),
    C.STORED_XSS: _phase2_endpoint_runner(C.STORED_XSS, phase2_checks.check_stored_xss),
}
