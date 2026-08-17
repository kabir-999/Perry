"""
Scan Manager — owns the two-stage scan lifecycle.

    QUEUED -> FAST_SCANNING -> INITIAL_RESULT_READY
           -> DEEP_SCANNING -> AI_ANALYSIS -> COMPLETED   (or FAILED/CANCELLED)

`create_scan` validates the URL, persists the scan, and launches a background
asyncio task that runs the fast scan (initial result in ~1-2s) and then the
deep scan. Progress is persisted to the DB and published to the SSE broker via
the `emit` callback. The manager is the only place that touches the DB and the
broker; the scanner services stay pure.
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import AsyncSessionLocal
from app.models.enums import ACTIVE_SCAN_STATUSES, ScanStatus
from app.models.endpoint import DiscoveredEndpoint, Parameter, Subdomain
from app.models.finding import Finding
from app.models.report import Report
from app.models.scan import Scan, ScanEvent
from app.models.target import Target
from app.schemas.scan import ScanCreate
from app.services import deep_scan as deep_scan_module
from app.services.deep_scan import DeepScanResult, run_deep_scan
from app.services.fast_scanner import FastScanResult, run_fast_scan
from app.services.report_generator import build_report, render_report_json
from app.services.scan_broker import scan_broker
from app.services.scope import TargetScope, build_scope
from app.services import target_verification as tv
from app.models.verified_target import AuditLog, VerifiedTarget

logger = logging.getLogger("scanner.manager")


class UnverifiedTargetError(PermissionError):
    """Active testing was requested against an unverified deployment."""

# Scan columns the emit() callback is allowed to patch directly.
_PATCHABLE_COLUMNS = {
    "status", "deep_progress", "urls_discovered", "apis_discovered",
    "parameters_discovered", "subdomains_discovered",
    "security_checks_completed", "findings_count", "ai_status",
    "initial_risk", "final_risk", "error_message", "risk_score",
}


def scan_snapshot(scan: Scan) -> dict:
    """Serialise the live-relevant scan state for SSE and reconnects."""
    try:
        fast_result = json.loads(scan.fast_result_json) if scan.fast_result_json else None
    except (ValueError, TypeError):
        fast_result = None
    try:
        checks_done = json.loads(scan.checks_done_json) if scan.checks_done_json else []
    except (ValueError, TypeError):
        checks_done = []

    def _load(raw, default):
        try:
            return json.loads(raw) if raw else default
        except (ValueError, TypeError):
            return default

    return {
        "id": str(scan.id),
        "status": scan.status,
        "initial_risk": scan.initial_risk,
        "final_risk": scan.final_risk,
        "deep_progress": scan.deep_progress,
        "urls_discovered": scan.urls_discovered,
        "apis_discovered": scan.apis_discovered,
        "parameters_discovered": scan.parameters_discovered,
        "subdomains_discovered": scan.subdomains_discovered,
        "security_checks_completed": scan.security_checks_completed,
        "findings_count": scan.findings_count,
        "ai_status": scan.ai_status,
        "risk_score": scan.risk_score,
        "requests_made": scan.requests_made,
        "error_message": scan.error_message,
        "checks_done": checks_done,
        "fast_result": fast_result,
        "passive_only": scan.passive_only,
        # Deterministic assessment + the test matrix / coverage.
        "overall_risk": scan.overall_risk,
        "assessment_confidence": scan.assessment_confidence,
        "assessment_coverage": scan.assessment_coverage,
        "assessment_warning": scan.assessment_warning,
        "attack_matrix": _load(scan.attack_matrix_json, []),
        "attack_coverage": _load(scan.attack_coverage_json, {}),
        "coverage": _load(scan.coverage_json, {}),
        "attack_logs": _load(scan.attack_logs_json, []),
        "anomaly": _load(scan.anomaly_json, {}),
        "attack_graph": _load(scan.attack_graph_json, {}),
        "crawl_strategies": _load(scan.crawl_strategies_json, {}),
    }


class ScanManager:
    def __init__(self) -> None:
        # scan_id(str) -> cancellation flag / running task, to support cancel
        # and prevent premature GC of the background task.
        self._cancel_flags: dict[str, asyncio.Event] = {}
        self._tasks: dict[str, asyncio.Task] = {}

    # ------------------------------------------------------------------ create

    async def get_or_create_target(
        self, db: AsyncSession, scope: TargetScope
    ) -> Target:
        result = await db.execute(
            select(Target).where(Target.base_url == scope.base_url)
        )
        target = result.scalar_one_or_none()
        if target is not None:
            return target
        target = Target(
            base_url=scope.base_url,
            hostname=scope.hostname,
            authorization_confirmed=True,
            allowed_domains=",".join(sorted(scope.allowed_hosts)),
        )
        db.add(target)
        await db.flush()
        return target

    async def create_scan(
        self,
        db: AsyncSession,
        payload: ScanCreate,
        *,
        user_id: uuid.UUID | None = None,
    ) -> Scan:
        """Validate + persist a scan, then launch it in the background.

        Raises InvalidTargetError if the URL cannot be scanned (the API layer
        turns this into a 400).
        """
        scope = build_scope(payload.target_url)
        target = await self.get_or_create_target(db, scope)

        # --- Authorization boundary ---------------------------------------
        # TESTING-ONLY CHANGE: the DNS/HTTP/meta-tag ownership-verification
        # requirement (VerifiedTarget lookup + is_active_testing_allowed) has
        # been removed here. Active testing now runs against ANY target as
        # soon as the caller checks the "I own this site..." confirmation
        # box (`payload.is_authorized`) — no proof of control is required
        # anymore. This is a real reduction in safety: re-add the
        # VerifiedTarget check before this is ever used against real users.
        wants_active = payload.is_authorized
        active_enabled = wants_active
        authorization_status = "LOCAL" if tv.is_local_target(scope.hostname) else "UNVERIFIED_BYPASS"
        scan_type = "AUTHORIZED_DEPLOYMENT" if active_enabled else "PASSIVE_WEB"

        db.add(AuditLog(
            user_id=user_id,
            action="active_scan_started" if active_enabled else "passive_scan_started",
            target=scope.hostname,
            result="allowed",
            detail=f"scan_type={scan_type}; authorization={authorization_status} "
            "(verification requirement disabled for testing)",
        ))

        scan = Scan(
            target_id=target.id,
            user_id=user_id,
            status=ScanStatus.QUEUED.value,
            modules="fast,deep",
            max_requests=payload.max_requests or 0,
            concurrency=payload.concurrency or 0,
            rate_limit_per_second=payload.rate_limit_per_second or 0,
            # Without a confirmed authorization statement the scan stays
            # read-only: discovery and passive checks, no attack payloads.
            passive_only=not active_enabled,
            authenticated_scan=bool(payload.authenticated_scan),
            scan_type=scan_type,
            authorization_status=authorization_status,
        )
        db.add(scan)
        await db.flush()
        db.add(
            ScanEvent(
                scan_id=scan.id,
                event_type="scan_created",
                message=f"Scan queued for {scope.hostname}.",
            )
        )
        await db.commit()
        await db.refresh(scan)

        self._launch(scan.id, scope)
        return scan

    def _launch(self, scan_id: uuid.UUID, scope: TargetScope) -> None:
        key = str(scan_id)
        cancel = asyncio.Event()
        self._cancel_flags[key] = cancel
        task = asyncio.create_task(self._run(scan_id, scope, cancel))
        self._tasks[key] = task
        task.add_done_callback(lambda _t: self._cleanup(key))

    def _cleanup(self, key: str) -> None:
        self._tasks.pop(key, None)
        self._cancel_flags.pop(key, None)

    # --------------------------------------------------------------- execution

    async def _run(
        self,
        scan_id: uuid.UUID,
        scope: TargetScope,
        cancel: asyncio.Event,
    ) -> None:
        key = str(scan_id)

        async def emit(patch: dict) -> None:
            await self._apply_patch(scan_id, patch)

        passive_only = False
        auth_header: str | None = None
        auth_header_b: str | None = None
        try:
            async with AsyncSessionLocal() as db:
                scan = await db.get(Scan, scan_id)
                if scan is None:
                    return
                passive_only = scan.passive_only
                # A test credential is only ever used for a scan that's
                # already running active tests against a verified target,
                # and only when the user explicitly opted into authenticated
                # scanning — never for passive-only scans, and never fetched
                # otherwise.
                if not passive_only and scan.authenticated_scan and scan.user_id is not None:
                    verified = (await db.execute(
                        select(VerifiedTarget).where(
                            VerifiedTarget.user_id == scan.user_id,
                            VerifiedTarget.hostname == scope.hostname,
                            VerifiedTarget.verification_status == tv.VERIFIED,
                        )
                    )).scalar_one_or_none()
                    if verified is not None:
                        auth_header = verified.auth_header
                        auth_header_b = verified.auth_header_b
                # A crawl of this target's frontend can capture calls to a
                # separate backend origin (e.g. a Vercel SPA calling a Render
                # API) via the browser network layer. Testing that origin is
                # only safe if the same user has independently demonstrated
                # control of it too — otherwise a captured call to some
                # unrelated third-party API would get attacked with no
                # authorization at all. Widening allowed_hosts here (rather
                # than in scope.py) is what makes it in-scope for both crawl
                # navigation and attack eligibility, without weakening the
                # scope check for anyone who hasn't verified a second host.
                if scan.user_id is not None:
                    other_hosts = (await db.execute(
                        select(VerifiedTarget.hostname).where(
                            VerifiedTarget.user_id == scan.user_id,
                            VerifiedTarget.verification_status == tv.VERIFIED,
                        )
                    )).scalars().all()
                    scope.allowed_hosts.update(other_hosts)
                scan.status = ScanStatus.FAST_SCANNING.value
                scan.started_at = datetime.now(timezone.utc)
                await db.commit()
                await self._publish(scan_id)

            # ---- Stage 1: Fast scan ----
            fast = await run_fast_scan(scope)
            await self._store_fast_result(scan_id, fast, cancel)
            if not fast.reachable:
                return  # already marked FAILED

            if cancel.is_set():
                await self._finish_cancelled(scan_id)
                return

            # ---- Stage 2: Deep scan ----
            await emit({"status": ScanStatus.DEEP_SCANNING.value})
            try:
                deep = await asyncio.wait_for(
                    run_deep_scan(
                        scope,
                        fast,
                        emit=emit,
                        is_cancelled=cancel.is_set,
                        passive_only=passive_only,
                        auth_header=auth_header,
                        auth_header_b=auth_header_b,
                    ),
                    timeout=deep_scan_module.settings.DEEP_SCAN_TIMEOUT_SECONDS,
                )
            except asyncio.TimeoutError:
                await self._persist_partial_timeout(scan_id)
                return
            except deep_scan_module._Cancelled:
                await self._finish_cancelled(scan_id)
                return

            await self._store_deep_result(scan_id, fast, deep)

        except MemoryError as exc:  # pragma: no cover - defensive top-level guard
            logger.exception("Scan %s ran out of memory", scan_id)
            await self._fail(
                scan_id,
                "The scan ran out of memory on this deployment. "
                "Use a smaller target, lower scan profile, or a larger backend plan.",
            )
        except Exception as exc:  # pragma: no cover - defensive top-level guard
            logger.exception("Scan %s failed", scan_id)
            detail = f"{type(exc).__name__}: {exc}".strip()
            if len(detail) > 180:
                detail = detail[:180].rstrip() + "..."
            await self._fail(scan_id, f"The scan failed due to an internal error ({detail}).")

    # ------------------------------------------------------------- persistence

    async def _apply_patch(self, scan_id: uuid.UUID, patch: dict) -> None:
        async with AsyncSessionLocal() as db:
            scan = await db.get(Scan, scan_id)
            if scan is None:
                return
            for key, value in patch.items():
                if key == "checks_done":
                    scan.checks_done_json = json.dumps(value)
                elif key in _PATCHABLE_COLUMNS:
                    setattr(scan, key, value)
            await db.commit()
            await db.refresh(scan)
            self._publish_snapshot(scan)

    async def _store_fast_result(
        self, scan_id: uuid.UUID, fast: FastScanResult, cancel: asyncio.Event
    ) -> None:
        async with AsyncSessionLocal() as db:
            scan = await db.get(Scan, scan_id)
            if scan is None:
                return
            scan.fast_result_json = json.dumps(fast.to_dict())
            scan.initial_risk = fast.initial_risk
            if not fast.reachable:
                scan.status = ScanStatus.FAILED.value
                scan.error_message = fast.error_message
                scan.completed_at = datetime.now(timezone.utc)
                db.add(
                    ScanEvent(
                        scan_id=scan.id,
                        event_type="scan_failed",
                        message=fast.error_message,
                    )
                )
            else:
                scan.status = ScanStatus.INITIAL_RESULT_READY.value
                db.add(
                    ScanEvent(
                        scan_id=scan.id,
                        event_type="initial_result",
                        message=f"Initial assessment ready: {fast.initial_risk} risk.",
                    )
                )
            await db.commit()
            await db.refresh(scan)
            self._publish_snapshot(scan)

    async def _store_deep_result(
        self, scan_id: uuid.UUID, fast: FastScanResult, deep: DeepScanResult
    ) -> None:
        async with AsyncSessionLocal() as db:
            scan = await db.get(Scan, scan_id)
            if scan is None:
                return

            # Endpoints (also index by URL so params can attach to one).
            endpoint_rows: dict[str, DiscoveredEndpoint] = {}
            for ep in deep.endpoints:
                row = DiscoveredEndpoint(
                    scan_id=scan.id,
                    url=ep.url[:2048],
                    method=ep.method,
                    source=ep.source,
                    discovery_method=ep.discovery_method,
                    status_code=ep.status_code,
                    content_type=ep.content_type[:256],
                    response_size=ep.response_size,
                )
                db.add(row)
                endpoint_rows.setdefault(ep.url, row)

            # Parameters: ensure each has a parent endpoint row.
            for p in deep.params:
                parent = endpoint_rows.get(p.url)
                if parent is None:
                    parent = DiscoveredEndpoint(
                        scan_id=scan.id,
                        url=p.url[:2048],
                        method=p.method,
                        source="parameter_discovery",
                        discovery_method="parameter_discovery",
                    )
                    db.add(parent)
                    endpoint_rows[p.url] = parent
                db.add(
                    Parameter(
                        endpoint=parent,
                        name=p.name[:256],
                        param_type=p.param_type,
                        example_value=(p.example_value or "")[:2000],
                    )
                )

            # Subdomains
            for sub in deep.subdomains:
                db.add(
                    Subdomain(
                        scan_id=scan.id,
                        hostname=sub.hostname[:512],
                        resolved_ip=sub.resolved_ip[:64],
                        source=sub.source,
                    )
                )

            # Findings — deterministic evidence, with affected-URL counts.
            for cand in deep.findings:
                evidence = cand.evidence
                if cand.affected_urls > 1:
                    evidence = f"Affects {cand.affected_urls} locations. " + evidence
                db.add(
                    Finding(
                        scan_id=scan.id,
                        title=cand.title[:256],
                        category=cand.category[:128],
                        severity=cand.severity,
                        confidence=cand.confidence,
                        url=cand.url[:2048],
                        method=cand.method,
                        parameter=cand.parameter[:256],
                        evidence=evidence,
                        request_summary=cand.request_summary,
                        response_summary=cand.response_summary,
                        description=cand.description,
                        impact=cand.impact,
                        remediation=cand.remediation,
                        risk_score=cand.risk_score,
                        fingerprint=cand.key()[:512],
                        parameter_location=cand.parameter_location[:32],
                        auth_context=cand.auth_context[:128],
                        reproducibility=cand.reproducibility[:256],
                    )
                )

            # Roll-up counters + terminal state
            scan.urls_discovered = len(deep.endpoints)
            # Every discovery method that can surface a real API endpoint —
            # not just the static wordlist/OpenAPI path (api_discovery), but
            # JS-bundle-mined paths and the browser crawler's own
            # behavior-based network classification. Undercounting this is
            # exactly what made a JS-heavy SPA report "APIs: 0".
            scan.apis_discovered = sum(
                1 for e in deep.endpoints
                if e.discovery_method in ("api_discovery", "js_bundle", "browser_network")
            )
            scan.parameters_discovered = len(deep.params)
            scan.subdomains_discovered = len(deep.subdomains)
            scan.findings_count = len(deep.findings)
            # Risk is the deterministic 5-factor formula: overall = highest
            # confirmed finding's score. Coverage/confidence are separate.
            scan.overall_risk = deep.overall_risk
            scan.risk_score = deep.risk_score
            scan.final_risk = deep.final_risk
            scan.assessment_confidence = deep.assessment_confidence
            scan.assessment_coverage = deep.assessment_coverage
            scan.assessment_warning = deep.assessment_warning
            scan.attack_matrix_json = json.dumps(deep.attack_matrix or [])
            scan.attack_coverage_json = json.dumps(deep.attack_coverage or {})
            scan.coverage_json = json.dumps(deep.coverage or {})
            scan.attack_logs_json = json.dumps(deep.attack_logs or [])
            scan.anomaly_json = json.dumps(deep.anomaly_scores or {})
            scan.attack_graph_json = json.dumps(deep.attack_graph or {})
            scan.crawl_strategies_json = json.dumps(deep.crawl_strategies or {})
            scan.requests_made = deep.requests_made
            scan.deep_progress = 100
            scan.status = ScanStatus.COMPLETED.value
            scan.completed_at = datetime.now(timezone.utc)
            db.add(
                ScanEvent(
                    scan_id=scan.id,
                    event_type="scan_completed",
                    message=(f"Scan complete: {len(deep.findings)} findings; "
                             f"risk {deep.final_risk} ({deep.overall_risk}/100), "
                             f"confidence {deep.assessment_confidence}, "
                             f"coverage {deep.assessment_coverage}%."),
                )
            )
            await db.flush()

            # Report artifact (JSON inline).
            await db.refresh(scan, ["target"])
            findings_result = await db.execute(
                select(Finding).where(Finding.scan_id == scan.id)
            )

            # Remediation verification: compare against the same target's
            # two most recent prior completed scans (if any) to classify
            # each current finding as OPEN/REGRESSED/UNVERIFIED, and report
            # what was fixed since the last scan. Never touches source code.
            prior_scans = (await db.execute(
                select(Scan.id)
                .where(Scan.target_id == scan.target_id, Scan.id != scan.id,
                       Scan.status == ScanStatus.COMPLETED.value)
                .order_by(Scan.completed_at.desc())
                .limit(2)
            )).scalars().all()
            prior_fingerprints = None
            prior_prior_fingerprints = None
            if prior_scans:
                prior_fingerprints = set((await db.execute(
                    select(Finding.fingerprint).where(Finding.scan_id == prior_scans[0])
                )).scalars().all())
                if len(prior_scans) > 1:
                    prior_prior_fingerprints = set((await db.execute(
                        select(Finding.fingerprint).where(Finding.scan_id == prior_scans[1])
                    )).scalars().all())

            report = build_report(
                scan, list(findings_result.scalars().all()),
                prior_fingerprints=prior_fingerprints,
                prior_prior_fingerprints=prior_prior_fingerprints,
            )
            db.add(
                Report(
                    scan_id=scan.id,
                    format="json",
                    file_path=render_report_json(report),
                )
            )
            await db.commit()
            await db.refresh(scan)
            self._publish_snapshot(scan)

    async def _persist_partial_timeout(self, scan_id: uuid.UUID) -> None:
        async with AsyncSessionLocal() as db:
            scan = await db.get(Scan, scan_id)
            if scan is None:
                return
            scan.status = ScanStatus.COMPLETED.value
            scan.deep_progress = 100
            scan.completed_at = datetime.now(timezone.utc)
            scan.ai_status = scan.ai_status or "Deep scan stopped at time limit."
            db.add(
                ScanEvent(
                    scan_id=scan.id,
                    event_type="scan_timeout",
                    message="Deep scan reached its time limit; returning "
                    "partial results.",
                )
            )
            await db.commit()
            await db.refresh(scan)
            self._publish_snapshot(scan)

    async def _fail(self, scan_id: uuid.UUID, message: str) -> None:
        async with AsyncSessionLocal() as db:
            scan = await db.get(Scan, scan_id)
            if scan is None:
                return
            scan.status = ScanStatus.FAILED.value
            scan.error_message = message
            scan.completed_at = datetime.now(timezone.utc)
            db.add(
                ScanEvent(
                    scan_id=scan.id, event_type="scan_failed", message=message
                )
            )
            await db.commit()
            await db.refresh(scan)
            self._publish_snapshot(scan)

    async def _finish_cancelled(self, scan_id: uuid.UUID) -> None:
        async with AsyncSessionLocal() as db:
            scan = await db.get(Scan, scan_id)
            if scan is None:
                return
            scan.status = ScanStatus.CANCELLED.value
            scan.completed_at = datetime.now(timezone.utc)
            await db.commit()
            await db.refresh(scan)
            self._publish_snapshot(scan)

    # -------------------------------------------------------------- publishing

    async def _publish(self, scan_id: uuid.UUID) -> None:
        async with AsyncSessionLocal() as db:
            scan = await db.get(Scan, scan_id)
            if scan is not None:
                self._publish_snapshot(scan)

    def _publish_snapshot(self, scan: Scan) -> None:
        scan_broker.publish(str(scan.id), scan_snapshot(scan))

    # ------------------------------------------------------------------ cancel

    async def cancel_scan(self, db: AsyncSession, scan_id: uuid.UUID) -> Scan | None:
        scan = await db.get(Scan, scan_id)
        if scan is None:
            return None
        # Signal the background task to stop cooperatively.
        flag = self._cancel_flags.get(str(scan_id))
        if flag is not None:
            flag.set()
        if scan.status in ACTIVE_SCAN_STATUSES:
            scan.status = ScanStatus.CANCELLED.value
            scan.completed_at = datetime.now(timezone.utc)
            db.add(
                ScanEvent(
                    scan_id=scan.id,
                    event_type="scan_cancelled",
                    message="Scan cancelled by user.",
                )
            )
            await db.commit()
            await db.refresh(scan)
            self._publish_snapshot(scan)
        return scan


scan_manager = ScanManager()
