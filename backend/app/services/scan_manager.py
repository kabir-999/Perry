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
from app.models.repository import Repository, SourceFinding
from app.models.scan import Scan, ScanEvent
from app.models.target import Target
from app.schemas.scan import ScanCreate
from app.services import deep_scan as deep_scan_module
from app.services.deep_scan import DeepScanResult, run_deep_scan
from app.services.fast_scanner import FastScanResult, run_fast_scan
from app.services.reachability import dependency_severity
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
    "initial_risk", "final_risk", "error_message",
    "risk_score", "ai_summary", "ai_recommendation", "ai_analyzed", "ai_error",
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
    try:
        repo_info = json.loads(scan.repo_info_json) if scan.repo_info_json else None
    except (ValueError, TypeError):
        repo_info = None
    try:
        risk_data = json.loads(scan.risk_factors_json) if scan.risk_factors_json else {}
    except (ValueError, TypeError):
        risk_data = {}
    try:
        test_results = json.loads(scan.test_results_json) if scan.test_results_json else []
    except (ValueError, TypeError):
        test_results = []
    try:
        sentinel_risk = (
            json.loads(scan.sentinel_risk_json) if scan.sentinel_risk_json else None
        )
    except (ValueError, TypeError):
        sentinel_risk = None
    # An empty object is indistinguishable from "no data" on the client, so
    # normalise it away.
    if not sentinel_risk:
        sentinel_risk = None
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
        "ai_analyzed": scan.ai_analyzed,
        "ai_error": scan.ai_error,
        "risk_score": scan.risk_score,
        "ai_summary": scan.ai_summary,
        "ai_recommendation": scan.ai_recommendation,
        "risk_factors": risk_data.get("risk_factors", []),
        "ai_statistics": risk_data.get("statistics", {}),
        "test_results": test_results,
        "requests_made": scan.requests_made,
        "error_message": scan.error_message,
        "checks_done": checks_done,
        "fast_result": fast_result,
        "repo_info": repo_info,
        "sentinel_risk": sentinel_risk,
        "passive_only": scan.passive_only,
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
        include_repo: bool = True,
    ) -> Scan:
        """Validate + persist a scan, then launch it in the background.

        Raises InvalidTargetError if the URL cannot be scanned (the API layer
        turns this into a 400).
        """
        scope = build_scope(payload.target_url)
        target = await self.get_or_create_target(db, scope)

        # --- Authorization boundary -------------------------------------
        # Active testing sends crafted payloads at a live host, so it runs
        # only against a deployment whose control the user has demonstrated.
        # A local/private address is the developer's own machine and needs no
        # challenge. Everything else without a VERIFIED target is downgraded
        # to PASSIVE: ordinary requests only, nothing crafted.
        wants_active = payload.is_authorized
        authorization_status = tv.UNVERIFIED
        scan_type = "PASSIVE_WEB"

        if tv.is_local_target(scope.hostname):
            authorization_status = "LOCAL"
            scan_type = "AUTHORIZED_DEPLOYMENT" if wants_active else "PASSIVE_WEB"
            allowed = True
        else:
            verified = None
            if user_id is not None:
                verified = (await db.execute(
                    select(VerifiedTarget).where(
                        VerifiedTarget.user_id == user_id,
                        VerifiedTarget.hostname == scope.hostname,
                    )
                )).scalar_one_or_none()
            allowed, reason = tv.is_active_testing_allowed(verified)
            if verified is not None:
                authorization_status = verified.verification_status
            if allowed:
                scan_type = "AUTHORIZED_DEPLOYMENT"

        if wants_active and not allowed:
            # Refuse to run the active half rather than silently doing it.
            raise UnverifiedTargetError(
                "Target verification required. Sentinel scans applications "
                "that you own or are authorized to test. Verify this "
                f"deployment ({scope.hostname}) before starting an active "
                "security scan."
            )

        active_enabled = wants_active and allowed
        db.add(AuditLog(
            user_id=user_id,
            action="active_scan_started" if active_enabled else "passive_scan_started",
            target=scope.hostname,
            result="allowed",
            detail=f"scan_type={scan_type}; authorization={authorization_status}",
        ))

        scan = Scan(
            target_id=target.id,
            user_id=user_id,
            status=ScanStatus.QUEUED.value,
            modules="fast,deep",
            max_requests=payload.max_requests or 0,
            concurrency=payload.concurrency or 0,
            rate_limit_per_second=payload.rate_limit_per_second or 0,
            repo_url=(payload.repo_url or "").strip()[:2048],
            custom_test_cases_json=(
                json.dumps([c.model_dump() for c in payload.custom_test_cases])
                if payload.custom_test_cases else ""
            ),
            # Without a confirmed authorization statement the scan stays
            # read-only: discovery and passive checks, no attack payloads.
            passive_only=not active_enabled,
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

        self._launch(scan.id, scope, include_repo=include_repo)
        return scan

    def _launch(
        self, scan_id: uuid.UUID, scope: TargetScope, *, include_repo: bool = True
    ) -> None:
        key = str(scan_id)
        cancel = asyncio.Event()
        self._cancel_flags[key] = cancel
        task = asyncio.create_task(
            self._run(scan_id, scope, cancel, include_repo=include_repo)
        )
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
        *,
        include_repo: bool = True,
    ) -> None:
        key = str(scan_id)

        async def emit(patch: dict) -> None:
            await self._apply_patch(scan_id, patch)

        repo_url = ""
        passive_only = False
        auth_header: str | None = None
        try:
            async with AsyncSessionLocal() as db:
                scan = await db.get(Scan, scan_id)
                if scan is None:
                    return
                repo_url = scan.repo_url
                passive_only = scan.passive_only
                custom_test_cases = (
                    json.loads(scan.custom_test_cases_json)
                    if scan.custom_test_cases_json else []
                )
                # A test credential is only ever used for a scan that's
                # already running active tests against a verified target —
                # never for passive-only scans, and never fetched otherwise.
                if not passive_only and scan.user_id is not None:
                    verified = (await db.execute(
                        select(VerifiedTarget).where(
                            VerifiedTarget.user_id == scan.user_id,
                            VerifiedTarget.hostname == scope.hostname,
                            VerifiedTarget.verification_status == tv.VERIFIED,
                        )
                    )).scalar_one_or_none()
                    if verified is not None:
                        auth_header = verified.auth_header
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
                        repo_url=repo_url,
                        passive_only=passive_only,
                        include_repo=include_repo,
                        auth_header=auth_header,
                        custom_test_cases=custom_test_cases,
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

        except Exception as exc:  # pragma: no cover - defensive top-level guard
            logger.exception("Scan %s failed", scan_id)
            await self._fail(scan_id, "The scan failed due to an internal error.")

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

            # Repository & Source Findings
            if deep.repo_info and deep.raw_repo_analysis:
                scan.repo_info_json = json.dumps(deep.repo_info)
                repo_row = Repository(
                    scan_id=scan.id,
                    provider=deep.repo_info["provider"],
                    owner=deep.repo_info["owner"][:256],
                    name=deep.repo_info["name"][:256],
                    url=deep.repo_info["url"][:2048],
                    confidence=deep.repo_info["confidence"],
                    status=deep.repo_info["status"],
                    files_analyzed=deep.repo_info.get("files_analyzed", 0),
                )
                db.add(repo_row)
                await db.flush() # flush to get repo_row.id
                
                ra = deep.raw_repo_analysis
                for sf in ra.secret_findings + ra.code_findings:
                    db.add(
                        SourceFinding(
                            scan_id=scan.id,
                            repository_id=repo_row.id,
                            finding_type=sf.finding_type,
                            file=sf.file[:512],
                            line=sf.line,
                            severity=sf.severity,
                            confidence=sf.confidence,
                            evidence=sf.evidence,
                            secret_type=sf.secret_type[:64],
                            redacted_value=sf.redacted_value[:256],
                            code_context=sf.code_context,
                        )
                    )
                for df in ra.dependency_findings:
                    db.add(
                        SourceFinding(
                            scan_id=scan.id,
                            repository_id=repo_row.id,
                            finding_type="dependency",
                            file="package.json",
                            line=0,
                            # Severity follows the reachability ladder, not the
                            # advisory's own rating.
                            severity=dependency_severity(
                                df.classification, df.severity
                            ),
                            # Static analysis never confirms exploitability.
                            confidence="potential",
                            evidence=(
                                f"Package: {df.package} {df.version} "
                                f"({df.dependency_kind})\n"
                                f"Vulnerable range: {df.affected_versions or 'unspecified'}\n"
                                f"Patched version: {df.fixed_version or 'none published'}\n"
                                f"Package imported: {'yes' if df.is_used else 'no'}\n"
                                f"Vulnerable functionality used: "
                                f"{'yes' if df.functionality_used else 'no'}\n"
                                f"Reachable from attacker-controlled input: "
                                f"{'yes' if df.reachable_from_input else 'no path found'}"
                            ),
                            package=df.package[:256],
                            version=df.version[:64],
                            ecosystem=df.ecosystem[:32],
                            advisory_id=df.advisory_id[:128],
                            fixed_version=df.fixed_version[:64],
                            classification=df.classification[:32],
                            vulnerable_range=df.affected_versions[:128],
                            is_direct=df.is_direct,
                            is_used=df.is_used,
                            externally_reachable=(
                                "yes" if df.reachable_from_input else "no path found"
                            ),
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
                    )
                )

            # Roll-up counters + terminal state
            scan.urls_discovered = len(deep.endpoints)
            scan.apis_discovered = sum(
                1 for e in deep.endpoints if e.discovery_method == "api_discovery"
            )
            scan.parameters_discovered = len(deep.params)
            scan.subdomains_discovered = len(deep.subdomains)
            scan.findings_count = len(deep.findings)
            # Risk score/level are authoritative ONLY from the AI analyst.
            scan.ai_analyzed = deep.ai_analyzed
            scan.ai_error = deep.ai_error
            scan.final_risk = deep.final_risk
            scan.risk_score = deep.risk_score
            scan.sentinel_risk_json = json.dumps(deep.sentinel_risk or {})
            scan.ai_summary = deep.ai_summary
            scan.ai_recommendation = deep.ai_recommendation
            scan.risk_factors_json = json.dumps(
                {"risk_factors": deep.risk_factors, "statistics": deep.statistics}
            )
            scan.test_results_json = json.dumps(deep.test_results)
            scan.requests_made = deep.requests_made
            scan.deep_progress = 100
            scan.status = ScanStatus.COMPLETED.value
            scan.completed_at = datetime.now(timezone.utc)
            db.add(
                ScanEvent(
                    scan_id=scan.id,
                    event_type="scan_completed",
                    message=f"Scan complete: {len(deep.findings)} findings; "
                    + (
                        f"AI risk {deep.final_risk} ({deep.risk_score}/100)."
                        if deep.ai_analyzed
                        else "AI analysis unavailable."
                    ),
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
