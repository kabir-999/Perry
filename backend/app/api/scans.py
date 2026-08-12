import asyncio
import json
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import AsyncSessionLocal, get_db
from app.models.endpoint import DiscoveredEndpoint, Subdomain
from app.models.enums import TERMINAL_SCAN_STATUSES, UserRole
from app.models.finding import Finding
from app.models.report import Report
from app.models.repository import Repository, SourceFinding
from app.models.scan import Scan, ScanEvent
from app.models.user import User
from app.schemas.endpoint import DiscoveredEndpointRead, SubdomainRead
from app.schemas.finding import FindingRead
from app.schemas.repository import RepositoryRead, SourceFindingRead
from app.schemas.scan import ScanCreate, ScanEventRead, ScanRead
from app.services.auth import decode_access_token, require_developer
from app.services.scan_broker import scan_broker
from app.services.scan_manager import scan_manager, scan_snapshot
from app.services.scope import InvalidTargetError

router = APIRouter(prefix="/scans", tags=["scans"])


async def _owned_scan(scan_id: uuid.UUID, db: AsyncSession, user: User) -> Scan:
    """Load a scan, refusing to reveal other accounts' scans.

    A scan belonging to someone else is reported as missing rather than
    forbidden, so scan ids cannot be probed for existence.
    """
    scan = await db.get(Scan, scan_id)
    if scan is None or (scan.user_id is not None and scan.user_id != user.id):
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.post("", response_model=ScanRead, status_code=201)
async def create_scan(
    payload: ScanCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_developer),
):
    """Create and immediately launch a scan.

    The user supplies only a URL (+ authorization). The fast scan starts in
    the background right away; the client should open the SSE stream to watch
    the initial result and deep-scan progress arrive live.
    """
    try:
        scan = await scan_manager.create_scan(db, payload, user_id=user.id)
    except InvalidTargetError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return scan


@router.get("", response_model=list[ScanRead])
async def list_scans(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_developer),
):
    result = await db.execute(
        select(Scan).where(Scan.user_id == user.id).order_by(Scan.created_at.desc())
    )
    return result.scalars().all()


@router.get("/{scan_id}", response_model=ScanRead)
async def get_scan(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_developer),
):
    return await _owned_scan(scan_id, db, user)


@router.get("/{scan_id}/live")
async def get_scan_live(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_developer),
):
    """Current live snapshot (status, progress, counters, parsed fast result).
    Used for the initial page load before the SSE stream takes over."""
    scan = await _owned_scan(scan_id, db, user)
    return scan_snapshot(scan)


@router.get("/{scan_id}/stream")
async def stream_scan(scan_id: uuid.UUID, request: Request, token: str | None = None):
    """Server-Sent Events stream of live scan progress.

    EventSource cannot send an Authorization header, so this route takes the
    access token as a query parameter instead. It is still fully authenticated
    and ownership-checked — it just carries the credential differently.
    """
    payload = decode_access_token(token or "")
    if payload is None or payload.get("role") != UserRole.DEVELOPER.value:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        user_id = uuid.UUID(str(payload.get("sub")))
    except (ValueError, TypeError):
        raise HTTPException(status_code=401, detail="Not authenticated")

    async with AsyncSessionLocal() as db:
        scan = await db.get(Scan, scan_id)
        if scan is None or (scan.user_id is not None and scan.user_id != user_id):
            raise HTTPException(status_code=404, detail="Scan not found")

    async def event_gen():
        async with AsyncSessionLocal() as db:
            scan = await db.get(Scan, scan_id)
            if scan is None:
                yield f"event: error\ndata: {json.dumps({'error': 'not_found'})}\n\n"
                return
            snapshot = scan_snapshot(scan)

        yield f"data: {json.dumps(snapshot)}\n\n"
        if snapshot["status"] in TERMINAL_SCAN_STATUSES:
            return

        queue = scan_broker.subscribe(str(scan_id))
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    message = await asyncio.wait_for(queue.get(), timeout=15.0)
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
                    continue
                yield f"data: {json.dumps(message)}\n\n"
                if message.get("status") in TERMINAL_SCAN_STATUSES:
                    break
        finally:
            scan_broker.unsubscribe(str(scan_id), queue)

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/{scan_id}/findings", response_model=list[FindingRead])
async def get_scan_findings(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_developer),
):
    await _owned_scan(scan_id, db, user)
    result = await db.execute(
        select(Finding)
        .where(Finding.scan_id == scan_id)
        .order_by(Finding.risk_score.desc(), Finding.created_at.desc())
    )
    return result.scalars().all()


@router.get("/{scan_id}/endpoints", response_model=list[DiscoveredEndpointRead])
async def get_scan_endpoints(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_developer),
):
    await _owned_scan(scan_id, db, user)
    result = await db.execute(
        select(DiscoveredEndpoint)
        .where(DiscoveredEndpoint.scan_id == scan_id)
        .order_by(DiscoveredEndpoint.created_at.desc())
    )
    return result.scalars().all()


@router.get("/{scan_id}/subdomains", response_model=list[SubdomainRead])
async def get_scan_subdomains(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_developer),
):
    await _owned_scan(scan_id, db, user)
    result = await db.execute(
        select(Subdomain)
        .where(Subdomain.scan_id == scan_id)
        .order_by(Subdomain.hostname.asc())
    )
    return result.scalars().all()


@router.get("/{scan_id}/source-findings", response_model=list[SourceFindingRead])
async def get_scan_source_findings(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_developer),
):
    """Per-issue source-code findings (file, line, and the redacted code line).

    This is what powers the code blocks on the scan detail page; the scan
    snapshot only carries aggregate repo counts.
    """
    await _owned_scan(scan_id, db, user)
    result = await db.execute(
        select(SourceFinding)
        .where(SourceFinding.scan_id == scan_id)
        .order_by(SourceFinding.file.asc(), SourceFinding.line.asc())
    )
    return result.scalars().all()


@router.get("/{scan_id}/repositories", response_model=list[RepositoryRead])
async def get_scan_repositories(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_developer),
):
    await _owned_scan(scan_id, db, user)
    result = await db.execute(
        select(Repository)
        .where(Repository.scan_id == scan_id)
        .order_by(Repository.created_at.desc())
    )
    return result.scalars().all()


@router.get("/{scan_id}/events", response_model=list[ScanEventRead])
async def get_scan_events(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_developer),
):
    await _owned_scan(scan_id, db, user)
    result = await db.execute(
        select(ScanEvent)
        .where(ScanEvent.scan_id == scan_id)
        .order_by(ScanEvent.created_at.asc())
    )
    return result.scalars().all()


@router.get("/{scan_id}/report")
async def get_scan_report(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_developer),
):
    """Return the generated JSON report for a completed scan."""
    await _owned_scan(scan_id, db, user)
    result = await db.execute(
        select(Report)
        .where(Report.scan_id == scan_id)
        .order_by(Report.created_at.desc())
        .limit(1)
    )
    report = result.scalar_one_or_none()
    if report is None:
        raise HTTPException(status_code=404, detail="Report not ready")
    try:
        return json.loads(report.file_path)
    except (ValueError, TypeError):
        raise HTTPException(status_code=500, detail="Report is corrupted")


@router.post("/{scan_id}/cancel", response_model=ScanRead)
async def cancel_scan(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_developer),
):
    await _owned_scan(scan_id, db, user)
    scan = await scan_manager.cancel_scan(db, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan
