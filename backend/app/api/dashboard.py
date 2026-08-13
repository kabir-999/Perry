import uuid
from datetime import datetime

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.enums import ACTIVE_SCAN_STATUSES, ScanStatus
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User
from app.schemas.scan import ScanRead
from app.services.auth import require_developer

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

# Points per project chart — enough to show a trend without an unbounded
# payload for a target that's been scanned hundreds of times.
_MAX_POINTS_PER_PROJECT = 30


class SeverityCount(BaseModel):
    severity: str
    count: int


class DashboardSummary(BaseModel):
    total_scans: int
    active_scans: int
    total_findings: int
    severity_distribution: list[SeverityCount]
    recent_scans: list[ScanRead]


@router.get("/summary", response_model=DashboardSummary)
async def get_dashboard_summary(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_developer),
):
    # Every figure is scoped to the signed-in developer's own scans.
    mine = Scan.user_id == user.id

    total_scans = (
        await db.execute(select(func.count(Scan.id)).where(mine))
    ).scalar_one()

    active_scans = (
        await db.execute(
            select(func.count(Scan.id)).where(
                mine, Scan.status.in_(ACTIVE_SCAN_STATUSES)
            )
        )
    ).scalar_one()

    my_scan_ids = select(Scan.id).where(mine).scalar_subquery()

    total_findings = (
        await db.execute(
            select(func.count(Finding.id)).where(Finding.scan_id.in_(my_scan_ids))
        )
    ).scalar_one()

    severity_rows = (
        await db.execute(
            select(Finding.severity, func.count(Finding.id))
            .where(Finding.scan_id.in_(my_scan_ids))
            .group_by(Finding.severity)
        )
    ).all()

    recent_scans_result = await db.execute(
        select(Scan).where(mine).order_by(Scan.created_at.desc()).limit(10)
    )

    return DashboardSummary(
        total_scans=total_scans,
        active_scans=active_scans,
        total_findings=total_findings,
        severity_distribution=[
            SeverityCount(severity=row[0], count=row[1]) for row in severity_rows
        ],
        recent_scans=list(recent_scans_result.scalars().all()),
    )


class ProjectSeriesPoint(BaseModel):
    scan_id: uuid.UUID
    created_at: datetime
    risk_score: int
    findings_count: int


class ProjectSeries(BaseModel):
    target_id: uuid.UUID
    label: str
    points: list[ProjectSeriesPoint]


@router.get("/projects", response_model=list[ProjectSeries])
async def get_project_series(
    target_id: uuid.UUID | None = None,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_developer),
):
    """One time series per project (Target) the caller owns — e.g. a
    portfolio site's scans plot on one chart, a different site's scans plot
    on a separate one. Only completed scans, since risk_score/findings_count
    aren't meaningful mid-run. Pass `target_id` to fetch just one project's
    series (the project detail page) instead of every project's."""
    filters = [Scan.user_id == user.id, Scan.status == ScanStatus.COMPLETED.value]
    if target_id is not None:
        filters.append(Scan.target_id == target_id)
    rows = (
        await db.execute(
            select(
                Scan.target_id,
                Target.hostname,
                Target.base_url,
                Scan.id,
                Scan.created_at,
                Scan.risk_score,
                Scan.findings_count,
            )
            .join(Target, Target.id == Scan.target_id)
            .where(*filters)
            .order_by(Scan.target_id, Scan.created_at.asc())
        )
    ).all()

    series_by_target: dict[uuid.UUID, ProjectSeries] = {}
    for target_id, hostname, base_url, scan_id, created_at, risk_score, findings_count in rows:
        series = series_by_target.setdefault(
            target_id,
            ProjectSeries(target_id=target_id, label=hostname or base_url, points=[]),
        )
        series.points.append(
            ProjectSeriesPoint(
                scan_id=scan_id, created_at=created_at,
                risk_score=risk_score, findings_count=findings_count,
            )
        )

    for series in series_by_target.values():
        series.points = series.points[-_MAX_POINTS_PER_PROJECT:]

    return list(series_by_target.values())


class ProjectSummary(BaseModel):
    target_id: uuid.UUID
    label: str
    base_url: str
    scan_count: int
    latest_scan_id: uuid.UUID
    latest_scan_at: datetime
    latest_status: str
    latest_risk_score: int
    latest_final_risk: str


@router.get("/targets", response_model=list[ProjectSummary])
async def list_project_targets(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_developer),
):
    """Every distinct website (Target) the caller has ever scanned — the
    same URL scanned twice is one project with two scans, not two projects
    (Target rows are already deduplicated by base_url, see
    ScanManager.get_or_create_target). Unlike /projects, this includes
    targets whose only scan is still running or failed, so a fresh project
    is navigable immediately instead of only after its first scan finishes."""
    rows = (
        await db.execute(
            select(Scan, Target.hostname, Target.base_url)
            .join(Target, Target.id == Scan.target_id)
            .where(Scan.user_id == user.id)
            .order_by(Scan.target_id, Scan.created_at.desc())
        )
    ).all()

    summaries: dict[uuid.UUID, ProjectSummary] = {}
    counts: dict[uuid.UUID, int] = {}
    for scan, hostname, base_url in rows:
        counts[scan.target_id] = counts.get(scan.target_id, 0) + 1
        if scan.target_id not in summaries:
            # Rows are ordered newest-first within each target, so the
            # first one seen per target_id is its latest scan.
            summaries[scan.target_id] = ProjectSummary(
                target_id=scan.target_id,
                label=hostname or base_url,
                base_url=base_url,
                scan_count=0,
                latest_scan_id=scan.id,
                latest_scan_at=scan.created_at,
                latest_status=scan.status,
                latest_risk_score=scan.risk_score,
                latest_final_risk=scan.final_risk,
            )

    for target_id, summary in summaries.items():
        summary.scan_count = counts[target_id]

    return sorted(summaries.values(), key=lambda s: s.latest_scan_at, reverse=True)
