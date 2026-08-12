from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.enums import ACTIVE_SCAN_STATUSES
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.user import User
from app.schemas.scan import ScanRead
from app.services.auth import require_developer

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


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
