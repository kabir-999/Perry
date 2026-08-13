"""Deployment targets and ownership verification."""
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.user import User
from app.models.verified_target import AuditLog, VerifiedTarget
from app.services.auth import require_developer
from app.services import target_verification as tv
from app.services.scope import build_scope, InvalidTargetError

router = APIRouter(prefix="/targets", tags=["targets"])


class TargetCreate(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048)
    method: str = Field(default="dns", pattern="^(dns|http|meta)$")


class TargetCredentialSet(BaseModel):
    # Raw header value, e.g. "Authorization: Bearer <token>" or a cookie
    # string. Used only for differential authenticated-vs-unauthenticated
    # testing against this one target; never logged, audited, or returned.
    auth_header: str | None = Field(default=None, max_length=4096)


class TargetRead(BaseModel):
    id: uuid.UUID
    hostname: str
    verification_status: str
    verification_method: str
    active_testing_enabled: bool
    verified_at: datetime | None = None
    verification_expires_at: datetime | None = None
    last_error: str = ""


async def _audit(db, user_id, action, target, result, detail=""):
    """Record a security-sensitive action. Never stores tokens."""
    db.add(AuditLog(user_id=user_id, action=action, target=target,
                    result=result, detail=detail[:500]))


@router.post("", status_code=201)
async def add_target(payload: TargetCreate, db: AsyncSession = Depends(get_db),
                     user: User = Depends(require_developer)):
    """Register a deployment and return its verification challenge."""
    try:
        scope = build_scope(payload.url)
    except InvalidTargetError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    existing = (await db.execute(
        select(VerifiedTarget).where(VerifiedTarget.user_id == user.id,
                                     VerifiedTarget.hostname == scope.hostname)
    )).scalar_one_or_none()

    target = existing or VerifiedTarget(
        user_id=user.id, hostname=scope.hostname,
        verification_token=tv.generate_token(),
    )
    target.verification_method = payload.method
    target.verification_status = tv.VERIFICATION_PENDING
    if existing is None:
        db.add(target)
    await _audit(db, user.id, "target_added", scope.hostname, "pending")
    await db.commit()
    await db.refresh(target)

    builder = {
        "dns": tv.dns_instructions,
        "http": tv.http_instructions,
        "meta": tv.meta_instructions,
    }[payload.method]
    instructions = builder(target.hostname, target.verification_token)
    return {"target": TargetRead.model_validate(target, from_attributes=True).model_dump(mode="json"),
            "verification": instructions}


@router.post("/{target_id}/verify")
async def verify_target(target_id: uuid.UUID, db: AsyncSession = Depends(get_db),
                        user: User = Depends(require_developer)):
    """Run the challenge. Only a pass enables active testing."""
    target = (await db.execute(
        select(VerifiedTarget).where(VerifiedTarget.id == target_id,
                                     VerifiedTarget.user_id == user.id)
    )).scalar_one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")

    result = await tv.run_verification(
        target.hostname, target.verification_token, target.verification_method
    )
    if result.verified:
        target.verification_status = tv.VERIFIED
        target.active_testing_enabled = True
        target.verified_at = datetime.now(timezone.utc)
        target.verification_expires_at = tv.expiry_from()
        target.last_error = ""
    else:
        target.verification_status = tv.VERIFICATION_FAILED
        target.active_testing_enabled = False
        target.last_error = result.detail

    await _audit(db, user.id,
                 "target_verified" if result.verified else "verification_failed",
                 target.hostname, "ok" if result.verified else "failed", result.detail)
    await db.commit()
    await db.refresh(target)
    return {"verified": result.verified, "detail": result.detail,
            "target": TargetRead.model_validate(target, from_attributes=True).model_dump(mode="json")}


@router.post("/{target_id}/credential", status_code=204)
async def set_target_credential(
    target_id: uuid.UUID, payload: TargetCredentialSet,
    db: AsyncSession = Depends(get_db), user: User = Depends(require_developer),
):
    """Set or clear the test credential used for authorization-boundary
    checks against this target. Owner-only. Only honored once the target is
    VERIFIED (enforced at scan time, not here — a target can be verified
    after a credential is set). Never audited: the value itself is a
    credential, not a security event about one."""
    target = (await db.execute(
        select(VerifiedTarget).where(VerifiedTarget.id == target_id,
                                     VerifiedTarget.user_id == user.id)
    )).scalar_one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")

    target.auth_header = (payload.auth_header or "").strip() or None
    await db.commit()


@router.get("", response_model=list[TargetRead])
async def list_targets(db: AsyncSession = Depends(get_db),
                       user: User = Depends(require_developer)):
    """Owned targets. Verification tokens are never included."""
    rows = (await db.execute(
        select(VerifiedTarget).where(VerifiedTarget.user_id == user.id)
        .order_by(VerifiedTarget.created_at.desc())
    )).scalars().all()
    return rows
