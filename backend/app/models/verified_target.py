import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class VerifiedTarget(Base):
    """A deployment the user has demonstrated technical control over.

    Active security testing sends crafted payloads, so it may only run against
    a host whose owner asked for it. Publishing a DNS TXT record or a file at a
    well-known path proves control of the deployment — not legal ownership,
    which no scanner can establish, but enough to show the request came from
    someone who administers the host.
    """

    __tablename__ = "verified_targets"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), index=True
    )

    hostname: Mapped[str] = mapped_column(String(255), index=True)
    # UNVERIFIED | VERIFICATION_PENDING | VERIFIED | VERIFICATION_FAILED | EXPIRED
    verification_status: Mapped[str] = mapped_column(String(32), default="UNVERIFIED")
    verification_method: Mapped[str] = mapped_column(String(16), default="")  # dns | http
    # A per-target nonce, not a credential. Returned only to the owner and
    # never written to logs.
    verification_token: Mapped[str] = mapped_column(String(128))
    last_error: Mapped[str] = mapped_column(Text, default="")

    verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    verification_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    active_testing_enabled: Mapped[bool] = mapped_column(Boolean, default=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class AuditLog(Base):
    """Append-only record of security-sensitive actions.

    Verification tokens and scan payloads are deliberately never written here.
    """

    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True, index=True,
    )
    action: Mapped[str] = mapped_column(String(64), index=True)
    target: Mapped[str] = mapped_column(String(255), default="")
    result: Mapped[str] = mapped_column(String(32), default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
