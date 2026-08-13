import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.enums import ScanStatus
from app.services.crypto_columns import EncryptedText
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.models.target import Target
    from app.models.endpoint import Subdomain, DiscoveredEndpoint
    from app.models.report import Report
    from app.models.repository import Repository, SourceFinding
    from app.models.finding import Finding


class Scan(Base):
    """A single scan run against a Target, with its safety/scope config."""

    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE")
    )
    # Owner of the scan. Nullable so scans created before accounts existed
    # still load; new scans always carry one.
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"),
        nullable=True, index=True,
    )

    status: Mapped[ScanStatus] = mapped_column(
        String(32), default=ScanStatus.QUEUED.value
    )

    # Enabled modules (Phase 1: stored only, not executed yet)
    modules: Mapped[str] = mapped_column(
        Text, default="", doc="Comma-separated list of enabled scan modules"
    )

    # Safety / scope controls
    max_requests: Mapped[int] = mapped_column(Integer, default=500)
    concurrency: Mapped[int] = mapped_column(Integer, default=5)
    rate_limit_per_second: Mapped[float] = mapped_column(Float, default=5.0)
    request_timeout_seconds: Mapped[float] = mapped_column(Float, default=10.0)
    scan_timeout_seconds: Mapped[float] = mapped_column(Float, default=1800.0)
    max_response_bytes: Mapped[int] = mapped_column(Integer, default=5_000_000)

    requests_made: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str] = mapped_column(Text, default="")

    # --- Two-stage scan results & live progress (Phase 2) ---
    # Fast-scan initial assessment, serialized as JSON text.
    fast_result_json: Mapped[str] = mapped_column(Text, default="")
    initial_risk: Mapped[str] = mapped_column(String(16), default="")
    # Fast-scan cache (avoids re-fetching the homepage in deep scan)
    fast_scan_homepage_text: Mapped[str] = mapped_column(Text, default="")
    fast_scan_homepage_url: Mapped[str] = mapped_column(String(2048), default="")
    
    # Repository analysis info (JSON serialized)
    repo_info_json: Mapped[str] = mapped_column(Text, default="")
    # Optional user-supplied GitHub/GitLab repo. When set, it is analyzed
    # directly instead of relying on auto-discovery from the site.
    repo_url: Mapped[str] = mapped_column(String(2048), default="")
    # Read-only scan: no active injection payloads were sent. Set when the
    # user did not confirm authorization for the target.
    passive_only: Mapped[bool] = mapped_column(default=False)
    # User-defined custom test cases for this scan (JSON list of
    # CustomTestCase), only ever executed when the scan runs active tests.
    custom_test_cases_json: Mapped[str] = mapped_column(Text, default="")
    # LOCAL_CODE | CI_CD | AUTHORIZED_DEPLOYMENT | PASSIVE_WEB
    scan_type: Mapped[str] = mapped_column(String(32), default="PASSIVE_WEB")
    # Verification state of the target at the time the scan ran.
    authorization_status: Mapped[str] = mapped_column(String(32), default="UNVERIFIED")
    final_risk: Mapped[str] = mapped_column(String(16), default="")

    # Deep-scan progress (0-100) and running discovery/finding counters.
    deep_progress: Mapped[int] = mapped_column(Integer, default=0)
    urls_discovered: Mapped[int] = mapped_column(Integer, default=0)
    apis_discovered: Mapped[int] = mapped_column(Integer, default=0)
    parameters_discovered: Mapped[int] = mapped_column(Integer, default=0)
    subdomains_discovered: Mapped[int] = mapped_column(Integer, default=0)
    security_checks_completed: Mapped[int] = mapped_column(Integer, default=0)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)

    # Human-readable AI-analysis status line for the live view.
    ai_status: Mapped[str] = mapped_column(String(128), default="")
    # Which deep-scan check groups have finished (JSON list of labels).
    checks_done_json: Mapped[str] = mapped_column(Text, default="")

    # --- Overall assessment shown on the single Scan Detail page ---
    # Whether the Groq analyst produced a validated assessment. Risk score /
    # level are authoritative ONLY when this is true.
    ai_analyzed: Mapped[bool] = mapped_column(default=False)
    # User-facing reason when AI analysis is unavailable (never internals).
    ai_error: Mapped[str] = mapped_column(Text, default="")
    # 0-100 overall risk score — set only by the AI analyst (0 when unavailable).
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    # AI Security Analyst narrative (empty if the analyst was not run).
    ai_summary: Mapped[str] = mapped_column(Text, default="")
    ai_recommendation: Mapped[str] = mapped_column(Text, default="")
    # Groq risk factors + severity statistics, serialized as JSON.
    risk_factors_json: Mapped[str] = mapped_column(Text, default="")
    # Full security-test matrix (every test + outcome), serialized as JSON.
    test_results_json: Mapped[str] = mapped_column(Text, default="")
    # Sentinel Risk Model v1 output: score, band, and contributors.
    sentinel_risk_json: Mapped[str] = mapped_column(Text, default="")

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    target: Mapped["Target"] = relationship(back_populates="scans")
    subdomains: Mapped[list["Subdomain"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    report: Mapped["Report"] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    repositories: Mapped[list["Repository"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    source_findings_rel: Mapped[list["SourceFinding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    events: Mapped[list["ScanEvent"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    endpoints: Mapped[list["DiscoveredEndpoint"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class ScanEvent(Base):
    """Append-only log of scan progress, used to drive the Live Scan view."""

    __tablename__ = "scan_events"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE")
    )
    event_type: Mapped[str] = mapped_column(String(64))
    # Encrypted at rest via Postgres pgcrypto (see crypto_columns.py) — a
    # database-only compromise never exposes scan activity log content.
    message: Mapped[str] = mapped_column(EncryptedText, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )

    scan: Mapped["Scan"] = relationship(back_populates="events")
