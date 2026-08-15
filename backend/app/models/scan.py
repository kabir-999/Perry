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
    # Read-only scan: no active injection payloads were sent. Set when the
    # user did not confirm authorization for the target.
    passive_only: Mapped[bool] = mapped_column(default=False)
    # Opt-in: attach the target's saved VerifiedTarget.auth_header (the
    # scanner's own test-account session) while crawling/testing. Never
    # triggers self-registration or a login attempt — see auth_discovery.py.
    authenticated_scan: Mapped[bool] = mapped_column(default=False)
    # AUTHORIZED_DEPLOYMENT | PASSIVE_WEB
    scan_type: Mapped[str] = mapped_column(String(32), default="PASSIVE_WEB")
    # Verification state of the target at the time the scan ran.
    authorization_status: Mapped[str] = mapped_column(String(32), default="UNVERIFIED")

    # Deep-scan progress (0-100) and running discovery/finding counters.
    deep_progress: Mapped[int] = mapped_column(Integer, default=0)
    urls_discovered: Mapped[int] = mapped_column(Integer, default=0)
    apis_discovered: Mapped[int] = mapped_column(Integer, default=0)
    parameters_discovered: Mapped[int] = mapped_column(Integer, default=0)
    subdomains_discovered: Mapped[int] = mapped_column(Integer, default=0)
    security_checks_completed: Mapped[int] = mapped_column(Integer, default=0)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)

    # Live status line for the deep-scan view.
    ai_status: Mapped[str] = mapped_column(String(128), default="")
    # Which deep-scan check groups have finished (JSON list of labels).
    checks_done_json: Mapped[str] = mapped_column(Text, default="")

    # --- Deterministic assessment (5-factor risk; no AI, no CVSS aggregation) ---
    # Overall risk = highest confirmed finding's 5-factor score (0-100), and
    # the level derived from it. Coverage never modifies these.
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    final_risk: Mapped[str] = mapped_column(String(16), default="")
    overall_risk: Mapped[int] = mapped_column(Integer, default=0)
    assessment_confidence: Mapped[str] = mapped_column(String(32), default="")
    assessment_coverage: Mapped[int] = mapped_column(Integer, default=0)
    assessment_warning: Mapped[str] = mapped_column(Text, default="")

    # Per-(endpoint,parameter,attack) test matrix + per-attack coverage +
    # crawl coverage — all serialized as JSON.
    attack_matrix_json: Mapped[str] = mapped_column(Text, default="")
    attack_coverage_json: Mapped[str] = mapped_column(Text, default="")
    coverage_json: Mapped[str] = mapped_column(Text, default="")
    # Production-grade structured JSON logs for every attack attempt (one
    # record per test — vulnerable, clean, skipped, inconclusive, or errored),
    # serialized as a JSON array. Rendered under each attack's box in the UI.
    attack_logs_json: Mapped[str] = mapped_column(Text, default="")
    # Per-domain + overall baseline-vs-fuzz anomaly scores, serialized as JSON
    # ({"overall": {...}, "domains": {attack: {...}}}).
    anomaly_json: Mapped[str] = mapped_column(Text, default="")
    # Full attack-surface graph (normalized, de-duplicated endpoints with
    # parent/child edges), serialized as JSON.
    attack_graph_json: Mapped[str] = mapped_column(Text, default="")
    # Per-strategy crawl layer (BFS vs DFS): each with its own graph, discovery
    # score, stats, and crawl log. Serialized as JSON.
    crawl_strategies_json: Mapped[str] = mapped_column(Text, default="")

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
