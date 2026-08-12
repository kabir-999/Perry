import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Finding(Base):
    """A security finding produced by the deterministic scanner and,
    optionally, annotated by the Groq LLM Security Analyst.

    Populated starting in Phase 4 (vulnerability_engine) and enriched in
    Phase 5 (llm_security_analyst). Left empty of scan logic in Phase 1.
    """

    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE")
    )

    title: Mapped[str] = mapped_column(String(256))
    category: Mapped[str] = mapped_column(String(128))
    severity: Mapped[str] = mapped_column(String(32))
    confidence: Mapped[str] = mapped_column(String(32))

    url: Mapped[str] = mapped_column(String(2048), default="")
    method: Mapped[str] = mapped_column(String(16), default="GET")
    parameter: Mapped[str] = mapped_column(String(256), default="")

    evidence: Mapped[str] = mapped_column(Text, default="")
    request_summary: Mapped[str] = mapped_column(Text, default="")
    response_summary: Mapped[str] = mapped_column(Text, default="")

    description: Mapped[str] = mapped_column(Text, default="")
    impact: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")

    # Deterministic risk score, computed by the risk_engine (Phase 4).
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)

    # LLM Security Analyst enrichment (Phase 5). Nullable until analyzed.
    llm_verdict: Mapped[str | None] = mapped_column(String(32), nullable=True)
    llm_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    llm_explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    llm_false_positive_reason: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    scan: Mapped["Scan"] = relationship(back_populates="findings")
