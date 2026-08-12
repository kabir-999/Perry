import uuid
from datetime import datetime
from sqlalchemy import Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base


class Repository(Base):
    __tablename__ = "repositories"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    provider: Mapped[str] = mapped_column(String(16))       # "github" | "gitlab"
    owner: Mapped[str] = mapped_column(String(256))
    name: Mapped[str] = mapped_column(String(256))
    url: Mapped[str] = mapped_column(String(2048))
    confidence: Mapped[float] = mapped_column(Float)
    status: Mapped[str] = mapped_column(String(32))         # "discovered" | "analyzed" | "skipped" | "error"
    files_analyzed: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="repositories") # type: ignore
    source_findings: Mapped[list["SourceFinding"]] = relationship(
        "SourceFinding", back_populates="repository", cascade="all, delete-orphan"
    )


class SourceFinding(Base):
    __tablename__ = "source_findings"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    repository_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("repositories.id", ondelete="CASCADE"), index=True, nullable=True)
    
    finding_type: Mapped[str] = mapped_column(String(64))   # "hardcoded_secret" | "env_secret" | "sql_injection" | ...
    file: Mapped[str] = mapped_column(String(512))
    line: Mapped[int] = mapped_column(Integer)
    severity: Mapped[str] = mapped_column(String(32))
    confidence: Mapped[str] = mapped_column(String(32))
    evidence: Mapped[str] = mapped_column(Text)             # always redacted
    secret_type: Mapped[str] = mapped_column(String(64), default="")
    redacted_value: Mapped[str] = mapped_column(String(256), default="")
    code_context: Mapped[str] = mapped_column(Text, default="")
    
    package: Mapped[str] = mapped_column(String(256), default="")       # for dependency findings
    version: Mapped[str] = mapped_column(String(64), default="")
    ecosystem: Mapped[str] = mapped_column(String(32), default="")
    advisory_id: Mapped[str] = mapped_column(String(128), default="")
    fixed_version: Mapped[str] = mapped_column(String(64), default="")

    # Exploitability context — a CVE against a package version says nothing
    # about this application until these are established.
    classification: Mapped[str] = mapped_column(String(32), default="")
    vulnerable_range: Mapped[str] = mapped_column(String(128), default="")
    is_direct: Mapped[bool] = mapped_column(default=False)
    is_used: Mapped[bool] = mapped_column(default=False)
    externally_reachable: Mapped[str] = mapped_column(String(64), default="")
    
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="source_findings_rel") # type: ignore
    repository: Mapped["Repository"] = relationship("Repository", back_populates="source_findings")
