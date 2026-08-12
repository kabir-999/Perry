import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.scan import Scan

class DiscoveredEndpoint(Base):
    """A URL/route discovered during the discovery phase (crawler,
    directory scan, API discovery, etc.). Populated in Phase 2/3."""

    __tablename__ = "discovered_endpoints"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE")
    )

    url: Mapped[str] = mapped_column(String(2048))
    method: Mapped[str] = mapped_column(String(16), default="GET")
    source: Mapped[str] = mapped_column(String(64), default="")
    discovery_method: Mapped[str] = mapped_column(String(64), default="")
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    content_type: Mapped[str] = mapped_column(String(256), default="")
    response_size: Mapped[int | None] = mapped_column(Integer, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    scan: Mapped["Scan"] = relationship(back_populates="endpoints")
    parameters: Mapped[list["Parameter"]] = relationship(
        back_populates="endpoint", cascade="all, delete-orphan"
    )


class Parameter(Base):
    """A query/form/JSON parameter observed on a discovered endpoint."""

    __tablename__ = "parameters"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    endpoint_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("discovered_endpoints.id", ondelete="CASCADE")
    )
    name: Mapped[str] = mapped_column(String(256))
    param_type: Mapped[str] = mapped_column(
        String(32), default="query", doc="query | form | json | header"
    )
    example_value: Mapped[str] = mapped_column(Text, default="")

    endpoint: Mapped["DiscoveredEndpoint"] = relationship(
        back_populates="parameters"
    )


class Subdomain(Base):
    """A subdomain discovered via controlled DNS enumeration (Phase 3)."""

    __tablename__ = "subdomains"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE")
    )
    hostname: Mapped[str] = mapped_column(String(512))
    resolved_ip: Mapped[str] = mapped_column(String(64), default="")
    source: Mapped[str] = mapped_column(String(64), default="dns_bruteforce")

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    scan: Mapped["Scan"] = relationship(back_populates="subdomains")
