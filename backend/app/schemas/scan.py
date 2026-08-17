import uuid
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.enums import ScanStatus

REQUIRED_AUTHORIZATION_PHRASE = "I confirm that I have authorization to test this target."

class ScanCreate(BaseModel):
    """Payload to create a new scan.

    The user only supplies a URL and the authorization confirmation. Scope,
    concurrency, request limits, timeouts, and enabled modules are all chosen
    automatically by the backend; the optional fields below exist only for
    an internal/advanced path and are not required.
    """

    target_url: str = Field(..., min_length=1, max_length=2048)
    allowed_domains: List[str] = Field(
        default_factory=list,
        description="Optional extra in-scope hostnames (advanced). Scope is "
        "otherwise derived from the target URL automatically.",
    )
    modules: List[str] = Field(
        default_factory=list,
        description="Ignored for normal scans; the backend runs fast+deep.",
    )
    # Authorization gate. Supplying the exact phrase unlocks the active
    # injection probes. Without it the scan still runs, but read-only: a user
    # checking a site they do not own must not send attack payloads at it.
    authorization_statement: Optional[str] = Field(
        default=None,
        description=f'Supply exactly "{REQUIRED_AUTHORIZATION_PHRASE}" to '
        "enable active testing. Omit for a passive, read-only scan.",
    )

    @property
    def is_authorized(self) -> bool:
        return (self.authorization_statement or "").strip() == REQUIRED_AUTHORIZATION_PHRASE

    # Authenticated scanning (opt-in). Only meaningful when the target has a
    # verified VerifiedTarget.auth_header already on file — Perry never
    # self-registers or generates a credential; a human must have created the
    # scanner's test account in the authorized environment and supplied its
    # session via the target verification flow. When true, crawling and
    # active testing attach that credential; when the target has no
    # auth_header on file this flag is a no-op (the scan proceeds
    # unauthenticated, never silently attempting a login).
    authenticated_scan: bool = Field(
        default=False,
        description="Attach the target's saved scanner credential "
        "(VerifiedTarget.auth_header) while crawling and testing, if one "
        "exists. Never triggers self-registration or a login attempt.",
    )

    # Safety / scope controls (all optional, fall back to safe defaults)
    max_requests: Optional[int] = Field(default=None, gt=0, le=100_000)
    concurrency: Optional[int] = Field(default=None, gt=0, le=50)
    rate_limit_per_second: Optional[float] = Field(default=None, gt=0, le=100)
    request_timeout_seconds: Optional[float] = Field(default=None, gt=0, le=120)
    scan_timeout_seconds: Optional[float] = Field(default=None, gt=0, le=86_400)
    max_response_bytes: Optional[int] = Field(default=None, gt=0, le=50_000_000)

    @field_validator("authorization_statement")
    @classmethod
    def validate_authorization(cls, value: Optional[str]) -> Optional[str]:
        if value is None or not value.strip():
            return None
        if value.strip() != REQUIRED_AUTHORIZATION_PHRASE:
            raise ValueError(
                "authorization_statement must exactly match the required "
                f'confirmation phrase: "{REQUIRED_AUTHORIZATION_PHRASE}"'
            )
        return value.strip()


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    target_id: uuid.UUID
    status: ScanStatus
    modules: str
    max_requests: int
    concurrency: int
    rate_limit_per_second: float
    request_timeout_seconds: float
    scan_timeout_seconds: float
    max_response_bytes: int
    requests_made: int
    error_message: str

    # Two-stage progress / results. Risk is deterministic (5-factor); overall
    # risk = highest confirmed finding, with confidence + coverage separate.
    initial_risk: str = ""
    final_risk: str = ""
    risk_score: int = 0
    overall_risk: int = 0
    assessment_confidence: str = ""
    assessment_coverage: int = 0
    deep_progress: int = 0
    urls_discovered: int = 0
    apis_discovered: int = 0
    parameters_discovered: int = 0
    subdomains_discovered: int = 0
    security_checks_completed: int = 0
    findings_count: int = 0
    ai_status: str = ""
    ai_analyzed: bool = False
    ai_error: str = ""
    ai_summary: str = ""
    ai_recommendation: str = ""
    risk_factors_json: str = ""

    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


class ScanEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    event_type: str
    message: str
    created_at: datetime
