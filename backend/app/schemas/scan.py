import uuid
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.enums import ScanStatus

REQUIRED_AUTHORIZATION_PHRASE = "I confirm that I have authorization to test this target."

_CUSTOM_TEST_LOCATIONS = ("query", "form", "json", "header")
_CUSTOM_TEST_SEVERITIES = ("info", "low", "medium", "high", "critical")


class CustomTestCase(BaseModel):
    """One user-defined security test, executed through the same
    ParamTarget -> RequestBuilder -> ResponseDiff -> Finding pipeline as
    every built-in active test. Deliberately separate from the static
    wordlists in wordlists.py — this is one ad hoc test per entry, scoped to
    a single scan, not a reusable list of names."""

    name: str = Field(..., min_length=1, max_length=200)
    description: str = Field(default="", max_length=1000)
    path: str = Field(..., min_length=1, max_length=2048)
    method: str = Field(default="GET", pattern="^(?i)(GET|POST|PUT|PATCH|DELETE)$")
    input: str = Field(..., min_length=1, max_length=200)
    location: str = Field(default="query")
    test: str = Field(..., min_length=1, max_length=2000, description="Payload/test value")
    expected: str = Field(
        default="differs",
        description='Validation condition: "differs" (response differs '
        'from baseline) or "contains:<substring>" (response body contains '
        "the given substring).",
    )
    severity: str = Field(default="medium")

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        return value.upper()

    @field_validator("location")
    @classmethod
    def validate_location(cls, value: str) -> str:
        if value not in _CUSTOM_TEST_LOCATIONS:
            raise ValueError(f"location must be one of {_CUSTOM_TEST_LOCATIONS}")
        return value

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, value: str) -> str:
        if value not in _CUSTOM_TEST_SEVERITIES:
            raise ValueError(f"severity must be one of {_CUSTOM_TEST_SEVERITIES}")
        return value


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
    repo_url: Optional[str] = Field(
        default=None,
        max_length=2048,
        description="Optional public GitHub/GitLab repository for this site. "
        "When given it is analyzed directly; otherwise the scanner tries to "
        "discover the repo from the site itself.",
    )
    custom_test_cases: List[CustomTestCase] = Field(
        default_factory=list,
        max_length=20,
        description="Optional user-defined security tests, run through the "
        "same active-testing pipeline as the built-in checks. Only executed "
        "when the scan is authorized for active testing; scope- and "
        "safety-limited exactly like every other active test.",
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

    # Safety / scope controls (all optional, fall back to safe defaults)
    max_requests: Optional[int] = Field(default=None, gt=0, le=100_000)
    concurrency: Optional[int] = Field(default=None, gt=0, le=50)
    rate_limit_per_second: Optional[float] = Field(default=None, gt=0, le=100)
    request_timeout_seconds: Optional[float] = Field(default=None, gt=0, le=120)
    scan_timeout_seconds: Optional[float] = Field(default=None, gt=0, le=86_400)
    max_response_bytes: Optional[int] = Field(default=None, gt=0, le=50_000_000)

    @field_validator("repo_url")
    @classmethod
    def validate_repo_url(cls, value: Optional[str]) -> Optional[str]:
        if value is None or not value.strip():
            return None
        # Reject early so a typo surfaces at submit time rather than silently
        # producing a scan with no source analysis.
        from app.services.repo_discovery import parse_repo_url

        if parse_repo_url(value) is None:
            raise ValueError(
                "repo_url must be a public GitHub or GitLab repository URL, "
                "e.g. https://github.com/owner/repo"
            )
        return value.strip()

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

    # Two-stage progress / results (Phase 2)
    initial_risk: str = ""
    final_risk: str = ""
    risk_score: int = 0
    ai_analyzed: bool = False
    ai_error: str = ""
    ai_summary: str = ""
    ai_recommendation: str = ""
    deep_progress: int = 0
    urls_discovered: int = 0
    apis_discovered: int = 0
    parameters_discovered: int = 0
    subdomains_discovered: int = 0
    security_checks_completed: int = 0
    findings_count: int = 0
    ai_status: str = ""

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
