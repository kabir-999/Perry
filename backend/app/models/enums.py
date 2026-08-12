import enum


class ScanStatus(str, enum.Enum):
    # Two-stage scan lifecycle:
    #   QUEUED -> FAST_SCANNING -> INITIAL_RESULT_READY
    #          -> DEEP_SCANNING -> AI_ANALYSIS -> COMPLETED
    # plus terminal FAILED / CANCELLED.
    QUEUED = "queued"
    FAST_SCANNING = "fast_scanning"
    INITIAL_RESULT_READY = "initial_result_ready"
    DEEP_SCANNING = "deep_scanning"
    AI_ANALYSIS = "ai_analysis"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

    # Legacy Phase 1 states, retained so old rows still deserialize.
    PENDING = "pending"
    RUNNING = "running"


# States in which a scan is still doing work (used for "active" queries and
# to decide whether an SSE stream should stay open).
ACTIVE_SCAN_STATUSES = (
    ScanStatus.QUEUED.value,
    ScanStatus.FAST_SCANNING.value,
    ScanStatus.INITIAL_RESULT_READY.value,
    ScanStatus.DEEP_SCANNING.value,
    ScanStatus.AI_ANALYSIS.value,
    ScanStatus.PENDING.value,
    ScanStatus.RUNNING.value,
)

TERMINAL_SCAN_STATUSES = (
    ScanStatus.COMPLETED.value,
    ScanStatus.FAILED.value,
    ScanStatus.CANCELLED.value,
)


class UserRole(str, enum.Enum):
    # Developers scan sites they own (full active scan + source analysis).
    DEVELOPER = "developer"
    # Customers only get the passive "is this link safe?" check — they are
    # checking sites they do not own, so nothing intrusive may run.
    CUSTOMER = "customer"


class RiskLevel(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, enum.Enum):
    CONFIRMED = "confirmed"
    POTENTIAL = "potential"
    UNCERTAIN = "uncertain"
    FALSE_POSITIVE = "false_positive"


class DiscoveryMethod(str, enum.Enum):
    CRAWLER = "crawler"
    DIRECTORY_SCAN = "directory_scan"
    API_DISCOVERY = "api_discovery"
    ROBOTS_TXT = "robots_txt"
    SITEMAP = "sitemap"
    MANUAL = "manual"


class ReportFormat(str, enum.Enum):
    HTML = "html"
    PDF = "pdf"
    JSON = "json"
