"""
Central configuration module.

Loads all environment-driven settings for the application from `.env`.
Nothing in this codebase should read `os.environ` directly outside of
this module — import `settings` instead.
"""
from functools import lru_cache
from pathlib import Path
from typing import List, Optional

from pydantic_settings import BaseSettings, SettingsConfigDict

# backend/app/config.py -> backend/ -> web-fuzzer/ (project root, where the
# top-level .env lives per the project layout). Also check backend/.env so
# the app still works if someone places .env next to backend/ instead.
_BACKEND_DIR = Path(__file__).resolve().parent.parent
_PROJECT_ROOT = _BACKEND_DIR.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(_PROJECT_ROOT / ".env", _BACKEND_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- App ---
    APP_NAME: str = "Web Application Security Fuzzer"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    API_PREFIX: str = "/api"

    # --- CORS ---
    FRONTEND_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]

    # --- Database ---
    DATABASE_URL: str = (
        "postgresql+psycopg://web_fuzzer:web_fuzzer@localhost:5432/web_fuzzer"
    )

    # --- Authentication ---
    # Override in .env for anything other than local development: changing it
    # invalidates every issued token.
    JWT_SECRET: str = "dev-only-change-me"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # one week

    # --- Scan activity log encryption + retention ---
    # Symmetric key passed to Postgres's pgcrypto (pgp_sym_encrypt/decrypt).
    # Override in .env for anything other than local development — this key
    # is what makes scan_events.message unreadable to anyone with only
    # database access, not application access.
    LOG_ENCRYPTION_KEY: str = "dev-only-change-me-log-key"
    # Scan activity logs (ScanEvent rows) older than this are purged by a
    # background sweep — never retained indefinitely.
    LOG_RETENTION_DAYS: int = 7

    # --- Groq / LLM Security Analyst ---
    # NOTE: These are read here only. The LLM analysis service itself is
    # implemented in a later phase. The key must never be hardcoded and
    # must never be returned to the frontend.
    GROQ_API_KEY: Optional[str] = None
    GROQ_MODEL: str = "llama-3.1-70b-versatile"
    GROQ_REQUEST_TIMEOUT_SECONDS: float = 30.0

    # Source Code Analysis (Feature 2)
    # Optional GitHub token. Only raises the API rate limit used while
    # auto-discovering the site's repository (60/hr anonymous vs 5000/hr).
    # Never sent to the frontend; a read-only/no-scope token is enough.
    GITHUB_TOKEN: Optional[str] = None
    REPO_MIN_CONFIDENCE: float = 0.6
    REPO_CLONE_TIMEOUT_SECONDS: float = 120.0
    REPO_MAX_FILES: int = 500

    # --- Scan safety / scope controls (defaults; user never sets these) ---
    DEFAULT_MAX_REQUESTS: int = 400
    DEFAULT_CONCURRENCY: int = 10
    DEFAULT_RATE_LIMIT_PER_SECOND: float = 20.0
    DEFAULT_REQUEST_TIMEOUT_SECONDS: float = 8.0
    DEFAULT_SCAN_TIMEOUT_SECONDS: float = 180.0
    DEFAULT_MAX_RESPONSE_BYTES: int = 2_000_000

    # --- Stage 1: Fast Scan (optimise time-to-first-result) ---
    # A handful of high-value requests with aggressive timeouts. The whole
    # stage is wrapped in FAST_SCAN_TIMEOUT so a slow target still yields an
    # initial result quickly.
    FAST_SCAN_TIMEOUT_SECONDS: float = 6.0
    FAST_REQUEST_TIMEOUT_SECONDS: float = 4.0
    FAST_CONNECT_TIMEOUT_SECONDS: float = 3.0
    FAST_MAX_RESPONSE_BYTES: int = 512_000

    # We follow redirects manually (never httpx's unbounded auto-follow) so a
    # redirect loop degrades to a finding instead of failing the scan.
    REDIRECT_MAX_DEPTH: int = 5

    # --- Stage 2: Deep Scan (tuned for low latency) ---
    DEEP_CONCURRENCY: int = 24
    DEEP_MAX_REQUESTS: int = 300
    DEEP_REQUEST_TIMEOUT_SECONDS: float = 6.0
    DEEP_SCAN_TIMEOUT_SECONDS: float = 90.0
    CRAWL_MAX_PAGES: int = 25
    CRAWL_MAX_DEPTH: int = 2
    # How many discovered subdomains get their own independent security
    # assessment (not just DNS discovery + VHost-probe reuse). Small and
    # bounded — they all draw from the one shared DEEP_MAX_REQUESTS budget.
    SUBDOMAIN_ASSESS_LIMIT: int = 5

    # Connection pool sizing for the shared httpx.AsyncClient.
    HTTP_MAX_CONNECTIONS: int = 48
    HTTP_MAX_KEEPALIVE: int = 24

    # A neutral, honest User-Agent. Not spoofed to evade detection.
    SCANNER_USER_AGENT: str = "WebFuzzer/0.2 (authorized-security-assessment)"

    # Cap on how many findings are batched into a single Groq call.
    LLM_MAX_FINDINGS_PER_CALL: int = 12

    @property
    def groq_configured(self) -> bool:
        """True only when a *real* key and model are set — placeholder values
        left over from .env.example count as not configured so we don't fire
        doomed Groq calls."""
        key = (self.GROQ_API_KEY or "").strip()
        model = (self.GROQ_MODEL or "").strip()
        if not key or not model:
            return False
        if "your_" in key.lower() or "your_" in model.lower():
            return False
        if model in {"your_model_here", "changeme"}:
            return False
        # Groq keys start with "gsk_"; be lenient but reject obvious stubs.
        if len(key) < 30:
            return False
        return True


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
