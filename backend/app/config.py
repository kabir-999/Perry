"""
Central configuration module.

Loads all environment-driven settings for the application from `.env`.
Nothing in this codebase should read `os.environ` directly outside of
this module — import `settings` instead.
"""
from functools import lru_cache
from pathlib import Path
from typing import List, Optional

from pydantic import field_validator
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
    # Defaults to off: this also drives SQLAlchemy's `echo` (database.py),
    # which fully serializes and logs every query + bound parameters on
    # every request — real CPU/I/O overhead on every single request, not
    # just noisy logs, and easy to deploy accidentally since the app
    # otherwise "just works" with it left on. Set DEBUG=true locally in
    # .env if you want that SQL echo back for local debugging.
    DEBUG: bool = False
    API_PREFIX: str = "/api"

    # --- CORS ---
    FRONTEND_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]

    # --- Database ---
    # Railway (and most Postgres hosts) inject DATABASE_URL as
    # "postgres://..." or "postgresql://...", which SQLAlchemy 2.0 + asyncpg
    # rejects — it requires the "postgresql+asyncpg://" dialect prefix. The
    # validator below rewrites the scheme so the Railway-provided value works
    # unmodified; a manually-configured local URL that already has the right
    # scheme passes through untouched.
    DATABASE_URL: str = (
        "postgresql+asyncpg://web_fuzzer:web_fuzzer@localhost:5432/web_fuzzer"
    )

    @field_validator("DATABASE_URL")
    @classmethod
    def _normalize_database_url(cls, v: str) -> str:
        if v.startswith("postgres://"):
            return "postgresql+asyncpg://" + v[len("postgres://") :]
        if v.startswith("postgresql://"):
            return "postgresql+asyncpg://" + v[len("postgresql://") :]
        return v

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

    # --- Stage 2: Deep Scan ---
    DEEP_CONCURRENCY: int = 24
    # Request budget must cover the whole attack surface: with 19 attack
    # modules each probing every eligible parameter, a modest site is easily
    # 1,000-2,000 requests. Set too low (the old 300) it starved later attacks
    # so eligible parameters showed "tested 0". The rate limit + scan timeout
    # remain the real governors; this ceiling is sized so it is not the
    # binding constraint for typical targets. Genuinely huge surfaces that
    # still exceed it now report the untested remainder as NOT_TESTED
    # (honestly), never a false NOT_VULNERABLE.
    DEEP_MAX_REQUESTS: int = 2500
    DEEP_REQUEST_TIMEOUT_SECONDS: float = 6.0
    DEEP_SCAN_TIMEOUT_SECONDS: float = 240.0
    CRAWL_MAX_PAGES: int = 25
    CRAWL_MAX_DEPTH: int = 2
    # How many discovered subdomains get their own independent security
    # assessment (not just DNS discovery + VHost-probe reuse). Small and
    # bounded — they all draw from the one shared DEEP_MAX_REQUESTS budget.
    SUBDOMAIN_ASSESS_LIMIT: int = 5

    # Connection pool sizing for the shared httpx.AsyncClient.
    HTTP_MAX_CONNECTIONS: int = 48
    HTTP_MAX_KEEPALIVE: int = 24

    # --- Browser-based crawling (JS/SPA discovery) ---
    # Off by default only in the sense that it degrades gracefully if
    # Chromium isn't installed — when available it always runs, additive
    # to the static crawler, never a replacement for it.
    BROWSER_CRAWL_MAX_PAGES: int = 8
    BROWSER_CRAWL_MAX_DEPTH: int = 2
    BROWSER_NAV_TIMEOUT_SECONDS: float = 6.0
    BROWSER_NETWORK_IDLE_TIMEOUT_SECONDS: float = 1.5
    # A separate, smaller budget than DEEP_MAX_REQUESTS — browser-driven
    # navigation/clicks can fan out fast, and this is a different cost
    # profile (a real browser tab) than a pooled httpx request.
    BROWSER_MAX_REQUESTS: int = 100
    # Hard wall-clock ceiling for the *entire* browser_crawl() call, launch
    # included. Per-page/per-interaction timeouts above are individually
    # small, but on a slow/heavy real-world site they add up across many
    # pages; this is the backstop that guarantees the browser-crawl phase
    # never gates the whole scan past a predictable, bounded duration. On
    # timeout, whatever pages/requests were already discovered are kept and
    # returned (graceful partial result), not thrown away.
    BROWSER_CRAWL_BUDGET_SECONDS: float = 18.0

    # --- Debug mode (Part 18): bracketed-tag trace of what was discovered/
    # tested and why, at logging.DEBUG. Zero cost when off.
    SCAN_DEBUG: bool = False

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
