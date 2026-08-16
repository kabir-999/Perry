import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import auth, dashboard, scans, targets
from app.config import settings
from app.services.log_retention import run_retention_loop


@asynccontextmanager
async def lifespan(app: FastAPI):
    stop_event = asyncio.Event()
    retention_task = asyncio.create_task(run_retention_loop(stop_event))
    try:
        yield
    finally:
        stop_event.set()
        await retention_task


app = FastAPI(
    title=settings.APP_NAME,
    description=(
        "Authorized security assessment platform. For use only against "
        "targets you own or have explicit written authorization to test."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.FRONTEND_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers(request, call_next):
    """A pure JSON API serves no scripts/styles/frames of its own, so these
    are maximally restrictive rather than tuned for a page that renders
    content — there's nothing here for a browser to be tricked into
    executing in the first place."""
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = "default-src 'none'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

app.include_router(auth.router, prefix=settings.API_PREFIX)
app.include_router(targets.router, prefix=settings.API_PREFIX)
app.include_router(scans.router, prefix=settings.API_PREFIX)
app.include_router(dashboard.router, prefix=settings.API_PREFIX)


@app.get("/api/health")
async def health_check():
    return {
        "status": "ok",
        "environment": settings.ENVIRONMENT,
        "groq_configured": settings.groq_configured,
    }
