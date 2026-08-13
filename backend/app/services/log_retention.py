"""
Retention sweep for scan activity logs (`ScanEvent` rows).

Logs are encrypted at rest (see crypto_columns.py) but still shouldn't be
kept forever — this deletes anything older than `settings.LOG_RETENTION_DAYS`
(default 7). Runs as a background loop for the life of the app process (see
main.py's lifespan), not a one-shot script, so no external scheduler/cron is
required to keep the retention policy enforced.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete

from app.config import settings
from app.database import AsyncSessionLocal
from app.models.scan import ScanEvent

logger = logging.getLogger("scanner.log_retention")

# A 7-day policy doesn't need minute-level precision — sweeping a few times
# a day is enough to keep the oldest row well under the retention window.
_SWEEP_INTERVAL_SECONDS = 6 * 60 * 60


async def purge_expired_scan_events() -> int:
    """Delete ScanEvent rows older than the retention window. Returns the
    number of rows deleted."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=settings.LOG_RETENTION_DAYS)
    async with AsyncSessionLocal() as db:
        result = await db.execute(delete(ScanEvent).where(ScanEvent.created_at < cutoff))
        await db.commit()
        return result.rowcount or 0


async def run_retention_loop(stop_event: asyncio.Event) -> None:
    """Sweeps on startup, then on a fixed interval, until `stop_event` is
    set (app shutdown). A failed sweep is logged and retried on the next
    tick rather than crashing the loop."""
    while not stop_event.is_set():
        try:
            deleted = await purge_expired_scan_events()
            if deleted:
                logger.info(
                    "Log retention: purged %d scan_events row(s) older than %d day(s).",
                    deleted, settings.LOG_RETENTION_DAYS,
                )
        except Exception:
            logger.exception("Log retention sweep failed")

        try:
            await asyncio.wait_for(stop_event.wait(), timeout=_SWEEP_INTERVAL_SECONDS)
        except asyncio.TimeoutError:
            pass
