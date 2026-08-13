"""
These tests hit the real local Postgres database (same one Alembic manages)
rather than a mock — pgcrypto encryption and delete-by-age are database
behaviors, not Python logic, so a mock would only prove the mock works.
Requires `alembic upgrade head` to have been run (adds the pgcrypto
extension and the scan_events.message/created_at changes these tests use).
Skipped automatically if no database is reachable.
"""
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import SQLAlchemyError

from app.database import AsyncSessionLocal, engine
from app.models.enums import ScanStatus
from app.models.scan import Scan, ScanEvent
from app.models.target import Target
from app.services.log_retention import purge_expired_scan_events


@pytest.fixture
async def scan():
    try:
        async with AsyncSessionLocal() as db:
            target = Target(
                base_url="https://encryption-test.invalid",
                hostname="encryption-test.invalid",
            )
            db.add(target)
            await db.flush()
            row = Scan(target_id=target.id, status=ScanStatus.COMPLETED.value)
            db.add(row)
            await db.commit()
            target_id, scan_id = target.id, row.id
    except SQLAlchemyError:
        pytest.skip("no reachable Postgres database for this test")

    yield scan_id

    async with AsyncSessionLocal() as db:
        # Cascades to the Scan and any ScanEvent rows created against it.
        target = await db.get(Target, target_id)
        if target is not None:
            await db.delete(target)
            await db.commit()


async def test_scan_event_message_is_encrypted_at_rest(scan):
    async with AsyncSessionLocal() as db:
        event = ScanEvent(scan_id=scan, event_type="test", message="plaintext-marker-xyz")
        db.add(event)
        await db.commit()
        event_id = event.id

    # Raw column bytes must never contain the plaintext.
    async with engine.begin() as conn:
        raw = (await conn.execute(
            text("SELECT message FROM scan_events WHERE id = :id"), {"id": str(event_id)}
        )).first()
        assert b"plaintext-marker-xyz" not in bytes(raw[0])

    # But the ORM (which decrypts via pgp_sym_decrypt) reads it back correctly.
    async with AsyncSessionLocal() as db:
        row = (await db.execute(select(ScanEvent).where(ScanEvent.id == event_id))).scalar_one()
        assert row.message == "plaintext-marker-xyz"


async def test_purge_deletes_only_events_older_than_retention_window(scan):
    async with AsyncSessionLocal() as db:
        old = ScanEvent(scan_id=scan, event_type="old", message="old")
        fresh = ScanEvent(scan_id=scan, event_type="fresh", message="fresh")
        db.add_all([old, fresh])
        await db.commit()
        old_id, fresh_id = old.id, fresh.id

    async with AsyncSessionLocal() as db:
        cutoff_breaching = datetime.now(timezone.utc) - timedelta(days=10)
        await db.execute(
            text("UPDATE scan_events SET created_at = :ts WHERE id = :id"),
            {"ts": cutoff_breaching, "id": str(old_id)},
        )
        await db.commit()

    deleted = await purge_expired_scan_events()
    assert deleted >= 1

    async with AsyncSessionLocal() as db:
        assert (await db.execute(
            select(ScanEvent).where(ScanEvent.id == old_id)
        )).scalar_one_or_none() is None
        assert (await db.execute(
            select(ScanEvent).where(ScanEvent.id == fresh_id)
        )).scalar_one_or_none() is not None
