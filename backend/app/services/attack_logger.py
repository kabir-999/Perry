"""
Production-grade structured JSON logging for attack execution.

Every attack attempt — whether it finds a vulnerability, comes back clean, is
skipped for scope/budget reasons, or errors out — is recorded as one
structured JSON log record. Each record carries a UTC timestamp, a severity
level, the attack identity, the exact target it ran against (endpoint /
parameter / payload), the machine-readable outcome (``status``), and free-form
evidence, mirroring the shape of a real production security log.

The records are collected per-scan through a :class:`contextvars.ContextVar`,
so the concurrent attack runners never have to thread a logger object through
their signatures — a runner just calls :func:`log_attack` and the record lands
in whichever scan's collector is active on the current async context. New
asyncio tasks copy the context at creation time, so records emitted inside the
``asyncio.gather`` fan-out of the executor are attributed to the correct scan
even though the runners execute concurrently.

The collected records are persisted on the scan (``scans.attack_logs_json``),
surfaced in the live snapshot, and rendered in the UI under each attack's box
as an expandable JSON log view.
"""
from __future__ import annotations

import contextvars
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.services.attacks.catalog import DISPLAY_NAME
from app.services.test_status import TestStatus

# --- Severity levels (ordered least → most severe, for UI coloring) ---------
LEVEL_DEBUG = "DEBUG"
LEVEL_INFO = "INFO"
LEVEL_SUCCESS = "SUCCESS"    # a test executed cleanly; target NOT vulnerable
LEVEL_WARNING = "WARNING"    # not tested / not applicable / inconclusive / skipped
LEVEL_ERROR = "ERROR"        # a probe raised or a request failed
LEVEL_ALERT = "ALERT"        # a vulnerability was detected

ALL_LEVELS = (
    LEVEL_DEBUG, LEVEL_INFO, LEVEL_SUCCESS, LEVEL_WARNING, LEVEL_ERROR, LEVEL_ALERT,
)

# Every TestStatus maps deterministically to a log level and an event code, so
# the log is a faithful, machine-readable projection of the test matrix.
_STATUS_LEVEL: dict[str, str] = {
    TestStatus.VULNERABLE: LEVEL_ALERT,
    TestStatus.NOT_VULNERABLE: LEVEL_SUCCESS,
    TestStatus.NOT_TESTED: LEVEL_WARNING,
    TestStatus.INCONCLUSIVE: LEVEL_WARNING,
    TestStatus.NOT_APPLICABLE: LEVEL_WARNING,
}
_STATUS_EVENT: dict[str, str] = {
    TestStatus.VULNERABLE: "vulnerability_detected",
    TestStatus.NOT_VULNERABLE: "test_passed",
    TestStatus.NOT_TESTED: "test_skipped",
    TestStatus.INCONCLUSIVE: "test_inconclusive",
    TestStatus.NOT_APPLICABLE: "not_applicable",
}

# A stderr logger so the same structured line is also visible in server logs
# (as compact JSON), not only in the persisted per-scan collection.
_logger = logging.getLogger("scanner.attack")

_MAX_EVIDENCE = 600
_MAX_MESSAGE = 400


def level_for_status(status: str) -> str:
    return _STATUS_LEVEL.get(status, LEVEL_INFO)


def event_for_status(status: str) -> str:
    return _STATUS_EVENT.get(status, "test")


def _now_iso() -> str:
    """UTC ISO-8601 with millisecond precision and a trailing ``Z``."""
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _clip(value: Any, limit: int) -> str:
    text = "" if value is None else str(value)
    return text if len(text) <= limit else text[: limit - 1] + "…"


@dataclass
class AttackLogRecord:
    """One structured log line for a single attack event."""

    seq: int
    timestamp: str
    level: str
    attack: str
    attack_display: str
    event: str
    message: str
    status: str = ""
    confidence: str = ""
    endpoint: str = ""
    method: str = ""
    parameter: str = ""
    location: str = ""
    payload: str = ""
    evidence: str = ""
    test_id: str = ""
    request_summary: str = ""
    response_summary: str = ""
    meta: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


class AttackLogCollector:
    """Accumulates :class:`AttackLogRecord` dicts for one scan run."""

    def __init__(self) -> None:
        self._records: list[dict] = []
        self._seq = 0

    def record(
        self,
        level: str,
        attack: str,
        event: str,
        message: str,
        *,
        attack_display: str = "",
        status: str = "",
        confidence: str = "",
        endpoint: str = "",
        method: str = "",
        parameter: str = "",
        location: str = "",
        payload: str = "",
        evidence: str = "",
        test_id: str = "",
        request_summary: str = "",
        response_summary: str = "",
        meta: dict | None = None,
    ) -> dict:
        self._seq += 1
        rec = AttackLogRecord(
            seq=self._seq,
            timestamp=_now_iso(),
            level=level,
            attack=attack,
            attack_display=attack_display or DISPLAY_NAME.get(attack, attack),
            event=event,
            message=_clip(message, _MAX_MESSAGE),
            status=status,
            confidence=confidence,
            endpoint=endpoint,
            method=method,
            parameter=parameter,
            location=location,
            payload=_clip(payload, 200),
            evidence=_clip(evidence, _MAX_EVIDENCE),
            test_id=test_id,
            request_summary=_clip(request_summary, 300),
            response_summary=_clip(response_summary, 300),
            meta=meta or {},
        ).to_dict()
        self._records.append(rec)
        if _logger.isEnabledFor(logging.INFO):
            try:
                _logger.info(json.dumps(rec, default=str))
            except Exception:  # logging must never break a scan
                pass
        return rec

    @property
    def records(self) -> list[dict]:
        return self._records

    def __len__(self) -> int:  # pragma: no cover - convenience
        return len(self._records)


# --- Context-variable plumbing ---------------------------------------------
# The collector for the scan currently executing on this async context. New
# tasks (the executor's per-attack gather) copy the context, so they inherit
# the right collector without any explicit passing.
_current: contextvars.ContextVar[AttackLogCollector | None] = contextvars.ContextVar(
    "attack_log_collector", default=None
)


def start_collector() -> AttackLogCollector:
    """Install a fresh collector on the current context and return it."""
    collector = AttackLogCollector()
    _current.set(collector)
    return collector


def get_collector() -> AttackLogCollector | None:
    return _current.get()


def log_attack(level: str, attack: str, event: str, message: str, **fields: Any) -> None:
    """Emit one record into the active collector, if any. A no-op when no scan
    collector is installed (e.g. unit tests that don't opt in), so callers can
    log unconditionally without guarding every call site."""
    collector = _current.get()
    if collector is not None:
        collector.record(level, attack, event, message, **fields)
