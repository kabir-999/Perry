"""
Scan debug mode (Part 18): a bracketed-tag trace of *why* a specific
endpoint was or wasn't tested — [CRAWLER]/[BROWSER]/[NETWORK]/[API]/
[PARAM]/[AUTH]/[TEST]/[RESULT]/[RISK]/[COVERAGE].

Zero cost when `settings.SCAN_DEBUG` is off: the logger simply isn't
enabled for DEBUG, so every call here is a cheap level-check that short-
circuits before any string formatting happens (standard `logging` behavior).
"""
from __future__ import annotations

import logging

from app.config import settings

_logger = logging.getLogger("scanner.debug")


def debug_log(tag: str, message: str) -> None:
    """`debug_log("CRAWLER", "Page discovered: https://...")` ->
    `[CRAWLER] Page discovered: https://...` at logging.DEBUG."""
    if not settings.SCAN_DEBUG:
        return
    _logger.debug("[%s] %s", tag, message)


def configure_debug_logging() -> None:
    """Called once at scan start when SCAN_DEBUG is on, so the trace is
    visible even if nothing else configured a DEBUG-level handler."""
    if not settings.SCAN_DEBUG:
        return
    if not _logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        _logger.addHandler(handler)
    _logger.setLevel(logging.DEBUG)
    _logger.propagate = False
