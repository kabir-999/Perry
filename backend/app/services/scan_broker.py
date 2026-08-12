"""
In-process pub/sub bridging the background scan tasks to SSE subscribers.

The scan orchestrator and the SSE endpoint run in the same event loop, so a
simple per-scan fan-out of ``asyncio.Queue`` objects is enough — no Redis or
external broker. Subscribers that fall behind drop intermediate messages
(the payload is always a full snapshot, so the next one resynchronises them).
"""
from __future__ import annotations

import asyncio
from collections import defaultdict


class ScanBroker:
    def __init__(self, max_queue: int = 32) -> None:
        self._subscribers: dict[str, set[asyncio.Queue]] = defaultdict(set)
        self._max_queue = max_queue

    def subscribe(self, scan_id: str) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=self._max_queue)
        self._subscribers[scan_id].add(queue)
        return queue

    def unsubscribe(self, scan_id: str, queue: asyncio.Queue) -> None:
        subs = self._subscribers.get(scan_id)
        if not subs:
            return
        subs.discard(queue)
        if not subs:
            self._subscribers.pop(scan_id, None)

    def publish(self, scan_id: str, message: dict) -> None:
        """Non-blocking broadcast. Drops the oldest message on a full queue
        rather than blocking the scan."""
        for queue in list(self._subscribers.get(scan_id, ())):
            if queue.full():
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            try:
                queue.put_nowait(message)
            except asyncio.QueueFull:  # pragma: no cover - race
                pass

    def has_subscribers(self, scan_id: str) -> bool:
        return bool(self._subscribers.get(scan_id))


# Process-wide singleton.
scan_broker = ScanBroker()
