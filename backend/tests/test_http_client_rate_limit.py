"""
Requests-per-second rate limiting in `Fetcher` — a token bucket independent
of the existing concurrency semaphore and request budget. `rate_limit_per_second
<= 0` (the default when a user doesn't set one) must produce identical,
unthrottled behavior to before this feature existed.
"""
import time

import httpx
import pytest

from app.services.http_client import Fetcher, _TokenBucket


def _instant_client() -> httpx.AsyncClient:
    """A real AsyncClient whose transport responds immediately with no
    network I/O — isolates rate-limiter timing from real latency."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_zero_rate_limit_is_unthrottled():
    client = _instant_client()
    fetcher = Fetcher(client, concurrency=20, request_budget=100,
                       max_response_bytes=10_000, rate_limit_per_second=0)
    t0 = time.monotonic()
    for _ in range(20):
        await fetcher.fetch("https://example.com/x", use_cache=False)
    elapsed = time.monotonic() - t0
    await client.aclose()
    assert elapsed < 0.5, f"unthrottled fetch took {elapsed:.2f}s — rate=0 must not throttle"


async def test_low_rate_limit_throttles_total_time():
    client = _instant_client()
    fetcher = Fetcher(client, concurrency=20, request_budget=100,
                       max_response_bytes=10_000, rate_limit_per_second=5)
    t0 = time.monotonic()
    for _ in range(10):
        await fetcher.fetch("https://example.com/x", use_cache=False)
    elapsed = time.monotonic() - t0
    await client.aclose()
    # 10 requests at 5/sec, 5-token starting capacity: ~1s of throttled wait.
    assert elapsed >= 0.8, f"rate=5/s, 10 requests took only {elapsed:.2f}s — not throttled"


async def test_cache_hits_never_consume_a_token():
    client = _instant_client()
    fetcher = Fetcher(client, concurrency=20, request_budget=100,
                       max_response_bytes=10_000, rate_limit_per_second=1)
    # First call pays for one token; every repeat is a cache hit and should
    # return instantly regardless of the 1/sec limit.
    await fetcher.fetch("https://example.com/x", use_cache=True)
    t0 = time.monotonic()
    for _ in range(10):
        await fetcher.fetch("https://example.com/x", use_cache=True)
    elapsed = time.monotonic() - t0
    await client.aclose()
    assert elapsed < 0.2, f"cache hits took {elapsed:.2f}s — should never touch the rate limiter"


async def test_budget_exhausted_never_waits_on_a_token():
    """A request past the budget ceiling must fail immediately, not wait for
    a token it will never use."""
    client = _instant_client()
    fetcher = Fetcher(client, concurrency=20, request_budget=1,
                       max_response_bytes=10_000, rate_limit_per_second=0.1)
    await fetcher.fetch("https://example.com/a", use_cache=False)
    t0 = time.monotonic()
    result = await fetcher.fetch("https://example.com/b", use_cache=False)
    elapsed = time.monotonic() - t0
    await client.aclose()
    assert result.error == "request_budget_exhausted"
    assert elapsed < 0.2


@pytest.mark.parametrize("rate", [0, -1])
async def test_token_bucket_disabled_for_non_positive_rates(rate):
    bucket = _TokenBucket(rate)
    t0 = time.monotonic()
    for _ in range(50):
        await bucket.acquire()
    assert time.monotonic() - t0 < 0.1
