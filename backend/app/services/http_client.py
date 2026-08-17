"""
Shared async HTTP layer for the scanner.

Everything that makes a request goes through `Fetcher`, which provides:

  * one pooled, keep-alive ``httpx.AsyncClient`` (connection reuse)
  * bounded concurrency via a semaphore (never unbounded task fan-out) —
    caps how many requests are in flight at once
  * a token-bucket rate limit (optional, ``rate_limit_per_second``) — caps
    how many requests actually egress per second, independent of
    concurrency; a high concurrency cap with fast responses can otherwise
    still burst well past a target's tolerance
  * a per-scan request budget (hard ceiling on total requests)
  * response-size caps enforced by streaming (never download huge bodies)
  * request de-duplication (identical GETs are fetched once)
  * short, explicit timeouts
  * no exceptions leaking to callers — failures come back as a
    ``FetchResult`` with ``error`` set.

Concurrency/budget/timeouts are the scan orchestrator's own safe defaults;
the rate limit is the one dial a user can actually set (``ScanCreate.
rate_limit_per_second``), defaulting to unthrottled (0) when unset.
"""
from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Callable, Optional
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from app.config import settings

_REDIRECT_STATUSES = {301, 302, 303, 307, 308}


def _canonical_url(url: str) -> str:
    """Scheme+host-lowercased, fragment-stripped key for loop detection."""
    parts = urlsplit(url)
    return urlunsplit(
        (
            parts.scheme.lower(),
            parts.netloc.lower(),
            parts.path or "/",
            parts.query,
            "",
        )
    )


@dataclass
class FetchResult:
    """A normalized, size-capped view of one HTTP response (or failure)."""

    url: str  # final URL after redirects
    requested_url: str
    method: str
    status_code: Optional[int] = None
    headers: dict[str, str] = field(default_factory=dict)
    content_type: str = ""
    text: str = ""
    body_bytes: int = 0
    truncated: bool = False
    elapsed_ms: float = 0.0
    redirects: list[tuple[int, str]] = field(default_factory=list)
    redirect_loop: bool = False
    out_of_scope_redirect: bool = False
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.status_code is not None

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)


def build_async_client(
    *,
    timeout: float,
    connect_timeout: float,
    max_connections: int,
    max_keepalive: int,
    follow_redirects: bool = True,
) -> httpx.AsyncClient:
    """Create a pooled AsyncClient with keep-alive connections."""
    limits = httpx.Limits(
        max_connections=max_connections,
        max_keepalive_connections=max_keepalive,
    )
    timeout_cfg = httpx.Timeout(timeout, connect=connect_timeout)
    return httpx.AsyncClient(
        limits=limits,
        timeout=timeout_cfg,
        follow_redirects=follow_redirects,
        headers={"User-Agent": settings.SCANNER_USER_AGENT},
        # We enforce our own size cap by streaming; verify=False would be
        # unsafe, so TLS verification stays on. Self-signed test targets on
        # loopback are reached over http, so this does not hurt latency.
    )


class _TokenBucket:
    """Requests-per-second throttle, independent of the concurrency
    semaphore. Tokens refill continuously (fractional, based on elapsed
    wall-clock time) rather than in fixed per-second ticks, so throughput is
    smoothed rather than steppy. ``rate_per_second <= 0`` disables the
    bucket entirely — ``acquire()`` returns immediately, no lock taken.
    """

    def __init__(self, rate_per_second: float) -> None:
        self._rate = rate_per_second
        self._capacity = max(1.0, rate_per_second)
        self._tokens = self._capacity
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        if self._rate <= 0:
            return
        while True:
            async with self._lock:
                now = time.monotonic()
                elapsed = now - self._updated
                self._updated = now
                self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                wait = (1.0 - self._tokens) / self._rate
            await asyncio.sleep(wait)


class Fetcher:
    """Concurrency-bounded, budgeted, rate-limited, de-duplicating request
    runner over a single shared AsyncClient."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        *,
        concurrency: int,
        request_budget: int,
        max_response_bytes: int,
        rate_limit_per_second: float = 0,
        max_cache_bytes: int = 60_000_000,
    ) -> None:
        self._client = client
        self._sem = asyncio.Semaphore(max(1, concurrency))
        self._budget = request_budget
        self._max_bytes = max_response_bytes
        self._bucket = _TokenBucket(rate_limit_per_second)
        # LRU, byte-capped: a plain unbounded dict here held every unique
        # cacheable response's full body (up to `max_response_bytes` each)
        # for the whole scan. On a content-heavy real-world site with a
        # large request budget, that alone can reach several hundred MB —
        # a bigger contributor to container OOM than Chromium on such
        # sites. Caching still avoids redundant re-fetches within a scan
        # (multiple attack modules often want the same URL); it just no
        # longer grows without bound — oldest entries are evicted once the
        # byte cap is hit.
        self._cache: "OrderedDict[tuple[str, str, bool], FetchResult]" = OrderedDict()
        self._cache_bytes = 0
        self._max_cache_bytes = max_cache_bytes
        self._lock = asyncio.Lock()
        self.requests_made = 0

    @property
    def budget_exhausted(self) -> bool:
        return self.requests_made >= self._budget

    async def fetch(
        self,
        url: str,
        *,
        method: str = "GET",
        follow_redirects: bool = True,
        use_cache: bool = True,
        headers: Optional[dict[str, str]] = None,
        json: object = None,
        data: Optional[dict] = None,
        files: Optional[dict] = None,
    ) -> FetchResult:
        # Requests with custom headers or a body (e.g. POST form/JSON tests, a
        # spoofed Host for VHost probing, a multipart file upload) are never
        # cached — the response depends on them.
        cacheable = (
            use_cache and not headers and json is None and data is None and files is None
        )
        key = (method.upper(), url, follow_redirects)
        if cacheable and key in self._cache:
            self._cache.move_to_end(key)
            return self._cache[key]

        # Reserve a budget slot atomically so concurrent callers can't blow
        # past the ceiling.
        async with self._lock:
            if self.requests_made >= self._budget:
                return FetchResult(
                    url=url,
                    requested_url=url,
                    method=method,
                    error="request_budget_exhausted",
                )
            self.requests_made += 1

        await self._bucket.acquire()
        result = await self._do_fetch(
            url, method, follow_redirects, headers, json, data, files
        )
        if cacheable:
            self._cache[key] = result
            self._cache.move_to_end(key)
            self._cache_bytes += result.body_bytes
            while self._cache_bytes > self._max_cache_bytes and len(self._cache) > 1:
                _, evicted = self._cache.popitem(last=False)
                self._cache_bytes -= evicted.body_bytes
        return result

    async def _do_fetch(
        self,
        url: str,
        method: str,
        follow_redirects: bool,
        headers: Optional[dict[str, str]] = None,
        json: object = None,
        data: Optional[dict] = None,
        files: Optional[dict] = None,
    ) -> FetchResult:
        started = time.perf_counter()
        request_kwargs: dict = {"follow_redirects": follow_redirects}
        if headers:
            request_kwargs["headers"] = headers
        if json is not None:
            request_kwargs["json"] = json
        if data is not None:
            request_kwargs["data"] = data
        if files is not None:
            request_kwargs["files"] = files

        # A single dropped packet must not read as "this path is safe" —
        # one bounded retry distinguishes a transient blip from a real
        # connectivity/timeout problem before we give up on this request.
        _TRANSIENT_RETRIES = 1
        _RETRY_BACKOFF_SECONDS = 0.3

        async with self._sem:
            for attempt in range(_TRANSIENT_RETRIES + 1):
                try:
                    async with self._client.stream(
                        method, url, **request_kwargs
                    ) as response:
                        chunks: list[bytes] = []
                        total = 0
                        truncated = False
                        async for chunk in response.aiter_bytes():
                            chunks.append(chunk)
                            total += len(chunk)
                            if total >= self._max_bytes:
                                truncated = True
                                break
                        raw = b"".join(chunks)[: self._max_bytes]
                        encoding = response.charset_encoding or "utf-8"
                        try:
                            text = raw.decode(encoding, errors="replace")
                        except (LookupError, TypeError):
                            text = raw.decode("utf-8", errors="replace")

                        redirects = [
                            (r.status_code, r.headers.get("location", ""))
                            for r in response.history
                        ]
                        headers = {k.lower(): v for k, v in response.headers.items()}
                        return FetchResult(
                            url=str(response.url),
                            requested_url=url,
                            method=method.upper(),
                            status_code=response.status_code,
                            headers=headers,
                            content_type=headers.get("content-type", ""),
                            text=text,
                            body_bytes=total,
                            truncated=truncated,
                            elapsed_ms=(time.perf_counter() - started) * 1000,
                            redirects=redirects,
                        )
                except httpx.ConnectError:
                    error = "connection_refused"
                    transient = True
                except httpx.ConnectTimeout:
                    error = "connect_timeout"
                    transient = True
                except (httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout):
                    error = "timeout"
                    transient = True
                except httpx.TooManyRedirects:
                    error = "too_many_redirects"
                    transient = False
                except httpx.InvalidURL:
                    error = "invalid_url"
                    transient = False
                except httpx.HTTPError as exc:
                    error = f"http_error:{type(exc).__name__}"
                    transient = False
                except Exception as exc:  # pragma: no cover - defensive
                    error = f"unexpected:{type(exc).__name__}"
                    transient = False

                if transient and attempt < _TRANSIENT_RETRIES:
                    await asyncio.sleep(_RETRY_BACKOFF_SECONDS)
                    continue
                break

            return FetchResult(
                url=url,
                requested_url=url,
                method=method.upper(),
                elapsed_ms=(time.perf_counter() - started) * 1000,
                error=error,
            )

    async def fetch_with_redirects(
        self,
        url: str,
        *,
        in_scope: Optional[Callable[[str], bool]] = None,
        max_redirects: Optional[int] = None,
    ) -> FetchResult:
        """Follow redirects manually, with loop and scope guards.

        Never relies on httpx's auto-follow. Returns the terminal response
        with the full redirect chain attached. A redirect loop, an
        out-of-scope hop, or exceeding the depth limit stops following and is
        reported via flags on the result — none of them is an error, so the
        fast scan can still produce an assessment.
        """
        if max_redirects is None:
            max_redirects = settings.REDIRECT_MAX_DEPTH

        chain: list[tuple[int, str]] = []
        seen = {_canonical_url(url)}
        current = url

        for _hop in range(max_redirects + 1):
            res = await self.fetch(
                current, follow_redirects=False, use_cache=False
            )
            res.redirects = list(chain)
            if not res.ok:
                return res  # connection error / timeout: propagate as-is

            location = res.header("location")
            if res.status_code in _REDIRECT_STATUSES and location:
                target = urljoin(current, location)
                chain.append((res.status_code, target))
                res.redirects = list(chain)

                if in_scope is not None and not in_scope(target):
                    res.out_of_scope_redirect = True
                    return res  # reachable, but we won't leave scope
                if _canonical_url(target) in seen:
                    res.redirect_loop = True
                    return res
                seen.add(_canonical_url(target))
                current = target
                continue

            return res  # terminal (non-redirect) response

        # Depth exhausted without a terminal response: treat as a loop.
        res.redirect_loop = True
        res.redirects = list(chain)
        return res

    async def fetch_many(
        self, urls: list[str], *, method: str = "GET", follow_redirects: bool = True
    ) -> list[FetchResult]:
        """Fetch a batch concurrently (bounded by the internal semaphore)."""
        tasks = [
            self.fetch(u, method=method, follow_redirects=follow_redirects)
            for u in urls
        ]
        return await asyncio.gather(*tasks)
