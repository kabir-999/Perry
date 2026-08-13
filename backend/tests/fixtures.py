"""Shared test doubles for the new capability tests."""
from app.services.http_client import FetchResult


class FakeFetcher:
    """A minimal stand-in for http_client.Fetcher.

    `responder` is either a callable `(url, **kwargs) -> FetchResult` for
    scripted per-call behavior, or a list of FetchResults consumed in order.
    """

    def __init__(self, responder, *, budget_exhausted: bool = False):
        self._responder = responder
        self.calls: list[tuple[str, dict]] = []
        self.budget_exhausted = budget_exhausted
        self.requests_made = 0

    async def fetch(self, url: str, **kwargs) -> FetchResult:
        self.calls.append((url, kwargs))
        self.requests_made += 1
        if callable(self._responder):
            return self._responder(url, **kwargs)
        return self._responder.pop(0)

    async def fetch_many(self, urls: list[str], **kwargs) -> list[FetchResult]:
        return [await self.fetch(u, **kwargs) for u in urls]


def ok_result(
    url: str,
    *,
    status_code: int = 200,
    text: str = "",
    headers: dict | None = None,
    content_type: str = "text/html",
) -> FetchResult:
    body = text.encode()
    return FetchResult(
        url=url,
        requested_url=url,
        method="GET",
        status_code=status_code,
        headers={"content-type": content_type, **(headers or {})},
        content_type=content_type,
        text=text,
        body_bytes=len(body),
    )


def error_result(url: str, error: str = "connection_refused") -> FetchResult:
    return FetchResult(url=url, requested_url=url, method="GET", error=error)
