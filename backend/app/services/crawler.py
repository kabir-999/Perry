"""
Bounded, breadth-first web crawler.

Stays strictly in scope (external links are recorded, never fetched),
processes each depth level as one concurrent batch (no unbounded task
fan-out), de-duplicates URLs, and extracts links, forms, and query
parameters. Bounded by ``max_pages`` and ``max_depth``.
"""
from __future__ import annotations

from urllib.parse import parse_qs, urldefrag, urljoin, urlsplit, urlunsplit

from bs4 import BeautifulSoup

from app.services.discovery_types import (
    CrawlResult,
    DiscoveredForm,
    DiscoveredParam,
    DiscoveredPath,
    UploadEndpoint,
)
from app.services.http_client import Fetcher
from app.services.response_analyzer import analyze
from app.services.scope import TargetScope

_SKIP_EXT = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css", ".woff",
    ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".gz", ".mp4", ".webp",
)


def _canonical(url: str) -> str:
    """Drop fragment; keep query. Used for the visited set."""
    url, _ = urldefrag(url)
    parts = urlsplit(url)
    path = parts.path or "/"
    return urlunsplit((parts.scheme, parts.netloc, path, parts.query, ""))


def _dedup_path(url: str) -> str:
    """Path+sorted-param-names key, so ?id=1 and ?id=2 aren't crawled twice."""
    parts = urlsplit(url)
    names = ",".join(sorted(parse_qs(parts.query).keys()))
    return f"{parts.netloc}{parts.path}?{names}"


async def crawl(
    fetcher: Fetcher,
    scope: TargetScope,
    *,
    seed_url: str,
    seed_html: str | None,
    max_pages: int,
    max_depth: int,
    on_page=None,
) -> CrawlResult:
    result = CrawlResult()
    visited: set[str] = set()
    seen_path_shapes: set[str] = set()

    seed = _canonical(seed_url)
    frontier: list[str] = [seed]
    visited.add(seed)
    seen_path_shapes.add(_dedup_path(seed))

    # Reuse the homepage HTML the fast scan already fetched, if provided.
    preloaded = {seed: seed_html} if seed_html else {}

    depth = 0
    while frontier and depth <= max_depth and len(result.pages) < max_pages:
        batch = frontier[: max_pages - len(result.pages)]
        frontier = []

        # Fetch this depth level concurrently (skip the preloaded seed).
        to_fetch = [u for u in batch if u not in preloaded]
        fetched = await fetcher.fetch_many(to_fetch)
        by_url = {r.requested_url: r for r in fetched}

        for url in batch:
            if url in preloaded:
                html = preloaded[url]
                page = DiscoveredPath(
                    url=url, status_code=200, content_type="text/html",
                    response_size=len(html or ""), source="crawler",
                    discovery_method="crawler",
                )
            else:
                res = by_url.get(url)
                if res is None or not res.ok:
                    continue
                analyzed = analyze(res)
                page = DiscoveredPath(
                    url=res.url,
                    status_code=res.status_code,
                    content_type=res.content_type,
                    response_size=res.body_bytes,
                    source="crawler",
                    discovery_method="crawler",
                )
                html = res.text if analyzed.is_html else ""

            result.pages.append(page)
            if on_page:
                on_page(len(result.pages))

            if not html:
                continue
            _extract(url, html, scope, result, frontier, visited, seen_path_shapes)

        depth += 1

    return result


def _extract(base_url, html, scope, result, frontier, visited, seen_shapes):
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return

    # Links
    for tag in soup.find_all("a", href=True):
        raw = tag["href"].strip()
        if not raw or raw.startswith(("javascript:", "mailto:", "tel:", "#")):
            continue
        absolute = _canonical(urljoin(base_url, raw))
        if not absolute.startswith(("http://", "https://")):
            continue
        if scope.in_scope(absolute):
            result.internal_links.add(absolute)
            _record_query_params(absolute, result)
            if absolute.lower().endswith(_SKIP_EXT):
                continue
            shape = _dedup_path(absolute)
            if absolute not in visited and shape not in seen_shapes:
                visited.add(absolute)
                seen_shapes.add(shape)
                frontier.append(absolute)
        else:
            result.external_links.add(absolute)

    # Script bundles — collected for later analysis, never crawled as pages.
    for tag in soup.find_all("script", src=True):
        raw = tag["src"].strip()
        if not raw:
            continue
        absolute = _canonical(urljoin(base_url, raw))
        if absolute.startswith(("http://", "https://")) and scope.in_scope(absolute):
            result.script_urls.add(absolute)

    # Forms
    for form in soup.find_all("form"):
        action = urljoin(base_url, (form.get("action") or "").strip() or base_url)
        method = (form.get("method") or "GET").upper()
        names = []
        enctype = (form.get("enctype") or "").lower() or "application/x-www-form-urlencoded"
        has_upload = enctype == "multipart/form-data"
        file_field_name = ""
        for field_tag in form.find_all(["input", "textarea", "select"]):
            name = field_tag.get("name")
            if (field_tag.get("type") or "").lower() == "file":
                has_upload = True
                file_field_name = name or file_field_name
            if name:
                names.append(name)
        if not scope.in_scope(action):
            continue
        result.forms.append(
            DiscoveredForm(url=action, method=method, params=names, has_upload=has_upload)
        )
        if has_upload:
            result.upload_endpoints.append(
                UploadEndpoint(
                    url=action,
                    method=method or "POST",
                    field_name=file_field_name or "file",
                    enctype=enctype or "multipart/form-data",
                )
            )
        for name in names:
            result.params.append(
                DiscoveredParam(
                    url=action, name=name, param_type="form", method=method
                )
            )


def _record_query_params(url: str, result: CrawlResult) -> None:
    parts = urlsplit(url)
    if not parts.query:
        return
    base = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
    for name, values in parse_qs(parts.query, keep_blank_values=True).items():
        result.params.append(
            DiscoveredParam(
                url=base,
                name=name,
                param_type="query",
                example_value=(values[0] if values else ""),
            )
        )
