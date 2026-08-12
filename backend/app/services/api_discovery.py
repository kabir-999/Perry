"""
API endpoint discovery.

Combines three cheap signals:
  1. OpenAPI/Swagger documents (parsed for declared paths + parameters)
  2. probing a short list of common API base paths
  3. API-looking links already seen by the crawler (contain /api/ or return JSON)

Soft-404s are rejected via the not-found profile; JSON responses are treated
as strong API signals.
"""
from __future__ import annotations

import json
from urllib.parse import urljoin, urlsplit

from app.services.discovery_types import DiscoveredParam, DiscoveredPath
from app.services.http_client import Fetcher
from app.services.response_analyzer import NotFoundProfile, analyze
from app.services.scope import TargetScope
from app.services.wordlists import API_PATHS


async def discover_apis(
    fetcher: Fetcher,
    scope: TargetScope,
    not_found: NotFoundProfile,
    crawl_internal_links: set[str],
) -> tuple[list[DiscoveredPath], list[DiscoveredParam]]:
    origin = scope.origin
    endpoints: dict[str, DiscoveredPath] = {}
    params: list[DiscoveredParam] = []

    probe_urls = [f"{origin}/{path}" for path in API_PATHS]
    results = await fetcher.fetch_many(probe_urls)

    for res, probe_path in zip(results, API_PATHS):
        analyzed = analyze(res)
        if not res.ok:
            continue
        is_doc = _looks_like_openapi(res)
        if is_doc:
            _record(endpoints, res.url, "api_docs")
            doc_paths, doc_params = _parse_openapi(res.text, scope)
            for path in doc_paths:
                _record(endpoints, path, "api_docs")
            params += doc_params
            continue
        if not not_found.is_real_hit(analyzed, probe_path):
            continue
        # An API path answering with the SPA shell is the catch-all route, not
        # an endpoint — only JSON-ish responses count as an API discovery.
        if analyzed.is_html and not_found.is_spa:
            continue
        if analyzed.is_json or "/api" in urlsplit(res.url).path.lower():
            _record(endpoints, res.url, "api_discovery")

    # Promote crawler links that look like API calls.
    for link in crawl_internal_links:
        path = urlsplit(link).path.lower()
        if "/api" in path or "/graphql" in path:
            _record(endpoints, link, "api_discovery")

    return list(endpoints.values()), params


def _record(store: dict, url: str, method_source: str) -> None:
    if url in store:
        return
    store[url] = DiscoveredPath(
        url=url,
        source=method_source,
        discovery_method="api_discovery",
    )


def _looks_like_openapi(res) -> bool:
    if not res.ok or res.status_code != 200:
        return False
    body = res.text.lstrip()
    if not body.startswith("{"):
        return False
    return '"openapi"' in body[:2000] or '"swagger"' in body[:2000]


def _parse_openapi(
    body: str, scope: TargetScope
) -> tuple[list[str], list[DiscoveredParam]]:
    paths: list[str] = []
    params: list[DiscoveredParam] = []
    try:
        doc = json.loads(body)
    except (ValueError, TypeError):
        return paths, params
    base = scope.origin
    for raw_path, item in (doc.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        # Skip templated path segments for the probe URL but still record.
        url = urljoin(base + "/", raw_path.lstrip("/"))
        paths.append(url)
        for method, op in item.items():
            if not isinstance(op, dict):
                continue
            for param in op.get("parameters", []) or []:
                if isinstance(param, dict) and param.get("name"):
                    params.append(
                        DiscoveredParam(
                            url=url,
                            name=param["name"],
                            param_type=param.get("in", "query"),
                            method=method.upper(),
                        )
                    )
    return paths, params
