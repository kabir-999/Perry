"""
Parameter discovery.

Aggregates and de-duplicates parameters observed by the crawler (query
strings + forms), the API discovery stage, and — new — the browser
crawler's captured network traffic. Does not brute-force hidden
parameters — it consolidates what was actually seen, which the security
checks then probe.
"""
from __future__ import annotations

import json
import re
from urllib.parse import parse_qsl, urlsplit

from app.services.discovery_types import DiscoveredNetworkRequest, DiscoveredParam

# Standard/infrastructure headers, never application parameters.
_STANDARD_HEADERS = {
    "accept", "accept-encoding", "accept-language", "connection",
    "content-length", "content-type", "host", "origin", "referer",
    "user-agent", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
    "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user",
    "upgrade-insecure-requests", "cache-control", "pragma", "cookie",
    "authorization", "te", "dnt",
}

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)
_JSON_CONTENT_RE = re.compile(r"(?i)\bjson\b")
_FORM_CONTENT_RE = re.compile(r"(?i)application/x-www-form-urlencoded")
_MULTIPART_CONTENT_RE = re.compile(r"(?i)multipart/form-data")
_GRAPHQL_RE = re.compile(r"(?i)/graphql\b")


def consolidate_parameters(
    *param_lists: list[DiscoveredParam],
) -> list[DiscoveredParam]:
    seen: dict[str, DiscoveredParam] = {}
    for params in param_lists:
        for p in params:
            if not p.name:
                continue
            key = p.key()
            if key not in seen:
                seen[key] = p
            elif p.example_value and not seen[key].example_value:
                seen[key].example_value = p.example_value
    return list(seen.values())


def _looks_like_id(segment: str) -> bool:
    return bool(segment) and (segment.isdigit() or bool(_UUID_RE.match(segment)))


def _flatten_json(value, prefix: str = "", depth: int = 0) -> dict[str, str]:
    """Top-level (and one level of nesting) JSON body fields, flattened to
    dotted names — deep nesting rarely maps to a testable parameter and
    would just add noise."""
    out: dict[str, str] = {}
    if depth > 2 or not isinstance(value, dict):
        return out
    for k, v in value.items():
        name = f"{prefix}.{k}" if prefix else str(k)
        if isinstance(v, dict):
            out.update(_flatten_json(v, name, depth + 1))
        elif isinstance(v, list):
            out[name] = ""
        else:
            out[name] = "" if v is None else str(v)
    return out


def extract_params_from_network(
    requests: list[DiscoveredNetworkRequest],
) -> list[DiscoveredParam]:
    """Parameters observed directly in captured browser network traffic:
    query strings, JSON/form/multipart bodies, GraphQL variables, path
    segments that vary across otherwise-identical requests (inferred path
    parameters), and non-standard request headers/cookies."""
    params: list[DiscoveredParam] = []

    # --- Path parameters: group same-method requests whose path differs
    # only in one id-shaped segment, e.g. /rest/products/1 vs /rest/products/2.
    by_shape: dict[str, list[tuple[str, str]]] = {}
    for req in requests:
        segments = [s for s in req.path.split("/") if s]
        for i, seg in enumerate(segments):
            if not _looks_like_id(seg):
                continue
            shape_segments = segments.copy()
            shape_segments[i] = "{}"
            shape = f"{req.method.upper()}:{'/'.join(shape_segments)}"
            base_url = f"{req.origin}/" + "/".join(
                shape_segments[:i] + ["0"] + shape_segments[i + 1:]
            ).lstrip("/")
            name = f"{segments[i - 1]}_id" if i > 0 else "id"
            by_shape.setdefault(shape, []).append((base_url, seg))

    for shape, occurrences in by_shape.items():
        if len(occurrences) < 1:
            continue
        method = shape.split(":", 1)[0]
        base_url, example = occurrences[0]
        segments = shape.split(":", 1)[1].split("/")
        idx = segments.index("{}")
        name = f"{segments[idx - 1]}_id" if idx > 0 else "id"
        params.append(
            DiscoveredParam(
                url=base_url, name=name, param_type="path",
                example_value=example, method=method,
            )
        )

    for req in requests:
        base_url = f"{req.origin}{req.path}"
        method = req.method.upper()
        is_graphql = bool(_GRAPHQL_RE.search(req.path))

        # Query string.
        for name, value in parse_qsl(urlsplit(req.url).query, keep_blank_values=True):
            params.append(
                DiscoveredParam(url=base_url, name=name, param_type="query",
                                 example_value=value, method=method)
            )

        # Body.
        content_type = req.content_type or ""
        body = req.body or ""
        if body and _JSON_CONTENT_RE.search(content_type):
            try:
                doc = json.loads(body)
            except (ValueError, TypeError):
                doc = None
            if isinstance(doc, dict):
                if is_graphql and isinstance(doc.get("variables"), dict):
                    for name, value in _flatten_json(doc["variables"]).items():
                        params.append(
                            DiscoveredParam(url=base_url, name=name,
                                             param_type="graphql_variable",
                                             example_value=value, method=method)
                        )
                else:
                    for name, value in _flatten_json(doc).items():
                        params.append(
                            DiscoveredParam(url=base_url, name=name,
                                             param_type="json",
                                             example_value=value, method=method)
                        )
        elif body and _FORM_CONTENT_RE.search(content_type):
            for name, value in parse_qsl(body, keep_blank_values=True):
                params.append(
                    DiscoveredParam(url=base_url, name=name, param_type="form",
                                     example_value=value, method=method)
                )
        elif body and _MULTIPART_CONTENT_RE.search(content_type):
            for match in re.finditer(r'name="([^"]+)"', body):
                params.append(
                    DiscoveredParam(url=base_url, name=match.group(1),
                                     param_type="multipart", method=method)
                )

        # Non-standard request headers.
        for header_name, header_value in req.headers.items():
            if header_name.lower() in _STANDARD_HEADERS:
                continue
            params.append(
                DiscoveredParam(url=base_url, name=header_name,
                                 param_type="header",
                                 example_value=header_value, method=method)
            )

        # Cookies.
        cookie_header = req.headers.get("cookie") or req.headers.get("Cookie")
        if cookie_header:
            for part in cookie_header.split(";"):
                if "=" not in part:
                    continue
                name, value = part.split("=", 1)
                params.append(
                    DiscoveredParam(url=base_url, name=name.strip(),
                                     param_type="cookie",
                                     example_value=value.strip(), method=method)
                )

    return params
