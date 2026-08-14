"""
Behavior-based classification of a captured network request.

Deliberately never keys off a "/api/" (or similar) substring in the URL —
that's exactly the false signal that made Sentinel report "APIs: 0" against
Juice Shop, whose real API lives at /rest/... and /api/... and dozens of
other shapes no wordlist would guess. Instead this uses what the browser
itself already knows about the request: Playwright's own `resource_type`
(a real behavioral fact — the browser issued this as an XHR/fetch, not as
a page navigation or an asset load) plus the response's actual
content-type. Path shape is used only as a last-resort tiebreaker, never
the primary signal.
"""
from __future__ import annotations

import re

from app.services.discovery_types import DiscoveredNetworkRequest

API = "api"
PAGE = "page"
ASSET = "asset"
GRAPHQL = "graphql"
WEBSOCKET = "websocket"

# Playwright resource_type values that mean "the browser fetched this as
# structured data for the app to consume", not "navigated to it" or
# "loaded it as a static asset".
_API_RESOURCE_TYPES = {"xhr", "fetch"}
_ASSET_RESOURCE_TYPES = {
    "stylesheet", "image", "font", "media", "manifest", "texttrack",
}
_PAGE_RESOURCE_TYPES = {"document"}

_JSON_LIKE_CONTENT_TYPE = re.compile(r"(?i)\b(json|graphql)\b")
_GRAPHQL_PATH_RE = re.compile(r"(?i)/graphql\b")


def classify_request(req: DiscoveredNetworkRequest) -> str:
    """Returns "api" | "page" | "asset" | "graphql" | "websocket"."""
    if req.resource_type == "websocket" or req.url.startswith(("ws://", "wss://")):
        return WEBSOCKET

    if req.resource_type in _ASSET_RESOURCE_TYPES:
        return ASSET

    # A behavioral signal, not a path guess: the browser itself issued this
    # as an XHR/fetch call, or the response came back as JSON/GraphQL.
    is_structured_response = bool(_JSON_LIKE_CONTENT_TYPE.search(req.response_content_type or ""))
    is_structured_request = bool(_JSON_LIKE_CONTENT_TYPE.search(req.content_type or ""))

    if req.resource_type in _API_RESOURCE_TYPES or is_structured_response or is_structured_request:
        if _GRAPHQL_PATH_RE.search(req.path) or "graphql" in (req.response_content_type or "").lower():
            return GRAPHQL
        return API

    if req.resource_type in _PAGE_RESOURCE_TYPES:
        return PAGE

    # Last-resort tiebreaker only for requests Playwright didn't tag with a
    # resource_type we recognize (e.g. captured via a lower-level hook) —
    # script requests that came back as JSON are still data, not a page.
    if is_structured_response:
        return API
    return ASSET if req.resource_type in ("script", "other") else PAGE
