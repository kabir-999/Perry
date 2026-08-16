"""Shared dataclasses for the discovery stage."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class DiscoveredPath:
    url: str
    method: str = "GET"
    status_code: int | None = None
    content_type: str = ""
    response_size: int | None = None
    source: str = ""  # crawler | directory_scan | api_discovery | robots_txt ...
    discovery_method: str = ""

    def key(self) -> str:
        return f"{self.method}:{self.url}"


@dataclass
class DiscoveredParam:
    url: str
    name: str
    # query | form | json | path | header | cookie | multipart | graphql_variable
    param_type: str = "query"
    example_value: str = ""
    method: str = "GET"

    def key(self) -> str:
        # Uniqueness = HTTP method + normalized URL (no scheme, no trailing
        # slash, no query) + parameter name. A parameter seen on many
        # identical requests counts once.
        from urllib.parse import urlsplit

        parts = urlsplit(self.url)
        norm = f"{parts.netloc.lower()}{parts.path.rstrip('/')}"
        return f"{self.method.upper()}:{norm}:{self.name}"


@dataclass
class DiscoveredForm:
    url: str  # action URL (absolute)
    method: str
    params: list[str] = field(default_factory=list)
    has_upload: bool = False  # contains an <input type="file">


@dataclass
class UploadEndpoint:
    url: str
    method: str = "POST"
    field_name: str = "file"  # the <input type="file"> name, for multipart POST
    enctype: str = "multipart/form-data"


@dataclass
class CrawlResult:
    pages: list[DiscoveredPath] = field(default_factory=list)
    internal_links: set[str] = field(default_factory=set)
    external_links: set[str] = field(default_factory=set)
    forms: list[DiscoveredForm] = field(default_factory=list)
    params: list[DiscoveredParam] = field(default_factory=list)
    upload_endpoints: list[UploadEndpoint] = field(default_factory=list)
    # In-scope <script src> URLs. On a single-page app the real attack surface
    # lives inside these bundles, not in the page's links.
    script_urls: set[str] = field(default_factory=set)


@dataclass
class DiscoveredNetworkRequest:
    """One request captured directly off the browser's network layer during
    a browser_crawler.py run — this is *behavioral* discovery: Perry saw
    the browser actually make this call, regardless of whether it came from
    fetch(), XMLHttpRequest, axios, Angular HttpClient, or anything else,
    since they all funnel through the same browser network stack. Never
    classified as an API by string-matching the URL — see
    network_classifier.py, which uses `resource_type` + response
    content-type instead."""

    method: str
    url: str
    origin: str
    path: str
    query: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    content_type: str = ""
    response_status: int | None = None
    response_headers: dict[str, str] = field(default_factory=dict)
    response_content_type: str = ""
    # Playwright's own request classification: "document" | "xhr" | "fetch"
    # | "script" | "stylesheet" | "image" | "font" | "websocket" | ... — the
    # primary signal network_classifier.py uses, precisely because it comes
    # from the browser's own behavior, not a URL guess.
    resource_type: str = ""
    source_page: str = ""  # the page URL that triggered this request
    is_authenticated: bool = False  # sent with the scanner's own credential

    def key(self) -> str:
        from urllib.parse import urlsplit

        parts = urlsplit(self.url)
        return f"{self.method.upper()}:{parts.netloc.lower()}{parts.path.rstrip('/')}"


@dataclass
class BrowserCrawlResult:
    """Everything a real-browser crawl produced — additive to (never a
    replacement for) the static crawler.CrawlResult."""

    pages: list[DiscoveredPath] = field(default_factory=list)
    network_requests: list[DiscoveredNetworkRequest] = field(default_factory=list)
    forms: list[DiscoveredForm] = field(default_factory=list)
    params: list[DiscoveredParam] = field(default_factory=list)
    js_bundle_urls: set[str] = field(default_factory=set)
    websocket_urls: set[str] = field(default_factory=set)
    # Client-side (JS-rendered) routes discovered only by navigating/
    # clicking through the app — a static HTML parse would never see these.
    spa_routes: set[str] = field(default_factory=set)
    pages_rendered: int = 0
    errors: list[str] = field(default_factory=list)
    # Number of DOM interactions (clicks / benign form submits) performed by
    # the interaction engine across the crawl.
    interactions_performed: int = 0
    # Parent/child attack-surface graph built live during the crawl
    # ({"nodes": [...], "edges": [...], "roots": [...]}).
    graph: dict = field(default_factory=dict)
    # Traversal strategy that produced this result: "bfs" | "dfs".
    strategy: str = ""
    # Structured crawl log (one record per navigate / interact / discover /
    # error), for the per-strategy log view.
    log: list[dict] = field(default_factory=list)
    # Deepest depth actually reached during the crawl.
    max_depth_reached: int = 0
