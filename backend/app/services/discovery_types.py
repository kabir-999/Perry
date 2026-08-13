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
    param_type: str = "query"  # query | form
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
