"""
Attack Surface Inventory — the single, centralized structure that every
discovery source populates and that the Test Planner + the 12 attack modules
read from. No attack module crawls or discovers on its own; it only consumes
what is registered here.

Every discovered item gets a stable unique internal ID (``ep_0001`` /
``pm_0001`` / …) so the test matrix, coverage, and report can refer to an
exact endpoint/parameter unambiguously.

Discovery *sources* (static ``crawler``, ``browser_crawler``,
``api_discovery``, ``directory_scanner``, ``js_analyzer``,
``subdomain_scanner``, ``vhost_scanner``, ``auth_discovery``) feed this via
the ``add_*`` methods; the Inventory owns ID assignment and shape-based
deduplication so the same route/parameter seen twice counts once.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from app.services.discovery_types import (
    DiscoveredForm,
    DiscoveredNetworkRequest,
    DiscoveredParam,
    DiscoveredPath,
    UploadEndpoint,
)

# Endpoint kinds — what a discovered endpoint *is*, used by the planner to
# decide which attacks are eligible.
PAGE = "page"
API = "api"
FORM = "form"
UPLOAD = "upload"
REDIRECT = "redirect"

# A path segment that looks like a concrete resource id (numeric or a UUID or
# a long hex/opaque token). Collapsed to ``{id}`` in the normalized route so
# ``/rest/products/1`` and ``/rest/products/2`` are one route with a path
# parameter, not two endpoints.
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HEXISH_RE = re.compile(r"^[0-9a-f]{12,}$", re.I)


def _id_shaped(segment: str) -> bool:
    return bool(segment) and (
        segment.isdigit() or bool(_UUID_RE.match(segment)) or bool(_HEXISH_RE.match(segment))
    )


def normalized_route(url: str) -> str:
    """host + path with id-shaped segments collapsed to ``{id}`` (query
    dropped). The route identity used for endpoint dedup and for spotting
    path parameters."""
    parts = urlsplit(url)
    segments = [s for s in parts.path.split("/") if s]
    norm = "/".join("{id}" if _id_shaped(s) else s for s in segments)
    return f"{parts.netloc.lower()}/{norm}"


@dataclass
class Endpoint:
    endpoint_id: str
    method: str
    url: str
    normalized_route: str
    kind: str = PAGE  # PAGE | API | FORM | UPLOAD | REDIRECT
    source_page: str = ""
    auth_context: str = "unauthenticated"
    status_code: int | None = None
    content_type: str = ""

    def key(self) -> str:
        return f"{self.method.upper()}:{self.normalized_route}"


@dataclass
class Parameter:
    parameter_id: str
    endpoint_id: str
    name: str
    location: str  # query | path | json | form | multipart | header | cookie
    original_value: str = ""
    value_type: str = "string"
    auth_context: str = "unauthenticated"

    def key(self) -> str:
        return f"{self.endpoint_id}:{self.location}:{self.name}"


def _value_type(value: str) -> str:
    if value == "":
        return "string"
    if value.isdigit():
        return "int"
    low = value.lower()
    if low in ("true", "false"):
        return "bool"
    if _UUID_RE.match(value):
        return "uuid"
    return "string"


@dataclass
class AttackSurfaceInventory:
    endpoints: list[Endpoint] = field(default_factory=list)
    parameters: list[Parameter] = field(default_factory=list)
    forms: list[DiscoveredForm] = field(default_factory=list)
    upload_endpoints: list[UploadEndpoint] = field(default_factory=list)
    redirect_endpoints: list[str] = field(default_factory=list)
    auth_routes: dict = field(default_factory=dict)  # from auth_discovery.AuthSurface
    subdomains: list = field(default_factory=list)
    vhosts: list = field(default_factory=list)
    js_bundles: set[str] = field(default_factory=set)
    network_requests: list[DiscoveredNetworkRequest] = field(default_factory=list)

    _ep_by_key: dict = field(default_factory=dict, repr=False)
    _pm_seen: set = field(default_factory=set, repr=False)
    _ep_counter: int = field(default=0, repr=False)
    _pm_counter: int = field(default=0, repr=False)

    # ------------------------------------------------------------- endpoints
    def add_endpoint(
        self,
        url: str,
        *,
        method: str = "GET",
        kind: str = PAGE,
        source_page: str = "",
        auth_context: str = "unauthenticated",
        status_code: int | None = None,
        content_type: str = "",
    ) -> Endpoint:
        route = normalized_route(url)
        key = f"{method.upper()}:{route}"
        existing = self._ep_by_key.get(key)
        if existing is not None:
            # Upgrade kind if a more specific one is now known (page → api/form).
            if existing.kind == PAGE and kind != PAGE:
                existing.kind = kind
            return existing
        self._ep_counter += 1
        ep = Endpoint(
            endpoint_id=f"ep_{self._ep_counter:04d}",
            method=method.upper(),
            url=url,
            normalized_route=route,
            kind=kind,
            source_page=source_page,
            auth_context=auth_context,
            status_code=status_code,
            content_type=content_type,
        )
        self.endpoints.append(ep)
        self._ep_by_key[key] = ep
        return ep

    def add_path(self, path: DiscoveredPath, *, kind: str = PAGE) -> Endpoint:
        return self.add_endpoint(
            path.url, method=path.method or "GET", kind=kind,
            source_page=getattr(path, "source", ""),
            status_code=path.status_code, content_type=path.content_type,
        )

    # ------------------------------------------------------------ parameters
    def add_parameter(
        self,
        endpoint: Endpoint,
        name: str,
        location: str,
        *,
        original_value: str = "",
        auth_context: str | None = None,
    ) -> Parameter | None:
        if not name:
            return None
        key = f"{endpoint.endpoint_id}:{location}:{name}"
        if key in self._pm_seen:
            return None
        self._pm_seen.add(key)
        self._pm_counter += 1
        pm = Parameter(
            parameter_id=f"pm_{self._pm_counter:04d}",
            endpoint_id=endpoint.endpoint_id,
            name=name,
            location=location,
            original_value=original_value,
            value_type=_value_type(original_value),
            auth_context=auth_context or endpoint.auth_context,
        )
        self.parameters.append(pm)
        return pm

    def add_discovered_param(self, dp: DiscoveredParam) -> Parameter | None:
        """Attach a DiscoveredParam to its endpoint (creating the endpoint if
        this is the first time its route is seen)."""
        method = dp.method or ("POST" if dp.param_type in ("form", "json", "multipart") else "GET")
        kind = API if dp.param_type in ("json", "multipart") else PAGE
        ep = self.add_endpoint(dp.url, method=method, kind=kind)
        return self.add_parameter(
            ep, dp.name, dp.param_type, original_value=dp.example_value or "",
        )

    # ------------------------------------------------------------ collections
    def add_form(self, form: DiscoveredForm) -> Endpoint:
        self.forms.append(form)
        ep = self.add_endpoint(form.url, method=form.method or "POST", kind=FORM)
        for name in form.params:
            self.add_parameter(ep, name, "form")
        return ep

    def add_upload(self, upload: UploadEndpoint) -> Endpoint:
        self.upload_endpoints.append(upload)
        return self.add_endpoint(upload.url, method=upload.method or "POST", kind=UPLOAD)

    def add_network_request(self, req: DiscoveredNetworkRequest) -> None:
        self.network_requests.append(req)

    def mark_redirect(self, url: str) -> None:
        if url not in self.redirect_endpoints:
            self.redirect_endpoints.append(url)

    # ------------------------------------------------------------- accessors
    def endpoint(self, endpoint_id: str) -> Endpoint | None:
        return next((e for e in self.endpoints if e.endpoint_id == endpoint_id), None)

    def parameter(self, parameter_id: str) -> Parameter | None:
        return next((p for p in self.parameters if p.parameter_id == parameter_id), None)

    def parameters_for(self, endpoint_id: str) -> list[Parameter]:
        return [p for p in self.parameters if p.endpoint_id == endpoint_id]

    def api_endpoints(self) -> list[Endpoint]:
        return [e for e in self.endpoints if e.kind == API]

    def counts(self) -> dict:
        """Discovery counts — the raw material for crawl coverage (§23)."""
        return {
            "urls": len(self.endpoints),
            "apis": len(self.api_endpoints()),
            "parameters": len(self.parameters),
            "forms": len(self.forms),
            "upload_endpoints": len(self.upload_endpoints),
            "redirect_endpoints": len(self.redirect_endpoints),
            "js_bundles": len(self.js_bundles),
            "network_requests": len(self.network_requests),
            "auth_routes": len(self.auth_routes.get("login_urls", []) if self.auth_routes else []),
            "subdomains": len(self.subdomains),
            "vhosts": len(self.vhosts),
        }
