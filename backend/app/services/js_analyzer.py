"""
JavaScript bundle & source-map analysis.

On a single-page app the server has no /admin or /dashboard — those are client
routes, and the real attack surface is the set of API paths the bundle calls.
Link crawling cannot see them and wordlist probing only guesses, so we read the
bundles themselves.

Two things are extracted:

  1. **Path literals** ("/api/v1/users", fetch("/graphql"), route tables). These
     are *claims* made by the code, so each one is probed and passed through the
     not-found profile before it is reported — a string in a bundle is not proof
     that an endpoint exists.
  2. **Source maps**. A published .map leaks the original source tree (and often
     the source itself), which is both a finding in its own right and a map of
     the application's structure.

Everything is bounded: a few bundles, a capped number of probes, and the shared
request budget applies throughout.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from app.services.discovery_types import DiscoveredPath
from app.services.finding_types import FindingCandidate
from app.services.http_client import Fetcher
from app.services.response_analyzer import NotFoundProfile, analyze
from app.services.scope import TargetScope

# How much work this stage is allowed to do.
MAX_BUNDLES = 8
MAX_SOURCE_MAPS = 4
MAX_PATH_PROBES = 25

# Quoted absolute paths: "/api/v1/users", '/auth/login'. Deliberately narrow —
# a leading slash and URL-safe characters only.
_PATH_LITERAL_RE = re.compile(r"""["'`](/[A-Za-z0-9._~\-/]{2,120})["'`]""")

# Template-literal paths with an interpolated id: `/api/users/${id}`
_TEMPLATE_PATH_RE = re.compile(r"""[`"'](/[A-Za-z0-9._~\-/]*?)\$\{""")

_SOURCE_MAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")

# Call-pattern candidates: fetch()/axios.*()/Angular HttpClient-shaped
# `.get(`/`.post(`/`.put(`/`.delete(`/`.patch(` calls, and XMLHttpRequest.open,
# whose first (or second, for .open) argument is an *absolute* URL literal —
# the plain path-literal regex above only catches leading-"/" strings, so a
# bundle that calls a different origin (`fetch("https://api.example.com/x")`)
# needs this pattern instead. Still just a candidate: verified below like
# every other extracted path.
_ABS_CALL_RE = re.compile(
    r"""(?:fetch|axios\.(?:get|post|put|delete|patch)|\.open)\s*\(\s*"""
    r"""(?:["'][A-Za-z]+["']\s*,\s*)?["'`](https?://[A-Za-z0-9._~\-/:%]{4,160})["'`]"""
)

# A GraphQL operation string literal (`query { ... }` / `mutation Foo(...)`).
# Presence implies a /graphql endpoint even if no literal "/graphql" string
# appears elsewhere in the bundle.
_GRAPHQL_OP_RE = re.compile(r"""[`"'\s](?:query|mutation)\s+\w""", re.IGNORECASE)

# `new WebSocket("wss://...")` — discovery-only (Part 3's explicit scope-down
# for full WS protocol fuzzing); collected so callers can at least record the
# endpoint exists.
_WEBSOCKET_CALL_RE = re.compile(
    r"""new\s+WebSocket\s*\(\s*["'`](wss?://[A-Za-z0-9._~\-/:%]{4,160})["'`]"""
)

# Static assets and framework noise — never endpoints.
_ASSET_EXTENSIONS = (
    ".js", ".mjs", ".cjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif",
    ".svg", ".webp", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webm",
    ".avif", ".wasm", ".txt", ".xml", ".json.gz",
)

# Path prefixes that are build output or third-party plumbing, not app routes.
_NOISE_PREFIXES = (
    "/static/", "/assets/", "/_next/static/", "/node_modules/", "/dist/",
    "/build/", "/chunks/", "/fonts/", "/images/", "/img/", "/media/",
    "/__webpack", "/@vite/", "/@react-refresh", "/sockjs-node/",
)

# Common MIME/header/junk strings that look like paths but are not.
_NOISE_EXACT = {
    "/", "//", "/*", "/#", "/.", "/..", "/null", "/undefined", "/true",
    "/false", "/text/html", "/application/json", "/image/png", "/charset",
}

# Paths worth probing first: these look like real server routes.
_INTERESTING_RE = re.compile(
    r"^/(api|v\d|rest|graphql|auth|oauth|login|logout|session|token|user|users|"
    r"account|admin|internal|private|upload|download|file|files|export|import|"
    r"search|query|config|settings|health|status|metrics|debug|webhook|callback)"
    r"(/|$)",
    re.IGNORECASE,
)


@dataclass
class JsAnalysisResult:
    endpoints: list[DiscoveredPath] = field(default_factory=list)
    findings: list[FindingCandidate] = field(default_factory=list)
    bundles_analyzed: int = 0
    paths_extracted: int = 0
    paths_confirmed: int = 0
    source_maps_found: list[str] = field(default_factory=list)
    websocket_urls: set[str] = field(default_factory=set)


def _is_noise(path: str) -> bool:
    lowered = path.lower()
    if lowered in _NOISE_EXACT or len(path) < 3:
        return True
    if lowered.endswith(_ASSET_EXTENSIONS):
        return True
    if lowered.startswith(_NOISE_PREFIXES):
        return True
    # A hashed build artefact like /a1b2c3d4e5f6 — no vowels, all hex-ish.
    tail = lowered.rsplit("/", 1)[-1]
    if len(tail) >= 12 and re.fullmatch(r"[0-9a-f]+", tail):
        return True
    # Reject anything that looks like a MIME type or header value.
    if lowered.count("/") == 1 and " " in path:
        return True
    return False


def extract_paths(js: str) -> set[str]:
    """Pull candidate server paths out of a JavaScript bundle."""
    found: set[str] = set()
    for match in _PATH_LITERAL_RE.finditer(js):
        found.add(match.group(1))
    for match in _TEMPLATE_PATH_RE.finditer(js):
        # `/api/users/${id}` -> /api/users
        candidate = match.group(1).rstrip("/")
        if candidate:
            found.add(candidate)
    for match in _ABS_CALL_RE.finditer(js):
        path = urlsplit(match.group(1)).path
        if path:
            found.add(path)
    if _GRAPHQL_OP_RE.search(js):
        found.add("/graphql")
    return {p for p in found if not _is_noise(p)}


def extract_websocket_urls(js: str) -> set[str]:
    """Discovery-only: `new WebSocket(...)` literals found in a bundle."""
    return {match.group(1) for match in _WEBSOCKET_CALL_RE.finditer(js)}


def _rank(path: str) -> tuple[int, int]:
    """Sort key: interesting API-ish paths first, then shorter paths."""
    return (0 if _INTERESTING_RE.match(path) else 1, len(path))


async def analyze_bundles(
    fetcher: Fetcher,
    scope: TargetScope,
    script_urls: set[str],
    not_found: NotFoundProfile,
) -> JsAnalysisResult:
    """Fetch the page's bundles, mine them for endpoints, and verify each one."""
    result = JsAnalysisResult()
    if not script_urls:
        return result

    # Prefer same-origin bundles, largest-looking names last (hashed chunks are
    # usually the app code; vendor chunks are noise but harmless).
    bundles = sorted(script_urls)[:MAX_BUNDLES]
    fetched = await fetcher.fetch_many(bundles)

    candidate_paths: set[str] = set()
    map_urls: list[str] = []

    for res in fetched:
        if not res.ok or res.status_code != 200:
            continue
        body = res.text
        if not body:
            continue
        result.bundles_analyzed += 1
        candidate_paths |= extract_paths(body)
        result.websocket_urls |= extract_websocket_urls(body)

        match = _SOURCE_MAP_RE.search(body[-2048:] or body)
        if match:
            ref = match.group(1).strip()
            if not ref.startswith("data:"):
                map_urls.append(urljoin(res.url, ref))

    result.paths_extracted = len(candidate_paths)

    # --- Source maps -------------------------------------------------------
    if map_urls:
        result.findings += await _check_source_maps(fetcher, map_urls[:MAX_SOURCE_MAPS], result)

    # --- Verify extracted paths -------------------------------------------
    ordered = sorted(candidate_paths, key=_rank)[:MAX_PATH_PROBES]
    if not ordered:
        return result

    probe_urls = [urljoin(scope.origin + "/", p.lstrip("/")) for p in ordered]
    probes = await fetcher.fetch_many(probe_urls)

    for path, res in zip(ordered, probes):
        analyzed = analyze(res)
        # The same SPA-fallback logic used everywhere else: a bundle string is
        # only an endpoint if the server answers it distinctly.
        if not not_found.is_real_hit(analyzed, path):
            continue
        result.paths_confirmed += 1
        result.endpoints.append(
            DiscoveredPath(
                url=res.url,
                status_code=res.status_code,
                content_type=res.content_type,
                response_size=res.body_bytes,
                source="js_bundle",
                discovery_method="js_bundle",
            )
        )

    return result


async def _check_source_maps(
    fetcher: Fetcher, map_urls: list[str], result: JsAnalysisResult
) -> list[FindingCandidate]:
    """A reachable .map in production exposes the original source tree."""
    findings: list[FindingCandidate] = []
    results = await fetcher.fetch_many(map_urls)

    for res in results:
        if not res.ok or res.status_code != 200:
            continue
        try:
            doc = json.loads(res.text)
        except (ValueError, TypeError):
            continue
        if not isinstance(doc, dict):
            continue
        sources = doc.get("sources")
        if not isinstance(sources, list) or not sources:
            continue

        # Ignore maps that only reference third-party code.
        own = [
            str(s) for s in sources
            if isinstance(s, str) and "node_modules" not in s
        ]
        if not own:
            continue

        result.source_maps_found.append(res.url)
        has_content = bool(doc.get("sourcesContent"))
        sample = ", ".join(s.lstrip("./") for s in own[:8])

        findings.append(
            FindingCandidate(
                title="Source map exposed in production",
                category="information_exposure",
                severity="medium" if has_content else "low",
                confidence="confirmed",
                url=res.url,
                evidence=(
                    f"{len(own)} original source files referenced"
                    + (" with full source content embedded" if has_content else "")
                    + f". Sample: {sample}"
                ),
                response_summary=f"HTTP 200, {res.body_bytes} bytes of source map",
                description=(
                    "A JavaScript source map is publicly readable. Source maps "
                    "reveal the application's original file and directory "
                    "structure, and when sourcesContent is present they contain "
                    "the unminified source code itself."
                ),
                impact=(
                    "An attacker can read the original source, revealing internal "
                    "API routes, client-side logic, and occasionally credentials "
                    "or keys left in the code — removing most of the effort of "
                    "reverse-engineering the application."
                ),
                remediation=(
                    "Disable source map generation for production builds, or stop "
                    "publishing .map files to the web root. If they are needed for "
                    "error reporting, upload them directly to the error tracker "
                    "instead of serving them."
                ),
                dedup_key=f"source_map|{urlsplit(res.url).path}",
            )
        )

    return findings
