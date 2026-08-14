"""
Real-browser (Playwright/Chromium) crawler for JS-rendered SPAs.

Additive to, never a replacement for, the static `crawler.py`: a
BeautifulSoup parse of the raw HTML response sees nothing an
Angular/React/Vue app injects into the DOM after load, and never sees a
request the app's own JS code issues client-side (fetch/XHR/axios/
Angular HttpClient) — the app's actual API surface. This module drives a
real headless browser so Sentinel sees what the application actually is,
not just what the server's first response contained.

Graceful degradation: if Playwright or Chromium isn't installed,
`browser_crawl` returns an empty `BrowserCrawlResult` with an entry in
`.errors` instead of raising — callers (deep_scan.py) must treat this as
"browser crawling unavailable this run", never a hard failure.
"""
from __future__ import annotations

import json
from urllib.parse import parse_qs, urldefrag, urljoin, urlsplit, urlunsplit

from app.config import settings
from app.services.debug_log import debug_log
from app.services.discovery_types import (
    BrowserCrawlResult,
    DiscoveredForm,
    DiscoveredNetworkRequest,
    DiscoveredParam,
    DiscoveredPath,
)
from app.services.scope import TargetScope

try:
    from playwright.async_api import async_playwright
    _PLAYWRIGHT_AVAILABLE = True
except Exception:  # pragma: no cover - exercised only when not installed
    _PLAYWRIGHT_AVAILABLE = False


def _canonical(url: str) -> str:
    url, _ = urldefrag(url)
    parts = urlsplit(url)
    path = parts.path or "/"
    return urlunsplit((parts.scheme, parts.netloc, path, parts.query, ""))


def _dedup_path(url: str) -> str:
    parts = urlsplit(url)
    names = ",".join(sorted(parse_qs(parts.query).keys()))
    return f"{parts.netloc}{parts.path}?{names}"


# A SPA route (React Router / Vue Router / etc.) is very often a <button> or
# a <a> with no real href, wired to a client-side navigate() call — a plain
# a[href] scrape never sees it, so its page (and whatever API calls that
# page's JS fires) stays permanently undiscovered. Clicking every interactive
# element surfaces those routes at the cost of also triggering whatever
# on-click side effect a "real" action button has (submit, logout, delete) —
# an accepted tradeoff for maximizing discovery, matching how the 12 attack
# modules themselves already only run against a verified/authorized target.
_CLICKABLE_SELECTOR = (
    "a, button, [role='button'], input[type='button'], "
    "input[type='submit'], [onclick]"
)


async def browser_crawl(
    scope: TargetScope,
    seed_url: str,
    *,
    max_pages: int | None = None,
    max_depth: int | None = None,
    auth_header: dict[str, str] | None = None,
) -> BrowserCrawlResult:
    """Crawl `seed_url` with a real headless browser, capturing every
    network request the page's own JS makes along the way. Returns an
    empty (but never-None) result with `.errors` populated if Playwright/
    Chromium isn't available — callers must not assume this raises."""
    result = BrowserCrawlResult()

    if not _PLAYWRIGHT_AVAILABLE:
        msg = "Playwright not installed - browser crawling skipped, falling back to static crawler only."
        result.errors.append(msg)
        debug_log("BROWSER", msg)
        return result

    max_pages = max_pages or settings.BROWSER_CRAWL_MAX_PAGES
    max_depth = max_depth if max_depth is not None else settings.BROWSER_CRAWL_MAX_DEPTH
    nav_timeout_ms = settings.BROWSER_NAV_TIMEOUT_SECONDS * 1000
    idle_timeout_ms = settings.BROWSER_NETWORK_IDLE_TIMEOUT_SECONDS * 1000

    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            try:
                context = await browser.new_context(
                    user_agent=settings.SCANNER_USER_AGENT,
                    ignore_https_errors=True,
                )
                if auth_header:
                    await context.set_extra_http_headers(auth_header)

                page = await context.new_page()
                requests_seen = 0
                seen_shapes: set[str] = set()
                visited: set[str] = set()

                def _on_request(req):
                    nonlocal requests_seen
                    if requests_seen >= settings.BROWSER_MAX_REQUESTS:
                        return
                    try:
                        parts = urlsplit(req.url)
                    except Exception:
                        return
                    if req.resource_type == "websocket" or req.url.startswith(("ws://", "wss://")):
                        result.websocket_urls.add(req.url)
                    net_req = DiscoveredNetworkRequest(
                        method=req.method,
                        url=req.url,
                        origin=f"{parts.scheme}://{parts.netloc}",
                        path=parts.path,
                        query={k: v[0] for k, v in parse_qs(parts.query).items()},
                        headers=dict(req.headers),
                        body=(req.post_data or "") if req.method in ("POST", "PUT", "PATCH") else "",
                        content_type=req.headers.get("content-type", ""),
                        resource_type=req.resource_type,
                        source_page=page.url,
                        is_authenticated=bool(auth_header),
                    )
                    requests_seen += 1
                    result.network_requests.append(net_req)
                    debug_log("NETWORK", f"{net_req.method} {net_req.url} ({net_req.resource_type})")

                def _on_response(res):
                    try:
                        parts = urlsplit(res.url)
                    except Exception:
                        return
                    key = f"{res.request.method.upper()}:{parts.netloc.lower()}{parts.path.rstrip('/')}"
                    for net_req in reversed(result.network_requests):
                        if net_req.key() == key and net_req.response_status is None:
                            net_req.response_status = res.status
                            net_req.response_headers = dict(res.headers)
                            net_req.response_content_type = res.headers.get("content-type", "")
                            break

                page.on("request", _on_request)
                page.on("response", _on_response)

                seed = _canonical(seed_url)
                frontier = [(seed, 0)]
                visited.add(seed)
                seen_shapes.add(_dedup_path(seed))

                while frontier and len(result.pages) < max_pages:
                    url, depth = frontier.pop(0)
                    if depth > max_depth:
                        continue
                    if requests_seen >= settings.BROWSER_MAX_REQUESTS:
                        debug_log("BROWSER", "Request budget exhausted, stopping crawl.")
                        break
                    try:
                        debug_log("CRAWLER", f"Navigating to {url} (depth={depth})")
                        resp = await page.goto(url, timeout=nav_timeout_ms, wait_until="domcontentloaded")
                        try:
                            await page.wait_for_load_state("networkidle", timeout=idle_timeout_ms)
                        except Exception:
                            pass
                    except Exception as exc:
                        result.errors.append(f"Navigation failed for {url}: {exc}")
                        debug_log("BROWSER", f"Navigation failed for {url}: {exc}")
                        continue

                    result.pages_rendered += 1
                    result.pages.append(
                        DiscoveredPath(
                            url=url,
                            status_code=resp.status if resp else None,
                            content_type=(resp.headers.get("content-type", "") if resp else ""),
                            source="browser_crawler",
                            discovery_method="browser_crawler",
                        )
                    )
                    if depth > 0 or url != seed:
                        result.spa_routes.add(url)

                    await _extract_dom(page, url, scope, result, frontier, visited, seen_shapes, depth, max_depth)
                    await _click_and_discover(
                        page, url, scope, result, frontier, visited, seen_shapes,
                        depth, max_depth, nav_timeout_ms, idle_timeout_ms,
                    )

            finally:
                await browser.close()
    except Exception as exc:  # pragma: no cover - defensive: never crash the scan
        result.errors.append(f"Browser crawl failed: {exc}")
        debug_log("BROWSER", f"Browser crawl failed: {exc}")

    debug_log(
        "BROWSER",
        f"Done: {len(result.pages)} pages rendered, "
        f"{len(result.network_requests)} network requests captured, "
        f"{len(result.spa_routes)} SPA routes.",
    )
    return result


async def _click_and_discover(
    page, base_url, scope, result, frontier, visited, seen_shapes, depth, max_depth,
    nav_timeout_ms, idle_timeout_ms,
):
    """Click every interactive element on the page to surface SPA routes
    that only exist behind a JS navigate() call, never a real ``<a href>``.

    Re-queries the element list by index on every iteration (a click can
    re-render the DOM and invalidate prior handles) and restores ``base_url``
    between clicks so each one starts from the same state. Best-effort only:
    an element that no longer matches its index, a click that times out, or a
    navigation that fails is skipped rather than aborting the rest.
    """
    if depth + 1 > max_depth:
        return
    try:
        count = await page.eval_on_selector_all(_CLICKABLE_SELECTOR, "els => els.length")
    except Exception:
        return

    budget = min(count, settings.BROWSER_CLICK_BUDGET_PER_PAGE)
    for i in range(budget):
        try:
            elements = await page.query_selector_all(_CLICKABLE_SELECTOR)
            if i >= len(elements):
                break
            el = elements[i]
            if not await el.is_visible():
                continue
            await el.click(timeout=1500)
        except Exception:
            continue

        try:
            await page.wait_for_load_state("networkidle", timeout=idle_timeout_ms)
        except Exception:
            pass

        try:
            new_url = _canonical(page.url)
        except Exception:
            new_url = base_url

        if new_url != base_url and scope.in_scope(new_url):
            shape = _dedup_path(new_url)
            if new_url not in visited and shape not in seen_shapes:
                visited.add(new_url)
                seen_shapes.add(shape)
                frontier.append((new_url, depth + 1))
                debug_log("CRAWLER", f"SPA route discovered via click: {new_url}")

        if page.url != base_url:
            try:
                await page.goto(base_url, timeout=nav_timeout_ms, wait_until="domcontentloaded")
                await page.wait_for_load_state("networkidle", timeout=idle_timeout_ms)
            except Exception:
                # base_url no longer loads (e.g. the click logged the session
                # out) — stop clicking on this page rather than clicking
                # blind against an unknown state.
                break


async def _extract_dom(page, base_url, scope, result, frontier, visited, seen_shapes, depth, max_depth):
    try:
        links = await page.eval_on_selector_all(
            "a[href]", "els => els.map(e => e.getAttribute('href'))"
        )
    except Exception:
        links = []

    for raw in links:
        raw = (raw or "").strip()
        if not raw or raw.startswith(("javascript:", "mailto:", "tel:", "#")):
            continue
        try:
            absolute = _canonical(urljoin(base_url, raw))
        except Exception:
            continue
        if not absolute.startswith(("http://", "https://")):
            continue
        if not scope.in_scope(absolute):
            continue
        shape = _dedup_path(absolute)
        if absolute in visited or shape in seen_shapes:
            continue
        if depth + 1 > max_depth:
            continue
        visited.add(absolute)
        seen_shapes.add(shape)
        frontier.append((absolute, depth + 1))
        debug_log("CRAWLER", f"SPA route discovered: {absolute}")

    try:
        scripts = await page.eval_on_selector_all(
            "script[src]", "els => els.map(e => e.getAttribute('src'))"
        )
    except Exception:
        scripts = []
    for raw in scripts:
        raw = (raw or "").strip()
        if not raw:
            continue
        try:
            absolute = _canonical(urljoin(base_url, raw))
        except Exception:
            continue
        if absolute.startswith(("http://", "https://")) and scope.in_scope(absolute):
            result.js_bundle_urls.add(absolute)

    try:
        forms_data = await page.evaluate(
            """() => Array.from(document.querySelectorAll('form')).map(f => ({
                action: f.getAttribute('action') || '',
                method: (f.getAttribute('method') || 'GET').toUpperCase(),
                enctype: (f.getAttribute('enctype') || '').toLowerCase(),
                fields: Array.from(f.querySelectorAll('input,textarea,select')).map(el => ({
                    name: el.getAttribute('name') || '',
                    type: (el.getAttribute('type') || '').toLowerCase(),
                })),
            }))"""
        )
    except Exception:
        forms_data = []

    for form in forms_data or []:
        action = urljoin(base_url, form.get("action") or base_url)
        if not scope.in_scope(action):
            continue
        method = form.get("method") or "GET"
        enctype = form.get("enctype") or "application/x-www-form-urlencoded"
        has_upload = enctype == "multipart/form-data"
        names = []
        for field in form.get("fields", []):
            name = field.get("name")
            if field.get("type") == "file":
                has_upload = True
            if name:
                names.append(name)
        result.forms.append(
            DiscoveredForm(url=action, method=method, params=names, has_upload=has_upload)
        )
        for name in names:
            result.params.append(
                DiscoveredParam(url=action, name=name, param_type="form", method=method)
            )
