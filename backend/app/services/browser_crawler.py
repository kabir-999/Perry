"""
Interaction-driven, priority-BFS real-browser crawler (Playwright/Chromium).

Additive to, never a replacement for, the static ``crawler.py``. A raw-HTML
parse can't see routes an Angular/React/Vue app injects after load, can't see
content that only appears after a button/menu/tab is clicked, and never sees
the API calls the app's own JS issues. This module drives a real browser to
surface all of that, and builds a parent/child **attack-surface graph** as it
goes.

Strategy (per the design):

    START → BFS (priority frontier) → INTERACT (safe clicks + benign GET form
    submits) → DISCOVER (links / forms / XHR-fetch via network interception) →
    NORMALIZE → DEDUPLICATE → PRIORITIZE → QUEUE → … → FULL ATTACK-SURFACE GRAPH

Key properties:
  * **Priority frontier** — a max-heap ordered by attack-surface richness
    (``attack_graph.url_priority``), so parameter/API/auth-rich endpoints are
    explored first within the page/interaction budget.
  * **Interaction engine (moderate)** — clicks non-destructive, non-submitting
    controls (expanders, tabs, menus, pagination) and submits GET/search forms
    with benign values; **skips** destructive keywords (delete/logout/pay/…)
    and all state-changing POST submits. State is restored after any
    interaction that navigates, so one interaction never corrupts the crawl.
  * **Network interception** — every XHR/fetch/document request the browser
    makes becomes a graph node and (when in scope) a discovered endpoint.
  * **Session persistence** — a single browser context is reused, so cookies /
    the scanner's auth header persist across the whole crawl.
  * **Normalization + dedup** — via ``attack_graph`` (identifier path segments
    collapse to ``{id}``), so ``/users/1`` and ``/users/2`` are one node.
  * **Depth limit + request budget** — bound exploration.

Graceful degradation: if Playwright/Chromium isn't installed, ``browser_crawl``
returns an empty (never-None) result with an ``.errors`` entry, so callers
(deep_scan.py) treat it as "browser crawling unavailable this run".
"""
from __future__ import annotations

import heapq
import re
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit

from app.config import settings
from app.services import attack_graph as G
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

# --- Interaction engine tuning --------------------------------------------
_MAX_CLICKS_PER_PAGE = 8
_MAX_FORMS_PER_PAGE = 4

# Elements safe to click: they toggle/expand/paginate, they don't submit.
_SAFE_CLICK_SELECTOR = ", ".join([
    "button:not([type='submit'])", "[role='button']", "[role='tab']",
    "[role='menuitem']", "summary", "[aria-expanded='false']",
    "[data-toggle]", "[data-bs-toggle]", ".load-more", ".show-more",
    ".pagination a", ".page-link", "[data-testid*='tab']",
])

# Any control whose visible text / label / id / class matches this is left
# alone — clicking it could change or destroy state on the target.
_DESTRUCTIVE = re.compile(
    r"delet|remov|logout|log\s*out|sign\s*out|\bpay\b|\bbuy\b|checkout|purchas|"
    r"\border\b|confirm|deactivat|unsubscrib|\breset\b|cancel|\bdrop\b|destroy|"
    r"withdraw|transfer|archive|ban\b|block\b|revoke|disable",
    re.IGNORECASE,
)

_BENIGN_INPUT = "test"
_LOG_CAP = 800


def _clog(result: BrowserCrawlResult, event: str, **fields) -> None:
    """Append one structured crawl-log record (capped)."""
    if len(result.log) >= _LOG_CAP:
        return
    rec = {
        "seq": len(result.log) + 1,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "event": event,
    }
    rec.update(fields)
    result.log.append(rec)


class _Frontier:
    """The only difference between the two crawl strategies: BFS pops the
    highest-priority pending URL (a max-heap over attack-surface score); DFS
    pops the most-recently-discovered URL (a LIFO stack), diving down a branch
    before backtracking. Both are bounded identically by the shared ``visited``
    set and ``max_depth`` in the caller, so DFS cannot loop or recurse
    forever."""

    def __init__(self, strategy: str) -> None:
        self.strategy = "dfs" if strategy == "dfs" else "bfs"
        self._heap: list[tuple[int, int, str, int]] = []
        self._stack: list[tuple[int, int, str, int]] = []

    def push(self, score: int, seq: int, url: str, depth: int) -> None:
        if self.strategy == "dfs":
            self._stack.append((score, seq, url, depth))
        else:
            heapq.heappush(self._heap, (-score, seq, url, depth))

    def pop(self) -> tuple[int, str, int]:
        if self.strategy == "dfs":
            score, _seq, url, depth = self._stack.pop()
            return score, url, depth
        neg, _seq, url, depth = heapq.heappop(self._heap)
        return -neg, url, depth

    def __bool__(self) -> bool:
        return bool(self._stack or self._heap)


async def browser_crawl(
    scope: TargetScope,
    seed_url: str,
    *,
    strategy: str = "bfs",
    max_pages: int | None = None,
    max_depth: int | None = None,
    auth_header: dict[str, str] | None = None,
) -> BrowserCrawlResult:
    result = BrowserCrawlResult()
    result.strategy = "dfs" if strategy == "dfs" else "bfs"

    if not _PLAYWRIGHT_AVAILABLE:
        msg = "Playwright not installed - browser crawling skipped, falling back to static crawler only."
        result.errors.append(msg)
        debug_log("BROWSER", msg)
        return result

    max_pages = max_pages or settings.BROWSER_CRAWL_MAX_PAGES
    max_depth = max_depth if max_depth is not None else settings.BROWSER_CRAWL_MAX_DEPTH
    nav_timeout_ms = settings.BROWSER_NAV_TIMEOUT_SECONDS * 1000
    idle_timeout_ms = settings.BROWSER_NETWORK_IDLE_TIMEOUT_SECONDS * 1000

    graph = G.GraphBuilder()
    seed_norm = G.normalize_url(seed_url)
    root_id = graph.add_node(seed_norm, depth=0, discovery="seed", method="GET")
    visited: set[str] = {G.dedup_key(seed_norm)}
    # BFS = priority max-heap; DFS = LIFO stack. Same visited/max-depth bounds.
    frontier = _Frontier(result.strategy)
    seq = [0]
    current_page_id = [root_id]

    def _enqueue(url: str, depth: int, parent: str, via: str) -> None:
        """Normalize, add to the graph (always), and push to the frontier if it
        is new, in scope, and within the depth limit."""
        if not url or url.startswith(("javascript:", "mailto:", "tel:", "#")):
            return
        norm = G.normalize_url(url)
        if not norm.startswith(("http://", "https://")):
            return
        if not scope.in_scope(norm):
            return
        is_api = G.looks_like_api(norm)
        has_params = bool(parse_qs(urlsplit(norm).query))
        child_id = graph.add_node(
            norm, depth=depth, discovery=via, method="GET",
            params=list(parse_qs(urlsplit(norm).query).keys()), is_api=is_api,
        )
        graph.add_edge(parent, child_id, via)
        key = G.dedup_key(norm)
        if key in visited or depth > max_depth:
            return
        visited.add(key)
        score = G.url_priority(norm, param_count=1 if has_params else 0, is_api=is_api, depth=depth)
        seq[0] += 1
        frontier.push(score, seq[0], norm, depth)
        _clog(result, "discover", url=norm, depth=depth, via=via, score=score)

    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            try:
                # One context for the whole crawl => cookies / auth persist
                # (session persistence).
                context = await browser.new_context(
                    user_agent=settings.SCANNER_USER_AGENT,
                    ignore_https_errors=True,
                )
                if auth_header:
                    await context.set_extra_http_headers(auth_header)
                page = await context.new_page()
                requests_seen = [0]

                def _on_request(req):
                    if requests_seen[0] >= settings.BROWSER_MAX_REQUESTS:
                        return
                    try:
                        parts = urlsplit(req.url)
                    except Exception:
                        return
                    if req.resource_type == "websocket" or req.url.startswith(("ws://", "wss://")):
                        result.websocket_urls.add(req.url)
                    net_req = DiscoveredNetworkRequest(
                        method=req.method, url=req.url,
                        origin=f"{parts.scheme}://{parts.netloc}", path=parts.path,
                        query={k: v[0] for k, v in parse_qs(parts.query).items()},
                        headers=dict(req.headers),
                        body=(req.post_data or "") if req.method in ("POST", "PUT", "PATCH") else "",
                        content_type=req.headers.get("content-type", ""),
                        resource_type=req.resource_type, source_page=page.url,
                        is_authenticated=bool(auth_header),
                    )
                    requests_seen[0] += 1
                    result.network_requests.append(net_req)
                    # Behavioural discovery -> graph. Only XHR/fetch/document
                    # in scope become endpoint nodes (not images/css/fonts).
                    if req.resource_type in ("xhr", "fetch", "document") and scope.in_scope(req.url):
                        via = "xhr" if req.resource_type in ("xhr", "fetch") else "navigation"
                        child = graph.add_node(
                            req.url, discovery=via, method=req.method,
                            params=list(parse_qs(parts.query).keys()),
                            is_api=req.resource_type in ("xhr", "fetch") or G.looks_like_api(req.url),
                        )
                        graph.add_edge(current_page_id[0], child, via)

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

                # Seed the frontier from the root.
                seq[0] += 1
                frontier.push(0, seq[0], seed_norm, 0)

                while frontier and len(result.pages) < max_pages:
                    if requests_seen[0] >= settings.BROWSER_MAX_REQUESTS:
                        debug_log("BROWSER", "Request budget exhausted, stopping crawl.")
                        break
                    score, url, depth = frontier.pop()
                    page_id = G.dedup_key(url)
                    current_page_id[0] = page_id
                    result.max_depth_reached = max(result.max_depth_reached, depth)
                    try:
                        debug_log("CRAWLER", f"[{result.strategy}] Navigating to {url} (depth={depth}, score={score})")
                        resp = await page.goto(url, timeout=nav_timeout_ms, wait_until="domcontentloaded")
                        try:
                            await page.wait_for_load_state("networkidle", timeout=idle_timeout_ms)
                        except Exception:
                            pass
                    except Exception as exc:
                        result.errors.append(f"Navigation failed for {url}: {exc}")
                        _clog(result, "error", url=url, depth=depth, detail=str(exc)[:200])
                        debug_log("BROWSER", f"Navigation failed for {url}: {exc}")
                        continue

                    _clog(result, "navigate", url=url, depth=depth, score=score,
                          status=resp.status if resp else None)
                    result.pages_rendered += 1
                    result.pages.append(
                        DiscoveredPath(
                            url=url,
                            status_code=resp.status if resp else None,
                            content_type=(resp.headers.get("content-type", "") if resp else ""),
                            source="browser_crawler", discovery_method="browser_crawler",
                        )
                    )
                    graph.add_node(url, depth=depth, discovery="page", method="GET")
                    if depth > 0 or url != seed_norm:
                        result.spa_routes.add(url)

                    # 1) Extract the base DOM first (reliable, before any
                    #    interaction can navigate away).
                    await _extract_dom(page, url, depth, scope, result, graph, _enqueue)
                    # 2) Interact (moderate) to reveal DOM-injected content / XHR;
                    #    injected links are re-extracted after each safe click.
                    await _interact(page, url, depth, scope, result, graph, _enqueue, current_page_id)

            finally:
                await browser.close()
    except Exception as exc:  # pragma: no cover - never crash the scan
        result.errors.append(f"Browser crawl failed: {exc}")
        debug_log("BROWSER", f"Browser crawl failed: {exc}")

    result.graph = graph.to_dict([root_id])
    debug_log(
        "BROWSER",
        f"Done: {result.pages_rendered} pages, {len(result.network_requests)} network requests, "
        f"{result.interactions_performed} interactions, {result.graph.get('node_count', 0)} graph nodes.",
    )
    return result


async def _interact(page, page_url, depth, scope, result, graph, enqueue, current_page_id) -> None:
    """Moderate interaction engine: safe clicks + benign GET form submits.
    Every interaction is wrapped so a failure never breaks the crawl, and any
    interaction that navigates restores the page afterwards (state tracking)."""
    # --- Safe, non-submitting clicks (expanders / tabs / menus / paging) ---
    try:
        handles = await page.query_selector_all(_SAFE_CLICK_SELECTOR)
    except Exception:
        handles = []
    clicks = 0
    for el in handles:
        if clicks >= _MAX_CLICKS_PER_PAGE:
            break
        try:
            label = ((await el.inner_text()) or "")[:80]
            label += " " + (await el.get_attribute("aria-label") or "")
            label += " " + (await el.get_attribute("id") or "")
            label += " " + (await el.get_attribute("class") or "")
            if _DESTRUCTIVE.search(label):
                continue
            if not await el.is_visible():
                continue
            # Skip controls inside a <form> — those are handled by the GET-form
            # pass (POST forms are never auto-submitted). A bare <button> reports
            # DOM .type === "submit" even outside a form, so gate on .form, not
            # on .type, or expanders/menus would be wrongly skipped.
            if await el.evaluate("e => !!e.form"):
                continue
            before = page.url
            await el.click(timeout=2000, no_wait_after=True)
            clicks += 1
            result.interactions_performed += 1
            _clog(result, "interact", url=page_url, depth=depth, detail="click")
            try:
                await page.wait_for_load_state("networkidle", timeout=1500)
            except Exception:
                await page.wait_for_timeout(200)
            if page.url != before:
                # The click navigated: record the new route, then restore.
                enqueue(page.url, depth + 1, G.dedup_key(before), "interaction")
                if not await _restore(page, page_url):
                    break
                current_page_id[0] = G.dedup_key(page_url)
            else:
                # No navigation — the click may have injected new DOM
                # (e.g. an expanded menu). Re-scan links for anything new.
                await _extract_links_only(page, page_url, depth, scope, enqueue)
        except Exception:
            continue

    # --- Benign GET / search form submissions (moderate) ---
    try:
        forms = await page.query_selector_all("form")
    except Exception:
        forms = []
    submitted = 0
    for fh in forms:
        if submitted >= _MAX_FORMS_PER_PAGE:
            break
        try:
            method = ((await fh.get_attribute("method")) or "get").lower()
            if method != "get":
                continue  # never auto-submit state-changing POST forms
            form_label = (await fh.get_attribute("id") or "") + " " + (await fh.get_attribute("class") or "")
            if _DESTRUCTIVE.search(form_label):
                continue
            text_inputs = await fh.query_selector_all(
                "input:not([type]), input[type='text'], input[type='search'], "
                "input[type='email'], input[type='number'], input[type='url'], textarea"
            )
            for ti in text_inputs[:6]:
                try:
                    await ti.fill(_BENIGN_INPUT)
                except Exception:
                    pass
            before = page.url
            submit = await fh.query_selector("[type='submit'], button:not([type])")
            try:
                if submit:
                    await submit.click(timeout=2000, no_wait_after=True)
                else:
                    await fh.evaluate("f => (f.requestSubmit ? f.requestSubmit() : f.submit())")
            except Exception:
                continue
            submitted += 1
            result.interactions_performed += 1
            _clog(result, "interact", url=page_url, depth=depth, detail="form-get submit")
            try:
                await page.wait_for_load_state("networkidle", timeout=2000)
            except Exception:
                await page.wait_for_timeout(300)
            if page.url != before:
                enqueue(page.url, depth + 1, G.dedup_key(page_url), "form-get")
                if not await _restore(page, page_url):
                    break
                current_page_id[0] = G.dedup_key(page_url)
        except Exception:
            continue


async def _restore(page, page_url) -> bool:
    """Return the page to `page_url` after an interaction navigated away, so one
    interaction never corrupts the rest of the crawl. False if it couldn't."""
    try:
        await page.goto(page_url, timeout=8000, wait_until="domcontentloaded")
        return True
    except Exception:
        return False


async def _extract_links_only(page, base_url, depth, scope, enqueue) -> None:
    """Cheap re-scan of <a href> only — used after a non-navigating click that
    may have injected new links into the DOM."""
    try:
        links = await page.eval_on_selector_all(
            "a[href]", "els => els.map(e => e.getAttribute('href'))"
        )
    except Exception:
        return
    page_id = G.dedup_key(base_url)
    for raw in links:
        raw = (raw or "").strip()
        if not raw:
            continue
        try:
            enqueue(_abs(base_url, raw), depth + 1, page_id, "interaction")
        except Exception:
            continue


async def _extract_dom(page, base_url, depth, scope, result, graph, enqueue) -> None:
    page_id = G.dedup_key(base_url)
    # Links
    try:
        links = await page.eval_on_selector_all(
            "a[href]", "els => els.map(e => e.getAttribute('href'))"
        )
    except Exception:
        links = []
    for raw in links:
        raw = (raw or "").strip()
        if not raw:
            continue
        try:
            absolute = _abs(base_url, raw)
        except Exception:
            continue
        enqueue(absolute, depth + 1, page_id, "link")

    # Script bundles (mined later, never crawled as pages).
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
            absolute = _abs(base_url, raw)
        except Exception:
            continue
        if absolute.startswith(("http://", "https://")) and scope.in_scope(absolute):
            result.js_bundle_urls.add(G.normalize_url(absolute))

    # Forms
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
        try:
            action = _abs(base_url, form.get("action") or base_url)
        except Exception:
            continue
        if not scope.in_scope(action):
            continue
        method = form.get("method") or "GET"
        enctype = form.get("enctype") or "application/x-www-form-urlencoded"
        has_upload = enctype == "multipart/form-data"
        names = []
        for fld in form.get("fields", []):
            name = fld.get("name")
            if fld.get("type") == "file":
                has_upload = True
            if name:
                names.append(name)
        result.forms.append(
            DiscoveredForm(url=action, method=method, params=names, has_upload=has_upload)
        )
        child = graph.add_node(
            action, depth=depth + 1, discovery="form", method=method,
            params=names, is_form=True,
        )
        graph.add_edge(page_id, child, "form")
        for name in names:
            result.params.append(
                DiscoveredParam(url=action, name=name, param_type="form", method=method)
            )


def _abs(base_url: str, raw: str) -> str:
    from urllib.parse import urljoin
    return G.normalize_url(urljoin(base_url, raw))
