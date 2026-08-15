"""
Attack-surface graph — URL normalization, de-duplication, priority scoring,
and a parent/child graph of everything discovered during a scan.

The crawler discovers URLs from many places (links, forms, XHR/fetch, JS
bundles, API discovery). This module turns that stream into a single directed
graph: each node is a distinct endpoint (de-duplicated by *shape*, so
``/users/1`` and ``/users/2`` collapse to one ``/users/{id}`` node), each edge
records which page/interaction discovered which child, and every node carries
an attack-surface **priority score** so the crawler can explore the richest
endpoints first and the report can rank them.

Everything here is pure (no I/O, no browser), so it is fully unit-testable and
shared by both the browser crawler (which builds the live graph as it explores)
and the deep-scan orchestrator (which folds in endpoints found by the other
discovery sources).
"""
from __future__ import annotations

import re
from urllib.parse import parse_qs, parse_qsl, urlencode, urlsplit, urlunsplit

# Query params that never identify a distinct resource — dropped before dedup.
_TRACKING = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "gclid", "fbclid", "msclkid", "mc_cid", "mc_eid", "ref", "ref_src", "_ga",
}

# A path segment that is really an identifier, not a route name — collapsed to
# ``{id}`` for the dedup key so per-record pages don't explode the graph.
_ID_SEGMENT = re.compile(
    r"^(?:\d+"                                            # numeric id
    r"|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"  # uuid
    r"|[0-9a-fA-F]{16,}"                                  # long hex / hash
    r"|[A-Za-z0-9_-]{22,})$"                              # long opaque token/slug
)

# Route/segment keywords that mark an attack-surface-rich endpoint.
_HIGH_VALUE = {
    "admin", "api", "graphql", "gql", "upload", "uploads", "login", "logout",
    "register", "signup", "signin", "auth", "oauth", "account", "accounts",
    "user", "users", "profile", "config", "settings", "debug", "token",
    "tokens", "search", "query", "file", "files", "download", "export",
    "import", "password", "passwd", "secret", "key", "keys", "session",
    "checkout", "cart", "order", "orders", "payment", "invoice", "report",
}

_API_HINT = re.compile(r"(^|/)(api|v\d+|graphql|gql|rest|rpc)(/|$)|\.json($|\?)", re.IGNORECASE)


def looks_like_api(path_or_url: str) -> bool:
    return bool(_API_HINT.search(path_or_url or ""))


def normalize_url(url: str) -> str:
    """Canonical, fetchable URL: lowercase scheme/host, no fragment, no default
    port, collapsed slashes, no trailing slash (except root), tracking params
    dropped, remaining query sorted. Keeps real values (so the URL still
    works)."""
    try:
        parts = urlsplit(url.strip())
    except Exception:
        return url
    scheme = (parts.scheme or "http").lower()
    host = (parts.hostname or "").lower()
    netloc = host
    if parts.port and not (
        (scheme == "http" and parts.port == 80) or (scheme == "https" and parts.port == 443)
    ):
        netloc = f"{host}:{parts.port}"
    path = re.sub(r"/{2,}", "/", parts.path or "/")
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    pairs = [
        (k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
        if k.lower() not in _TRACKING
    ]
    pairs.sort()
    return urlunsplit((scheme, netloc, path or "/", urlencode(pairs), ""))


def dedup_key(url: str) -> str:
    """Shape key: identifier path segments -> ``{id}``, query reduced to sorted
    parameter *names*. ``/users/1?x=9`` and ``/users/2?x=3`` share one key."""
    parts = urlsplit(normalize_url(url))
    segs = ["{id}" if _ID_SEGMENT.match(s) else s for s in parts.path.split("/")]
    names = ",".join(sorted(parse_qs(parts.query, keep_blank_values=True).keys()))
    shape_path = "/".join(segs) or "/"
    return f"{parts.netloc}{shape_path}?{names}"


def url_priority(
    url: str,
    *,
    param_count: int = 0,
    is_form: bool = False,
    is_api: bool = False,
    depth: int = 0,
) -> int:
    """Attack-surface richness score for exploration ordering. Higher = probe
    sooner. Rewards parameters, API/form endpoints, and high-value route
    keywords; lightly penalises depth."""
    parts = urlsplit(url if "//" in url else f"http://x{url if url.startswith('/') else '/' + url}")
    score = 10
    score += min(param_count, 6) * 8
    if is_api or looks_like_api(parts.path):
        score += 25
    if is_form:
        score += 15
    for seg in (s for s in parts.path.lower().split("/") if s):
        base = re.sub(r"[^a-z0-9]", "", seg)
        if base in _HIGH_VALUE:
            score += 12
    if parse_qs(parts.query):
        score += 10
    score -= max(0, depth) * 3
    return max(score, 0)


def _short_label(node: dict) -> str:
    if node.get("synthetic"):
        return node.get("label", node.get("path", ""))
    methods = "/".join(node.get("methods") or []) or "GET"
    path = node.get("path") or "/"
    return f"{methods} {path}"


class GraphBuilder:
    """Accumulates de-duplicated nodes and parent->child edges."""

    def __init__(self) -> None:
        self.nodes: dict[str, dict] = {}
        self.edges: list[dict] = []
        self._edge_seen: set[tuple] = set()

    def add_synthetic(self, node_id: str, label: str) -> str:
        """A grouping/root node that is not itself an endpoint."""
        if node_id not in self.nodes:
            self.nodes[node_id] = {
                "id": node_id, "url": "", "path": label, "label": label,
                "depth": 0, "discovery": "group", "methods": [], "params": [],
                "param_count": 0, "is_api": False, "is_form": False, "score": 0,
                "synthetic": True,
            }
        return node_id

    def add_node(
        self,
        url: str,
        *,
        depth: int = 0,
        discovery: str = "",
        method: str = "GET",
        params: list[str] | None = None,
        is_api: bool = False,
        is_form: bool = False,
    ) -> str:
        nid = dedup_key(url)
        params = sorted({p for p in (params or []) if p})
        node = self.nodes.get(nid)
        if node is None:
            node = {
                "id": nid,
                "url": normalize_url(url),
                "path": urlsplit(normalize_url(url)).path or "/",
                "depth": depth,
                "discovery": discovery,
                "methods": [method] if method else [],
                "params": params,
                "param_count": len(params),
                "is_api": is_api or looks_like_api(url),
                "is_form": is_form,
            }
            node["score"] = url_priority(
                node["url"], param_count=node["param_count"],
                is_form=node["is_form"], is_api=node["is_api"], depth=depth,
            )
            node["label"] = _short_label(node)
            self.nodes[nid] = node
            return nid
        # Merge into the existing node.
        if method and method not in node["methods"]:
            node["methods"].append(method)
        if params:
            merged = sorted(set(node["params"]) | set(params))
            node["params"], node["param_count"] = merged, len(merged)
        node["is_api"] = node["is_api"] or is_api or looks_like_api(url)
        node["is_form"] = node["is_form"] or is_form
        if depth:
            node["depth"] = min(node["depth"], depth) if node["depth"] else depth
        if discovery and not node.get("discovery"):
            node["discovery"] = discovery
        node["score"] = url_priority(
            node["url"], param_count=node["param_count"],
            is_form=node["is_form"], is_api=node["is_api"], depth=node["depth"],
        )
        node["label"] = _short_label(node)
        return nid

    def add_edge(self, parent: str, child_id: str, via: str = "") -> None:
        """`parent` may be a URL or an existing node id (synthetic or real)."""
        pid = parent if parent in self.nodes else dedup_key(parent)
        if pid == child_id:
            return
        key = (pid, child_id, via)
        if key in self._edge_seen:
            return
        self._edge_seen.add(key)
        self.edges.append({"parent": pid, "child": child_id, "via": via})

    def to_dict(self, roots: list[str]) -> dict:
        return {
            "nodes": list(self.nodes.values()),
            "edges": self.edges,
            "roots": [r for r in roots if r in self.nodes],
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
        }


_BUCKET_LABELS = {
    "api": "API endpoints", "api_discovery": "API endpoints",
    "js_bundle": "JS-mined endpoints", "browser_network": "Network-observed",
    "page": "Pages", "form": "Forms", "redirect": "Redirects",
    "upload": "Upload endpoints", "directory_scan": "Directory scan",
    "crawler": "Static crawl",
}


def build_attack_graph(origin: str, browser_graph: dict | None, endpoints: list[dict]) -> dict:
    """Fold the browser crawl's live parent/child graph together with every
    endpoint the other discovery sources found into one attack-surface graph.

    ``endpoints`` is a list of ``{url, method, discovery, params, is_api,
    is_form}`` dicts (built by the orchestrator from the inventory). Endpoints
    the browser already placed keep their real parent; the rest are attached
    under a per-discovery-method grouping node beneath the root, so every
    endpoint appears with a sensible parent.
    """
    gb = GraphBuilder()
    if browser_graph:
        for n in browser_graph.get("nodes", []):
            gb.nodes[n["id"]] = dict(n)
        for e in browser_graph.get("edges", []):
            gb.edges.append(dict(e))
            gb._edge_seen.add((e.get("parent"), e.get("child"), e.get("via", "")))

    root_id = gb.add_node(origin, depth=0, discovery="seed", method="GET")
    for br_root in (browser_graph or {}).get("roots", []):
        if br_root != root_id:
            gb.add_edge(root_id, br_root, "seed")

    have_parent = {e["child"] for e in gb.edges}

    def _bucket(discovery: str) -> str:
        bid = f"__bucket__:{discovery or 'discovery'}"
        if bid not in gb.nodes:
            gb.add_synthetic(bid, _BUCKET_LABELS.get(discovery, "Discovered"))
            gb.add_edge(root_id, bid, "group")
        return bid

    for ep in endpoints:
        cid = gb.add_node(
            ep["url"], discovery=ep.get("discovery") or "discovery",
            method=ep.get("method", "GET"), params=ep.get("params"),
            is_api=ep.get("is_api", False), is_form=ep.get("is_form", False),
        )
        if cid != root_id and cid not in have_parent:
            gb.add_edge(_bucket(ep.get("discovery") or "discovery"), cid, "discovery")
            have_parent.add(cid)

    return gb.to_dict([root_id])


def merge_graphs(*graphs: dict) -> dict:
    """Union several graph dicts into one (nodes de-duplicated by id, edges by
    parent/child/via). Roots are the union of all roots."""
    gb = GraphBuilder()
    roots: list[str] = []
    for g in graphs:
        if not g:
            continue
        for n in g.get("nodes", []):
            if n["id"] not in gb.nodes:
                gb.nodes[n["id"]] = dict(n)
        for e in g.get("edges", []):
            key = (e.get("parent"), e.get("child"), e.get("via", ""))
            if key not in gb._edge_seen:
                gb._edge_seen.add(key)
                gb.edges.append(dict(e))
        for r in g.get("roots", []):
            if r not in roots:
                roots.append(r)
    return gb.to_dict(roots)


def graph_stats(graph: dict) -> dict:
    """Discovery counts for a graph (real endpoints only, buckets excluded)."""
    real = [n for n in graph.get("nodes", []) if not n.get("synthetic")]
    apis = sum(1 for n in real if n.get("is_api"))
    forms = sum(1 for n in real if n.get("is_form"))
    params = sum(int(n.get("param_count", 0)) for n in real)
    max_depth = max((int(n.get("depth", 0)) for n in real), default=0)
    avg_score = round(sum(int(n.get("score", 0)) for n in real) / len(real), 1) if real else 0.0
    high_value = sum(1 for n in real if int(n.get("score", 0)) >= 40)
    return {
        "endpoints": len(real),
        "apis": apis,
        "forms": forms,
        "params": params,
        "max_depth": max_depth,
        "avg_score": avg_score,
        "high_value": high_value,
        "edges": graph.get("edge_count", len(graph.get("edges", []))),
    }


def crawl_score(stats: dict, *, interactions: int = 0) -> int:
    """A single 0–100 discovery-richness score for a crawl strategy — how much
    attack surface it uncovered. Heuristic, comparable across strategies."""
    raw = (
        stats.get("endpoints", 0) * 2
        + stats.get("apis", 0) * 5
        + stats.get("forms", 0) * 4
        + stats.get("params", 0) * 1
        + stats.get("high_value", 0) * 3
        + stats.get("max_depth", 0) * 3
        + interactions * 2
    )
    return min(100, raw)


def to_dot(graph: dict) -> str:
    """Render a graph dict (nodes/edges) as Graphviz DOT."""
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    index = {n["id"]: i for i, n in enumerate(nodes)}

    def esc(text: str) -> str:
        return (text or "").replace("\\", "\\\\").replace('"', '\\"')

    lines = ["digraph attack_surface {", '  rankdir=LR;',
             '  node [shape=box, style=rounded, fontname="Helvetica", fontsize=10];']
    for n in nodes:
        label = esc(n.get("label") or n.get("path") or n["id"])
        if n.get("synthetic"):
            lines.append(f'  n{index[n["id"]]} [label="{label}", style="rounded,filled", fillcolor="#eee"];')
        else:
            score = n.get("score", 0)
            extra = f"\\nscore={score}" + (f" · {n['param_count']}p" if n.get("param_count") else "")
            lines.append(f'  n{index[n["id"]]} [label="{label}{esc(extra)}"];')
    for e in edges:
        p, c = e.get("parent"), e.get("child")
        if p in index and c in index:
            via = esc(e.get("via", ""))
            lbl = f' [label="{via}", fontsize=8]' if via else ""
            lines.append(f"  n{index[p]} -> n{index[c]}{lbl};")
    lines.append("}")
    return "\n".join(lines)
