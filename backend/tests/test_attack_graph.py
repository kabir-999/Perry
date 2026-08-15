"""Attack-surface graph: normalization, dedup, priority, and assembly."""
from app.services import attack_graph as G


def test_normalize_url_canonicalizes():
    assert G.normalize_url("HTTP://Example.com:80/a/b/") == "http://example.com/a/b"
    assert G.normalize_url("https://x.com/p?b=2&a=1") == "https://x.com/p?a=1&b=2"
    # tracking params dropped
    assert "utm_source" not in G.normalize_url("https://x.com/p?utm_source=g&id=5")
    assert "id=5" in G.normalize_url("https://x.com/p?utm_source=g&id=5")


def test_dedup_key_collapses_ids():
    a = G.dedup_key("https://x.com/users/1?x=9")
    b = G.dedup_key("https://x.com/users/2?x=3")
    assert a == b  # /users/{id}?x
    # uuid + long hex also collapse
    c = G.dedup_key("https://x.com/o/550e8400-e29b-41d4-a716-446655440000")
    d = G.dedup_key("https://x.com/o/550e8400-e29b-41d4-a716-446655440999")
    assert c == d
    # distinct routes stay distinct
    assert G.dedup_key("https://x.com/a") != G.dedup_key("https://x.com/b")


def test_priority_rewards_attack_surface():
    plain = G.url_priority("https://x.com/about")
    api = G.url_priority("https://x.com/api/v1/users", is_api=True)
    param = G.url_priority("https://x.com/search?q=1", param_count=1)
    admin = G.url_priority("https://x.com/admin/login")
    assert api > plain
    assert param > plain
    assert admin > plain


def test_graph_builder_dedups_nodes_and_edges():
    gb = G.GraphBuilder()
    root = gb.add_node("https://x.com/", discovery="seed")
    c1 = gb.add_node("https://x.com/users/1", method="GET")
    c2 = gb.add_node("https://x.com/users/2", method="GET")  # same shape -> same node
    assert c1 == c2
    gb.add_edge(root, c1, "link")
    gb.add_edge(root, c1, "link")  # duplicate edge suppressed
    d = gb.to_dict([root])
    assert d["node_count"] == 2
    assert d["edge_count"] == 1


def test_build_attack_graph_attaches_orphans_to_buckets():
    browser_graph = {
        "nodes": [
            {"id": G.dedup_key("https://x.com/"), "url": "https://x.com/", "path": "/",
             "label": "GET /", "depth": 0, "discovery": "seed", "methods": ["GET"],
             "params": [], "param_count": 0, "is_api": False, "is_form": False, "score": 10},
            {"id": G.dedup_key("https://x.com/dashboard"), "url": "https://x.com/dashboard",
             "path": "/dashboard", "label": "GET /dashboard", "depth": 1, "discovery": "link",
             "methods": ["GET"], "params": [], "param_count": 0, "is_api": False,
             "is_form": False, "score": 7},
        ],
        "edges": [{"parent": G.dedup_key("https://x.com/"),
                   "child": G.dedup_key("https://x.com/dashboard"), "via": "link"}],
        "roots": [G.dedup_key("https://x.com/")],
    }
    endpoints = [
        # already in the browser graph -> keeps its real parent
        {"url": "https://x.com/dashboard", "method": "GET", "discovery": "page", "params": []},
        # never seen by the browser -> attached to an API bucket under root
        {"url": "https://x.com/api/orders", "method": "GET", "discovery": "api",
         "params": ["status"], "is_api": True},
    ]
    graph = G.build_attack_graph("https://x.com", browser_graph, endpoints)
    ids = {n["id"] for n in graph["nodes"]}
    api_id = G.dedup_key("https://x.com/api/orders")
    assert api_id in ids
    # the orphan API endpoint has a parent (a bucket), i.e. it's reachable
    assert any(e["child"] == api_id for e in graph["edges"])
    # the dashboard keeps exactly its original single parent (the root), not a bucket
    dash_id = G.dedup_key("https://x.com/dashboard")
    dash_parents = [e["parent"] for e in graph["edges"] if e["child"] == dash_id]
    assert dash_parents == [G.dedup_key("https://x.com/")]


def test_to_dot_is_wellformed():
    gb = G.GraphBuilder()
    root = gb.add_node("https://x.com/", discovery="seed")
    child = gb.add_node("https://x.com/api?q=1", method="GET", params=["q"], is_api=True)
    gb.add_edge(root, child, "link")
    dot = G.to_dot(gb.to_dict([root]))
    assert dot.startswith("digraph attack_surface {")
    assert dot.strip().endswith("}")
    assert "->" in dot
