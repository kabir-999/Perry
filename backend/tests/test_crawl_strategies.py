"""BFS frontier behaviour + graph merge/stats/score.

A second, DFS/LIFO-stack strategy used to live alongside BFS here, run as a
full second browser crawl for a BFS-vs-DFS comparison — removed entirely
(see browser_crawler.py's _Frontier docstring): on a memory-constrained
instance, a second full Chromium cycle was pure cost for little unique
coverage BFS's priority ordering didn't already mostly cover.
"""
from app.services import attack_graph as G
from app.services.browser_crawler import _Frontier


def test_frontier_pops_highest_priority_first():
    f = _Frontier()
    f.push(5, 1, "a", 0)
    f.push(20, 2, "b", 0)
    f.push(10, 3, "c", 0)
    order = [f.pop()[1] for _ in range(3)]
    assert order == ["b", "c", "a"]  # by score, high -> low


def test_frontier_truthiness():
    f = _Frontier()
    assert not f
    f.push(1, 1, "x", 0)
    assert f


def _graph(*urls):
    gb = G.GraphBuilder()
    root = gb.add_node("https://x.com/", discovery="seed")
    for u in urls:
        cid = gb.add_node(u, method="GET",
                          params=list(__import__("urllib.parse", fromlist=["parse_qs"]).parse_qs(u.split("?", 1)[1]).keys()) if "?" in u else None,
                          is_api=G.looks_like_api(u), is_form=u.endswith("/submit"))
        gb.add_edge(root, cid, "link")
    return gb.to_dict([root])


def test_merge_graphs_dedups_across_strategies():
    g1 = _graph("https://x.com/a", "https://x.com/api/x")
    g2 = _graph("https://x.com/a", "https://x.com/b")  # /a overlaps
    merged = G.merge_graphs(g1, g2)
    ids = {n["id"] for n in merged["nodes"]}
    # root + a + api/x + b = 4 unique
    assert len(ids) == 4
    assert merged["node_count"] == 4


def test_graph_stats_and_crawl_score():
    g = _graph("https://x.com/search?q=1", "https://x.com/api/orders", "https://x.com/submit")
    stats = G.graph_stats(g)
    assert stats["endpoints"] == 4  # root + 3
    assert stats["apis"] >= 1
    assert stats["forms"] >= 1
    assert stats["params"] >= 1
    score = G.crawl_score(stats, interactions=3)
    assert 0 < score <= 100


def test_crawl_score_rewards_more_surface():
    small = G.crawl_score(G.graph_stats(_graph("https://x.com/a")))
    big = G.crawl_score(
        G.graph_stats(_graph("https://x.com/api/a", "https://x.com/api/b",
                             "https://x.com/s?q=1", "https://x.com/submit")),
        interactions=5,
    )
    assert big > small
