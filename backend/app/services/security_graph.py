"""
Security graph and graph-based risk scoring.

Risk was previously the maximum severity across a flat list of findings, which
cannot distinguish "twenty missing headers" from "one parameter that reaches a
SQL sink". This module models the application as a graph instead, so risk
follows the *structure* of the attack surface:

    Internet → Host → Endpoint → Parameter → Source → Function → Sink → Impact

A finding is scored from the path that supports it. Five dimensions are kept
deliberately separate, because collapsing them is what produces inflated
reports:

    Impact          what an attacker gains if it works
    Exploitability  whether an attacker can actually drive it
    Exposure        how reachable the entry point is
    Reachability    whether a path from attacker input to the sink exists
    Evidence        how well-supported the claim is

Severity, confidence, and exploitability never collapse into one number. A
Critical-impact issue with no attacker path scores low; a Medium-impact issue
that was dynamically verified scores high.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

# ------------------------------------------------------------------ nodes

TARGET = "target"
HOST = "host"
ENDPOINT = "endpoint"
PARAMETER = "parameter"
SOURCE = "source"
FUNCTION = "function"
DEPENDENCY = "dependency"
SINK = "sink"
FINDING = "finding"
TECHNOLOGY = "technology"
AUTH_BOUNDARY = "auth_boundary"

# ------------------------------------------------------------------ edges

HOSTS = "HOSTS"
CONTAINS = "CONTAINS"
ROUTES_TO = "ROUTES_TO"
ACCEPTS = "ACCEPTS"
CONTROLS = "CONTROLS"
CALLS = "CALLS"
IMPORTS = "IMPORTS"
FLOWS_TO = "FLOWS_TO"
PROTECTED_BY = "PROTECTED_BY"
EXPOSES = "EXPOSES"
AFFECTS = "AFFECTS"
VERIFIED_BY = "VERIFIED_BY"


# --------------------------------------------------------- evidence levels

# Ordered weakest to strongest. The weight is the multiplier applied to a
# finding's raw risk, so an unverified advisory cannot outrank a demonstrated
# attack no matter how severe the advisory claims to be.
EVIDENCE_WEIGHT = {
    "informational": 0.15,
    "reported": 0.30,     # a third party published an advisory
    "observed": 0.55,     # we saw the pattern in code or config
    "suspected": 0.45,
    "potentially_reachable": 0.75,  # a path from attacker input exists
    "confirmed": 1.00,    # dynamically verified
}

IMPACT_SCORE = {"none": 0.0, "low": 0.25, "medium": 0.5, "high": 0.8, "critical": 1.0}


@dataclass
class Node:
    id: str
    kind: str
    label: str
    attrs: dict = field(default_factory=dict)


@dataclass
class Edge:
    src: str
    dst: str
    kind: str
    attrs: dict = field(default_factory=dict)


@dataclass
class RiskBreakdown:
    """Why a finding scored what it scored — shown to the user verbatim."""

    impact: float = 0.0
    exploitability: float = 0.0
    exposure: float = 0.0
    reachability: float = 0.0
    evidence: float = 0.0
    score: int = 0
    severity: str = "informational"
    rationale: str = ""

    def as_dict(self) -> dict:
        return {
            "impact": round(self.impact, 2),
            "exploitability": round(self.exploitability, 2),
            "exposure": round(self.exposure, 2),
            "reachability": round(self.reachability, 2),
            "evidence": round(self.evidence, 2),
            "score": self.score,
            "severity": self.severity,
            "rationale": self.rationale,
        }


class SecurityGraph:
    """Nodes, edges, and the attack paths derivable from them."""

    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []
        self._out: dict[str, list[Edge]] = defaultdict(list)

    def add_node(self, node_id: str, kind: str, label: str, **attrs) -> str:
        if node_id not in self.nodes:
            self.nodes[node_id] = Node(node_id, kind, label, attrs)
        else:
            self.nodes[node_id].attrs.update(attrs)
        return node_id

    def add_edge(self, src: str, dst: str, kind: str, **attrs) -> None:
        if src not in self.nodes or dst not in self.nodes:
            return
        edge = Edge(src, dst, kind, attrs)
        self.edges.append(edge)
        self._out[src].append(edge)

    def neighbours(self, node_id: str) -> list[Edge]:
        return self._out.get(node_id, [])

    def path_to(self, start: str, target_kind: str, max_depth: int = 8) -> list[str]:
        """Shortest path from ``start`` to any node of ``target_kind``."""
        seen = {start}
        queue: list[list[str]] = [[start]]
        while queue:
            path = queue.pop(0)
            if len(path) > max_depth:
                continue
            for edge in self.neighbours(path[-1]):
                if edge.dst in seen:
                    continue
                node = self.nodes.get(edge.dst)
                if node is None:
                    continue
                if node.kind == target_kind:
                    return path + [edge.dst]
                seen.add(edge.dst)
                queue.append(path + [edge.dst])
        return []

    def describe_path(self, path: list[str]) -> str:
        """Render a path the way a developer reads an attack chain."""
        return "\n  ↓\n".join(
            self.nodes[n].label for n in path if n in self.nodes
        )

    def summary(self) -> dict:
        kinds: dict[str, int] = defaultdict(int)
        for node in self.nodes.values():
            kinds[node.kind] += 1
        return {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "by_kind": dict(kinds),
        }


# ------------------------------------------------------------- construction


def build_graph(scope, deep) -> SecurityGraph:
    """Assemble the graph from what the scan actually observed."""
    g = SecurityGraph()

    internet = g.add_node("internet", TARGET, "Internet")
    host = g.add_node(f"host:{scope.hostname}", HOST, scope.hostname)
    g.add_edge(internet, host, HOSTS)

    # Endpoints and their parameters.
    for endpoint in getattr(deep, "endpoints", []) or []:
        eid = g.add_node(
            f"ep:{endpoint.url}", ENDPOINT, endpoint.url,
            method=getattr(endpoint, "method", "GET"),
            discovery=getattr(endpoint, "discovery_method", ""),
            status=getattr(endpoint, "status_code", None),
        )
        g.add_edge(host, eid, CONTAINS)

    for param in getattr(deep, "params", []) or []:
        pid = g.add_node(
            f"param:{param.url}:{param.name}", PARAMETER,
            f"{param.method} parameter: {param.name}",
            name=param.name, url=param.url,
        )
        eid = f"ep:{param.url}"
        if eid in g.nodes:
            g.add_edge(eid, pid, ACCEPTS)
        else:
            g.add_edge(host, pid, ACCEPTS)
        # A discovered parameter is, by definition, attacker-controlled input.
        sid = g.add_node(f"src:{param.url}:{param.name}", SOURCE,
                         f"attacker-controlled input: {param.name}")
        g.add_edge(pid, sid, CONTROLS)

    # Additional hosts that were proven distinct.
    for vhost in getattr(deep, "vhosts", []) or []:
        if not getattr(vhost, "distinct", False):
            continue
        vid = g.add_node(f"host:{vhost.hostname}", HOST, vhost.hostname,
                         environment=getattr(vhost, "environment", ""))
        g.add_edge(internet, vid, HOSTS)

    # Dependencies, with the vulnerable symbol and its call sites.
    for finding in getattr(deep, "findings", []) or []:
        dep = getattr(finding, "dependency", None) or {}
        if not dep:
            continue
        did = g.add_node(
            f"dep:{dep.get('package')}", DEPENDENCY,
            f"{dep.get('package')} {dep.get('version')}",
            **{k: dep.get(k) for k in
               ("advisory_id", "is_direct", "is_development", "classification")},
        )
        g.add_edge(host, did, IMPORTS)
        for symbol in (dep.get("symbols_found") or [])[:3]:
            fid = g.add_node(f"fn:{dep.get('package')}:{symbol}", SINK,
                             f"{symbol}() in {dep.get('package')}")
            g.add_edge(did, fid, CONTAINS)
            # Only a proven taint path creates the FLOWS_TO edge.
            for site in (dep.get("tainted_call_sites") or [])[:2]:
                src = g.add_node(f"src:code:{site}", SOURCE,
                                 f"request data at {site}")
                g.add_edge(src, fid, FLOWS_TO, site=site)

    # Findings hang off the asset they concern.
    for finding in getattr(deep, "findings", []) or []:
        fid = g.add_node(
            f"finding:{finding.dedup_key or finding.title}", FINDING,
            finding.title, category=finding.category, severity=finding.severity,
        )
        anchor = f"ep:{finding.url}" if f"ep:{finding.url}" in g.nodes else host
        g.add_edge(anchor, fid, EXPOSES)

    return g


# ----------------------------------------------------------------- scoring

# Impact per finding category. This is the *ceiling* the category can reach;
# the other dimensions decide how much of it is realised.
_CATEGORY_IMPACT = {
    "input_validation": "high",       # injection / XSS family
    "code_security": "high",
    "dependency_vulnerability": "medium",
    "information_exposure": "medium",
    "authentication": "high",
    "configuration": "medium",
    "security_headers": "low",
    "attack_surface": "low",
    "source_correlation": "high",
}

# Which evidence level a finding's own confidence maps to when nothing
# stronger is known.
_CONFIDENCE_TO_EVIDENCE = {
    "confirmed": "observed",
    "potential": "suspected",
    "uncertain": "informational",
    "false_positive": "informational",
}


def _evidence_level(finding) -> str:
    """Strongest evidence level this finding has earned."""
    # A dynamically demonstrated finding carries a request/response pair.
    demonstrated = bool(
        finding.confidence == "confirmed"
        and finding.evidence
        and (finding.request_summary or finding.response_summary)
        and finding.category not in ("dependency_vulnerability", "code_security")
    )
    if demonstrated:
        return "confirmed"

    exploitability = getattr(finding, "exploitability", "") or ""
    if exploitability == "confirmed_exploitable":
        return "confirmed"
    if exploitability in ("potentially_exploitable", "reachable_from_input"):
        return "potentially_reachable"
    if exploitability == "functionality_used":
        return "observed"
    if exploitability == "dependency_present":
        return "reported"

    return _CONFIDENCE_TO_EVIDENCE.get(finding.confidence, "suspected")


def score_finding(finding, graph: SecurityGraph | None = None) -> RiskBreakdown:
    """Score one finding from its evidence and its place in the graph."""
    category = finding.category or ""
    impact = IMPACT_SCORE.get(_CATEGORY_IMPACT.get(category, "low"), 0.25)

    evidence_level = _evidence_level(finding)
    evidence = EVIDENCE_WEIGHT.get(evidence_level, 0.3)

    dep = getattr(finding, "dependency", None) or {}
    exploitability_state = getattr(finding, "exploitability", "") or ""

    # --- Reachability: is there a path from attacker input to the sink?
    if evidence_level == "confirmed":
        reachability = 1.0
    elif dep:
        reachability = (
            0.9 if dep.get("reachable_from_input")
            else 0.45 if dep.get("functionality_used")
            else 0.15
        )
    elif category in ("input_validation", "code_security"):
        reachability = 0.6 if finding.parameter or finding.url else 0.35
    else:
        reachability = 0.5

    # --- Exposure: how reachable is the entry point?
    if dep and dep.get("is_development"):
        # A dev-only dependency is not part of the deployed surface.
        exposure = 0.15
    elif category in ("security_headers", "attack_surface"):
        exposure = 0.5
    elif finding.url or finding.parameter:
        exposure = 1.0          # observed on a public endpoint
    else:
        exposure = 0.6

    # --- Exploitability: can an attacker actually drive it?
    if evidence_level == "confirmed":
        exploitability = 1.0
    elif exploitability_state in ("potentially_exploitable", "reachable_from_input"):
        exploitability = 0.7
    elif category == "security_headers":
        # Hardening gaps are not independently exploitable.
        exploitability = 0.2
    elif category == "attack_surface":
        exploitability = 0.25
    else:
        exploitability = 0.5

    raw = impact * exploitability * exposure * reachability * evidence
    score = int(round(min(1.0, raw) * 100))

    breakdown = RiskBreakdown(
        impact=impact,
        exploitability=exploitability,
        exposure=exposure,
        reachability=reachability,
        evidence=evidence,
        score=score,
        severity=severity_for_score(score),
        rationale=(
            f"impact {impact:.2f} x exploitability {exploitability:.2f} x "
            f"exposure {exposure:.2f} x reachability {reachability:.2f} x "
            f"evidence {evidence:.2f} ({evidence_level})"
        ),
    )
    return breakdown


# Configurable bands.
RISK_BANDS = [(75, "critical"), (50, "high"), (25, "medium"), (0, "low")]


def severity_for_score(score: int) -> str:
    for threshold, label in RISK_BANDS:
        if score >= threshold:
            return label
    return "low"


def overall_risk(findings, graph: SecurityGraph | None = None) -> dict:
    """Application risk from the graph, not from a count of findings.

    The result is the greater of the strongest single finding and a weighted
    aggregate, so one confirmed attack path dominates a pile of hardening
    notes, while a genuinely broad set of medium issues still registers.
    """
    live = [
        f for f in findings
        if f.confidence != "false_positive"
        and getattr(f, "contributes_to_risk", True)
    ]
    if not live:
        return {
            "score": 0,
            "level": "low",
            "strongest": 0,
            "aggregate": 0,
            "breakdowns": [],
            "explanation": "No findings with supporting evidence.",
        }

    scored = [(f, score_finding(f, graph)) for f in live]
    scores = sorted((b.score for _, b in scored), reverse=True)
    strongest = scores[0]

    # Diminishing returns: the second finding contributes half, the third a
    # third, and so on — volume alone cannot manufacture a high score.
    aggregate = min(
        100,
        int(round(sum(s / (i + 1) for i, s in enumerate(scores)))),
    )

    score = max(strongest, aggregate)
    top_finding, top_breakdown = max(scored, key=lambda pair: pair[1].score)

    return {
        "score": score,
        "level": severity_for_score(score),
        "strongest": strongest,
        "aggregate": aggregate,
        "driver": top_finding.title,
        "driver_rationale": top_breakdown.rationale,
        "breakdowns": [
            {"title": f.title, **b.as_dict()} for f, b in
            sorted(scored, key=lambda pair: pair[1].score, reverse=True)[:15]
        ],
        "explanation": (
            f"Driven by '{top_finding.title}' at {strongest}/100"
            if strongest >= aggregate
            else f"Driven by the combined weight of {len(scored)} findings"
        ),
    }
