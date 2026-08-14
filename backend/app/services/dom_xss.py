"""
Static DOM-XSS analysis.

Scans JavaScript source text for tainted data flows from a DOM *source*
(attacker-controllable input) into a dangerous *sink*. This is static analysis
only — no JavaScript is ever executed.

Confidence:
  * ``confirmed``  — a source expression (or a variable assigned from a source)
                     appears directly in a sink's argument/right-hand side.
  * ``potential``  — both a source and a sink exist in the file but a direct
                     flow could not be established.
  * (no finding)   — a sink with only static data, or a source with no sink.
"""
from __future__ import annotations

import re

from app.services.finding_types import FindingCandidate

# Attacker-controllable DOM sources.
_SOURCES = [
    r"location\.hash", r"location\.search", r"location\.href", r"location\b",
    r"document\.URL", r"document\.documentURI", r"document\.referrer",
    r"window\.name", r"\.data\b",  # event.data from postMessage handlers
]
_SOURCE_RE = re.compile("|".join(_SOURCES))

# Dangerous sinks: (name, regex capturing the assigned/argument expression).
_SINKS = [
    ("innerHTML", re.compile(r"\.innerHTML\s*=\s*([^;\n]+)")),
    ("outerHTML", re.compile(r"\.outerHTML\s*=\s*([^;\n]+)")),
    ("document.write", re.compile(r"document\.write(?:ln)?\s*\(([^;\n]+)\)")),
    ("eval", re.compile(r"(?<![.\w])eval\s*\(([^;\n]+)\)")),
    ("Function", re.compile(r"new\s+Function\s*\(([^;\n]+)\)")),
    ("setTimeout", re.compile(r"set(?:Timeout|Interval)\s*\(\s*([\"'][^\"']*[\"'][^)]*)\)")),
    ("insertAdjacentHTML", re.compile(r"\.insertAdjacentHTML\s*\([^,]+,\s*([^;\n]+)\)")),
]

# Assignments that taint a variable from a source: `var x = location.hash...`.
_ASSIGN_RE = re.compile(r"(?:var|let|const)?\s*([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)")


def _tainted_vars(js: str) -> set[str]:
    tainted: set[str] = set()
    # Iterate to a fixed point so `b = a` inherits taint from `a = location.hash`.
    for _ in range(3):
        added = False
        for name, rhs in _ASSIGN_RE.findall(js):
            if name in tainted:
                continue
            if _SOURCE_RE.search(rhs) or any(re.search(rf"\b{re.escape(t)}\b", rhs) for t in tainted):
                tainted.add(name)
                added = True
        if not added:
            break
    return tainted


def analyze_dom_xss(js: str, *, source_url: str = "") -> list[FindingCandidate]:
    """Return DOM-XSS findings for one JavaScript resource."""
    if not js:
        return []
    tainted = _tainted_vars(js)
    findings: list[FindingCandidate] = []
    seen: set[str] = set()

    for sink_name, sink_re in _SINKS:
        for m in sink_re.finditer(js):
            arg = m.group(1)
            direct_source = bool(_SOURCE_RE.search(arg))
            via_var = any(re.search(rf"\b{re.escape(t)}\b", arg) for t in tainted)
            if direct_source or via_var:
                confidence = "confirmed"
            else:
                continue  # sink with only static/unrelated data — not reported
            key = f"dom_xss|{source_url}|{sink_name}"
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                FindingCandidate(
                    title=f"DOM-based XSS via {sink_name}",
                    category="input_validation",
                    severity="high",
                    confidence=confidence,
                    url=source_url,
                    method="GET",
                    parameter=sink_name,
                    evidence=(
                        f"A DOM source flows into the '{sink_name}' sink: "
                        f"{arg.strip()[:160]}"
                    ),
                    request_summary=f"static analysis of {source_url or 'inline script'}",
                    response_summary=f"source -> {sink_name}",
                    description="Attacker-controllable DOM input reaches a dangerous "
                    f"sink ({sink_name}) without sanitisation.",
                    impact="Client-side script execution in the victim's browser.",
                    remediation="Avoid HTML/JS sinks with untrusted input; use "
                    "textContent, safe DOM APIs, and a strict CSP.",
                    dedup_key=key,
                )
            )
    return findings
