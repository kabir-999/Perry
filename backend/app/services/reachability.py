"""
Vulnerable-functionality reachability analysis.

The question "is this application affected by CVE-X in package P?" decomposes
into three separate questions, and answering the easy one does not answer the
hard ones:

  1. Is P present?                       — reading a manifest
  2. Is the *vulnerable part* of P used? — which symbol does the advisory
                                           blame, and do we call it?
  3. Can attacker-controlled input reach  — does data from an HTTP request
     that call?                            flow into that call's arguments?

Importing a package answers none of these. `import lodash` says nothing about
whether `_.template` (the vulnerable function) is called, and calling
`_.template("static string")` says nothing about whether a request body can
reach it. Both distinctions are the difference between a maintenance ticket
and an incident, so neither is inferred here.

The dataflow is intraprocedural and lexical: it tracks assignments from known
request-input expressions to local names within a file, then checks whether
those names appear in the arguments of a vulnerable call. That is a real
taint check with real limits — it does not follow values across function
boundaries or module exports. Where it cannot establish a path it says so,
rather than assuming one exists.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------- ladder

# The five states, weakest evidence first. Each is a strictly stronger claim
# than the one before it.
DEPENDENCY_PRESENT = "dependency_present"
FUNCTIONALITY_USED = "functionality_used"
REACHABLE_FROM_INPUT = "reachable_from_input"
POTENTIALLY_EXPLOITABLE = "potentially_exploitable"
CONFIRMED_EXPLOITABLE = "confirmed_exploitable"

CLASSIFICATION_LABEL = {
    DEPENDENCY_PRESENT: "Vulnerable Dependency Present",
    FUNCTIONALITY_USED: "Vulnerable Functionality Used",
    REACHABLE_FROM_INPUT: "Vulnerable Functionality Reachable From Input",
    POTENTIALLY_EXPLOITABLE: "Potentially Exploitable",
    CONFIRMED_EXPLOITABLE: "Confirmed Exploitable Vulnerability",
}

CLASSIFICATION_ORDER = [
    DEPENDENCY_PRESENT,
    FUNCTIONALITY_USED,
    REACHABLE_FROM_INPUT,
    POTENTIALLY_EXPLOITABLE,
    CONFIRMED_EXPLOITABLE,
]

# What each state means in one sentence, for the report.
CLASSIFICATION_MEANING = {
    DEPENDENCY_PRESENT: (
        "The advisory affects a package version this project depends on. No "
        "evidence was found that the vulnerable functionality is used."
    ),
    FUNCTIONALITY_USED: (
        "The specific functionality named by the advisory is called by this "
        "project, but no path was found from attacker-controlled input to it."
    ),
    REACHABLE_FROM_INPUT: (
        "The vulnerable functionality is called with data that originates "
        "from an HTTP request."
    ),
    POTENTIALLY_EXPLOITABLE: (
        "The vulnerable functionality is used and reachable from "
        "attacker-controlled input. Exploitation was not demonstrated."
    ),
    CONFIRMED_EXPLOITABLE: (
        "The scanner demonstrated a working attack against this issue."
    ),
}


# ------------------------------------------------- advisory symbol mining

# Function/method names as they appear in advisory prose: `_.template`,
# "the parse() function", "Model.find", "safe_load".
_BACKTICKED = re.compile(r"`([A-Za-z_$][\w$.]*(?:\(\))?)`")
_FUNCTION_PROSE = re.compile(
    r"\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(\)"
)
_METHOD_PHRASE = re.compile(
    r"\b(?:function|method|api|helper|utility)\s+`?([A-Za-z_$][\w$.]*)`?",
    re.IGNORECASE,
)

# Words that look like identifiers in prose but never name an API.
_SYMBOL_STOPWORDS = {
    "the", "this", "that", "it", "a", "an", "and", "or", "not", "is", "are",
    "when", "if", "then", "with", "via", "using", "used", "use", "allows",
    "attacker", "user", "input", "version", "versions", "package", "affected",
    "vulnerability", "vulnerable", "issue", "fix", "fixed", "patch", "prior",
    "before", "after", "npm", "pypi", "cve", "ghsa", "http", "https", "url",
}


def extract_vulnerable_symbols(advisory_text: str, package: str) -> list[str]:
    """Best-effort list of the functions/APIs an advisory blames.

    OSV records rarely carry machine-readable symbols outside the Go ecosystem,
    so this reads the human summary/details. It is a heuristic: an empty result
    means "the advisory did not name a symbol we could recognise", which the
    caller must treat as *unknown*, never as "no vulnerable functionality".
    """
    if not advisory_text:
        return []

    candidates: set[str] = set()
    for pattern in (_BACKTICKED, _FUNCTION_PROSE, _METHOD_PHRASE):
        for match in pattern.finditer(advisory_text):
            raw = match.group(1).strip().rstrip("()")
            if not raw:
                continue
            # Keep the last segment too: `_.template` -> also `template`.
            tail = raw.split(".")[-1]
            for name in (raw, tail):
                if (
                    len(name) >= 3
                    and name.lower() not in _SYMBOL_STOPWORDS
                    and name.lower() != package.lower()
                    and not name.isdigit()
                ):
                    candidates.add(name)

    # Longest first so `_.template` is preferred over `template`.
    return sorted(candidates, key=len, reverse=True)[:12]


# --------------------------------------------------------- taint sources

# Expressions that yield attacker-controlled data. Matching one of these is
# what makes a value "tainted"; nothing else does.
_REQUEST_SOURCES = [
    # Express / Koa / Fastify / generic Node
    r"req\.(?:body|query|params|headers|cookies|url|originalUrl|path)",
    r"request\.(?:body|query|params|headers|cookies|url)",
    r"ctx\.(?:request|query|params|body|headers)",
    r"event\.(?:body|queryStringParameters|pathParameters|headers)",
    # Next.js / SvelteKit style
    r"searchParams\.get\(",
    r"formData\.get\(",
    # Flask / Django / FastAPI
    r"request\.(?:args|form|json|data|files|values|GET|POST|COOKIES|headers)",
    r"request\.get_json\(",
    # Raw WSGI/ASGI
    r"environ\[",
    r"scope\[\s*[\"']query_string",
]

_SOURCE_RE = re.compile("|".join(_REQUEST_SOURCES))

# `const x = req.query.q` / `x = request.args.get("q")` — capture the name a
# tainted value lands in.
_JS_ASSIGN = re.compile(
    r"(?:const|let|var)\s+(?:\{\s*([\w\s,:]+)\s*\}|([\w$]+))\s*=\s*([^;\n]+)"
)
_PY_ASSIGN = re.compile(r"^\s*([\w, ]+?)\s*=\s*([^\n]+)", re.MULTILINE)

# Route/handler declarations, used only to describe *where* a path was found.
_ROUTE_HINT = re.compile(
    r"(?:@app\.(?:route|get|post|put|delete|patch)|"
    r"app\.(?:get|post|put|delete|patch|use)\s*\(|"
    r"router\.(?:get|post|put|delete|patch)\s*\(|"
    r"def\s+\w+\s*\(\s*request|export\s+async\s+function\s+(?:GET|POST|PUT|DELETE))",
    re.IGNORECASE,
)


@dataclass
class ReachabilityEvidence:
    """What was established about one advisory against one codebase."""

    symbols_searched: list[str] = field(default_factory=list)
    symbols_found: list[str] = field(default_factory=list)
    # file:line where the vulnerable symbol is called.
    call_sites: list[str] = field(default_factory=list)
    # file:line where request data flows into such a call.
    tainted_call_sites: list[str] = field(default_factory=list)
    tainted_variables: list[str] = field(default_factory=list)
    in_route_handler: bool = False
    notes: str = ""

    @property
    def functionality_used(self) -> bool:
        return bool(self.symbols_found)

    @property
    def reachable_from_input(self) -> bool:
        return bool(self.tainted_call_sites)


def _tainted_names(content: str, language: str) -> set[str]:
    """Local names that hold request-derived data, within this file."""
    names: set[str] = set()

    if language == "python":
        for match in _PY_ASSIGN.finditer(content):
            targets, expr = match.group(1), match.group(2)
            if _SOURCE_RE.search(expr):
                for t in targets.split(","):
                    t = t.strip()
                    if t.isidentifier():
                        names.add(t)
    else:
        for match in _JS_ASSIGN.finditer(content):
            destructured, single, expr = match.groups()
            if not _SOURCE_RE.search(expr or ""):
                continue
            if single:
                names.add(single)
            if destructured:
                for part in destructured.split(","):
                    name = part.split(":")[-1].strip()
                    if name.isidentifier():
                        names.add(name)

    # One hop: `const y = x` where x is tainted.
    for _ in range(2):
        added = False
        for match in (_PY_ASSIGN if language == "python" else _JS_ASSIGN).finditer(content):
            groups = match.groups()
            expr = groups[-1] or ""
            targets = [g for g in groups[:-1] if g]
            if not any(re.search(rf"\b{re.escape(n)}\b", expr) for n in names):
                continue
            for target in targets:
                for t in target.split(","):
                    t = t.split(":")[-1].strip()
                    if t.isidentifier() and t not in names:
                        names.add(t)
                        added = True
        if not added:
            break

    return names


def analyze_reachability(
    repo_path: Path,
    files: list[Path],
    package: str,
    symbols: list[str],
    import_files: list[str],
) -> ReachabilityEvidence:
    """Look for calls to ``symbols`` and for request data flowing into them."""
    evidence = ReachabilityEvidence(symbols_searched=list(symbols))

    if not symbols:
        evidence.notes = (
            "The advisory does not name a specific function or API that we "
            "could match against the code, so we cannot tell whether the "
            "vulnerable functionality is used."
        )
        return evidence

    # Only files that import the package can call into it.
    candidates = [p for p in files if str(p.relative_to(repo_path)) in set(import_files)] or files

    # The lookbehind excludes a preceding word character (so `myparse(` does
    # not match `parse`) but deliberately allows a preceding dot, because
    # member access — `marked.parse(...)`, `_.template(...)` — is the normal
    # way these APIs are called.
    call_patterns = {
        s: re.compile(rf"(?<![\w$]){re.escape(s)}\s*\(") for s in symbols
    }

    for file_path in candidates:
        try:
            rel = str(file_path.relative_to(repo_path))
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, ValueError):
            continue

        language = "python" if file_path.suffix == ".py" else "javascript"
        tainted = _tainted_names(content, language)
        has_route = bool(_ROUTE_HINT.search(content))

        lines = content.splitlines()
        for symbol, pattern in call_patterns.items():
            for i, line in enumerate(lines, 1):
                if not pattern.search(line):
                    continue
                if symbol not in evidence.symbols_found:
                    evidence.symbols_found.append(symbol)
                site = f"{rel}:{i}"
                if site not in evidence.call_sites:
                    evidence.call_sites.append(site)

                # Attacker-controlled data in this call's arguments? Either a
                # request expression inline, or a local holding one.
                args = line[line.find("(", line.find(symbol)) :]
                flows = _SOURCE_RE.search(args) is not None
                hit_names = [
                    n for n in tainted if re.search(rf"\b{re.escape(n)}\b", args)
                ]
                if flows or hit_names:
                    if site not in evidence.tainted_call_sites:
                        evidence.tainted_call_sites.append(site)
                    evidence.tainted_variables.extend(
                        n for n in hit_names if n not in evidence.tainted_variables
                    )
                    evidence.in_route_handler = evidence.in_route_handler or has_route

    evidence.call_sites = evidence.call_sites[:6]
    evidence.tainted_call_sites = evidence.tainted_call_sites[:6]
    evidence.tainted_variables = evidence.tainted_variables[:6]

    if evidence.reachable_from_input:
        evidence.notes = (
            f"Request data reaches {evidence.symbols_found[0]}() at "
            f"{evidence.tainted_call_sites[0]}."
        )
    elif evidence.functionality_used:
        evidence.notes = (
            f"{evidence.symbols_found[0]}() is called at "
            f"{evidence.call_sites[0]}, but no path was found from request "
            "input to that call."
        )
    else:
        evidence.notes = (
            "The functionality named by the advisory "
            f"({', '.join(symbols[:3])}) was not found in the analyzed source."
        )

    return evidence


def classify(evidence: ReachabilityEvidence, *, is_used: bool) -> str:
    """Map the evidence onto the five-state ladder.

    ``Potentially Exploitable`` requires BOTH that the vulnerable
    functionality is used and that attacker-controlled input can reach it.
    Neither an import nor an open HTTP port contributes to that decision.
    """
    if evidence.reachable_from_input and evidence.functionality_used:
        # Reachable from a request handler is the strongest static claim.
        return (
            POTENTIALLY_EXPLOITABLE
            if evidence.in_route_handler
            else REACHABLE_FROM_INPUT
        )
    if evidence.functionality_used:
        return FUNCTIONALITY_USED
    return DEPENDENCY_PRESENT
