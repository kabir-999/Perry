"""
Dependency exploitability analysis.

A CVE against a package version is *not* a vulnerability in the application.
Before a dependency advisory is reported as something exploitable, we establish
three separate facts, each of which can fail independently:

  1. **Declared** — is the package a direct dependency, or pulled in
     transitively by something else?
  2. **Used** — is it actually imported anywhere in the source we analyzed?
     An unused entry in package.json ships no attack surface.
  3. **Reachable** — is the importing module plausibly on the path of an
     externally-triggered request (a route, handler, controller, middleware)?

The result is one of three classifications, in increasing order of concern:

  ``known_vulnerable_dependency``
      The advisory is real but we found no evidence the code is used, or it is
      confined to build/test tooling. Informational.
  ``potentially_exploitable``
      The package is imported by code that appears to serve external requests.
      Worth fixing, but we have *not* shown an attack works.
  ``confirmed_exploitable``
      Reserved for findings where the live scanner actually demonstrated the
      attack. Static dependency analysis alone never produces this — the
      constant exists so nothing else has to invent a stronger word.

The reachability signal is a heuristic over import graphs and directory
conventions. It is deliberately reported as an explicit "unknown" when we
cannot tell, rather than being rounded up to "reachable".
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

# The five-state ladder lives in reachability.py; re-exported so every caller
# shares one vocabulary.
from app.services.reachability import (
    CLASSIFICATION_LABEL,
    CLASSIFICATION_MEANING,
    CONFIRMED_EXPLOITABLE,
    DEPENDENCY_PRESENT,
    FUNCTIONALITY_USED,
    POTENTIALLY_EXPLOITABLE,
    REACHABLE_FROM_INPUT,
)

# Alias for the weakest state, kept so older call sites keep working.
KNOWN_VULNERABLE = DEPENDENCY_PRESENT

# Directories whose code only runs at build or test time — a vulnerability
# reachable only from here is not part of the deployed attack surface.
_NON_RUNTIME_DIRS = {
    "test", "tests", "__tests__", "spec", "specs", "e2e", "cypress",
    "docs", "doc", "examples", "example", "scripts", "script", "tools",
    "benchmark", "benchmarks", "fixtures", "mocks", "__mocks__", "storybook",
}

# Directories that typically handle inbound requests. An import inside one of
# these is the strongest cheap signal of external reachability we have.
_REQUEST_PATH_DIRS = {
    "routes", "route", "api", "apis", "controllers", "controller", "handlers",
    "handler", "endpoints", "views", "middleware", "middlewares", "pages",
    "server", "resolvers", "graphql", "app",
}

# Files that commonly boot an HTTP server.
_ENTRYPOINT_NAMES = {
    "app.py", "main.py", "server.py", "wsgi.py", "asgi.py", "manage.py",
    "index.js", "server.js", "app.js", "main.js", "index.ts", "server.ts",
    "app.ts", "main.ts",
}

_SOURCE_EXTENSIONS = (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")


@dataclass
class DependencyUsage:
    """What we could establish about one package inside one repository."""

    package: str
    ecosystem: str
    is_direct: bool = False
    is_development: bool = False
    is_used: bool = False
    # None = we could not determine reachability either way.
    externally_reachable: bool | None = None
    runtime_only_in_tooling: bool = False
    import_sites: list[str] = field(default_factory=list)
    # Every runtime file importing the package — the search space for the
    # reachability pass.
    runtime_import_files: list[str] = field(default_factory=list)
    notes: str = ""

    @property
    def classification(self) -> str:
        """Import-level evidence only — never stronger than "present".

        Whether the *vulnerable functionality* is used, and whether input can
        reach it, is decided in reachability.py. An import is evidence of
        neither, so this deliberately cannot return an exploitability state.
        """
        return DEPENDENCY_PRESENT

    def dependency_kind(self) -> str:
        """direct/transitive crossed with production/development."""
        scope = "development" if self.is_development else "production"
        return f"{'direct' if self.is_direct else 'transitive'} {scope}"


def _module_names(package: str, ecosystem: str) -> set[str]:
    """Import names a package plausibly registers."""
    names = {package}
    if ecosystem.lower() in ("pypi", "python"):
        # requests-oauthlib -> requests_oauthlib; also the bare first segment.
        names.add(package.replace("-", "_"))
        names.add(package.replace("-", "_").split(".")[0])
    else:
        # Scoped npm packages are imported by their full name.
        names.add(package.split("/")[-1])
    return {n for n in names if n}


def _import_patterns(package: str, ecosystem: str) -> list[re.Pattern]:
    patterns: list[re.Pattern] = []
    for name in _module_names(package, ecosystem):
        escaped = re.escape(name)
        if ecosystem.lower() in ("pypi", "python"):
            patterns.append(
                re.compile(rf"^\s*(?:from\s+{escaped}(?:\.\w+)*\s+import\b|import\s+{escaped}\b)", re.MULTILINE)
            )
        else:
            patterns.append(
                re.compile(
                    rf"""(?:require\(\s*['"]{escaped}(?:/[^'"]*)?['"]\s*\)"""
                    rf"""|from\s+['"]{escaped}(?:/[^'"]*)?['"]"""
                    rf"""|import\s*\(\s*['"]{escaped}(?:/[^'"]*)?['"]\s*\))"""
                )
            )
    return patterns


def _is_non_runtime(rel_path: str) -> bool:
    parts = {p.lower() for p in Path(rel_path).parts}
    if parts & _NON_RUNTIME_DIRS:
        return True
    name = Path(rel_path).name.lower()
    return (
        ".test." in name
        or ".spec." in name
        or name.startswith("test_")
        or name.endswith("_test.py")
    )


def _looks_request_facing(rel_path: str) -> bool:
    parts = {p.lower() for p in Path(rel_path).parts}
    if parts & _REQUEST_PATH_DIRS:
        return True
    return Path(rel_path).name.lower() in _ENTRYPOINT_NAMES


def read_declared_dependencies(repo_path: Path) -> dict[tuple[str, str], tuple[bool, bool]]:
    """Map (ecosystem, package) -> is_direct for everything we can see declared.

    Manifest entries are direct dependencies. Lockfiles are read only to learn
    that a package exists transitively, so we can label it honestly instead of
    implying the developer chose it.
    """
    # (ecosystem, package) -> (is_direct, is_development)
    declared: dict[tuple[str, str], tuple[bool, bool]] = {}

    pkg_json = repo_path / "package.json"
    if pkg_json.exists():
        try:
            doc = json.loads(pkg_json.read_text(encoding="utf-8", errors="ignore"))
            for section in ("dependencies", "devDependencies", "optionalDependencies"):
                is_dev = section == "devDependencies"
                for name in (doc.get(section) or {}):
                    declared[("npm", name)] = (True, is_dev)
        except (ValueError, TypeError, OSError):
            pass

    lock = repo_path / "package-lock.json"
    if lock.exists():
        try:
            doc = json.loads(lock.read_text(encoding="utf-8", errors="ignore"))
            for path in (doc.get("packages") or {}):
                if not path:
                    continue
                name = path.split("node_modules/")[-1]
                declared.setdefault(("npm", name), (False, False))
            for name in (doc.get("dependencies") or {}):
                declared.setdefault(("npm", name), (False, False))
        except (ValueError, TypeError, OSError):
            pass

    req = repo_path / "requirements.txt"
    if req.exists():
        try:
            for line in req.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line or line.startswith(("#", "-")):
                    continue
                name = re.split(r"[=<>~!\[;\s]", line, 1)[0].strip()
                if name:
                    declared[("PyPI", name)] = (True, False)
        except OSError:
            pass

    for manifest in ("pyproject.toml", "Pipfile"):
        path = repo_path / manifest
        if not path.exists():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
            for match in re.finditer(r"^\s*['\"]?([A-Za-z0-9_.-]+)['\"]?\s*[=<>~^]", text, re.MULTILINE):
                declared.setdefault(("PyPI", match.group(1)), (True, False))
        except OSError:
            pass

    return declared


def analyze_usage(
    repo_path: Path,
    files: list[Path],
    package: str,
    ecosystem: str,
    declared: dict[tuple[str, str], bool],
) -> DependencyUsage:
    """Establish whether ``package`` is declared, imported, and request-facing."""
    usage = DependencyUsage(package=package, ecosystem=ecosystem)

    # Direct vs transitive. Absent from every manifest we could read means we
    # only know about it from a lockfile, i.e. transitive.
    for key in ((ecosystem, package), ("npm", package), ("PyPI", package)):
        if key in declared:
            usage.is_direct, usage.is_development = declared[key]
            break

    patterns = _import_patterns(package, ecosystem)
    runtime_hits: list[str] = []
    tooling_hits: list[str] = []
    request_facing = False

    for file_path in files:
        if file_path.suffix.lower() not in _SOURCE_EXTENSIONS:
            continue
        try:
            rel = str(file_path.relative_to(repo_path))
        except ValueError:
            continue
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if package.split("/")[-1] not in content:
            continue  # cheap reject before running the regexes
        if not any(p.search(content) for p in patterns):
            continue

        if _is_non_runtime(rel):
            tooling_hits.append(rel)
            continue
        runtime_hits.append(rel)
        if _looks_request_facing(rel):
            request_facing = True

    usage.is_used = bool(runtime_hits or tooling_hits)
    usage.import_sites = (runtime_hits or tooling_hits)[:5]
    usage.runtime_import_files = list(runtime_hits)

    if runtime_hits:
        usage.runtime_only_in_tooling = False
        # Deliberately NOT set from directory names — see classification().
        usage.externally_reachable = None
        usage.notes = f"Imported in {len(runtime_hits)} runtime file(s)."
    elif tooling_hits:
        usage.runtime_only_in_tooling = True
        usage.externally_reachable = False
        usage.notes = (
            f"Only imported by build/test tooling ({tooling_hits[0]}); not part "
            "of the deployed runtime."
        )
    else:
        usage.externally_reachable = False
        usage.notes = (
            "Declared but no import of this package was found in the analyzed "
            "source."
        )

    return usage


# --------------------------------------------------------------------- OSV


def parse_osv_vulnerability(vuln: dict, package: str) -> dict:
    """Pull the version facts and real severity out of an OSV record.

    OSV reports severity in several places and none of them are guaranteed, so
    the caller gets an explicit empty string rather than a fabricated default.
    """
    introduced: list[str] = []
    fixed: list[str] = []

    for affected in vuln.get("affected", []) or []:
        if not isinstance(affected, dict):
            continue
        name = ((affected.get("package") or {}).get("name") or "").lower()
        if name and package.lower() not in name:
            continue
        for rng in affected.get("ranges", []) or []:
            for event in (rng or {}).get("events", []) or []:
                if not isinstance(event, dict):
                    continue
                if event.get("introduced"):
                    introduced.append(str(event["introduced"]))
                if event.get("fixed"):
                    fixed.append(str(event["fixed"]))

    if introduced and fixed:
        vulnerable_range = f">={introduced[0]}, <{fixed[0]}"
    elif introduced:
        vulnerable_range = f">={introduced[0]}"
    elif fixed:
        vulnerable_range = f"<{fixed[0]}"
    else:
        vulnerable_range = ""

    return {
        "advisory_id": str(vuln.get("id") or ""),
        "summary": str(vuln.get("summary") or "")[:300],
        "vulnerable_range": vulnerable_range,
        "fixed_version": fixed[0] if fixed else "",
        "severity": _osv_severity(vuln),
        "aliases": [str(a) for a in (vuln.get("aliases") or [])][:4],
    }


_CVSS_SEVERITY_BANDS = (
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
)


def _osv_severity(vuln: dict) -> str:
    """Advisory severity, or "" when OSV does not state one."""
    db = vuln.get("database_specific") or {}
    raw = str(db.get("severity") or "").strip().lower()
    if raw in ("critical", "high", "medium", "moderate", "low"):
        return "medium" if raw == "moderate" else raw

    for entry in vuln.get("severity", []) or []:
        if not isinstance(entry, dict):
            continue
        score = str(entry.get("score") or "")
        # CVSS vectors carry no numeric score here; a bare number sometimes does.
        try:
            value = float(score)
        except ValueError:
            continue
        for threshold, label in _CVSS_SEVERITY_BANDS:
            if value >= threshold:
                return label
    return ""
