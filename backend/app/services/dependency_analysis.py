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
from app.services.version_ranges import RangeMatch, evaluate
from app.services.finding_types import FindingCandidate
from app.services.reachability import (
    CLASSIFICATION_LABEL,
    CLASSIFICATION_MEANING,
    CONFIRMED_EXPLOITABLE,
    DEPENDENCY_PRESENT,
    FUNCTIONALITY_USED,
    POTENTIALLY_EXPLOITABLE,
    REACHABLE_FROM_INPUT,
    dependency_severity,
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

_SOURCE_EXTENSIONS = (
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".go", ".rb", ".java", ".php", ".rs", ".cs",
)

# Canonical OSV.dev ecosystem strings this module recognizes, keyed by every
# lowercase alias a caller/manifest reader might use for it.
_ECOSYSTEM_ALIASES = {
    "pypi": "python", "python": "python",
    "npm": "js", "node": "js",
    "go": "go", "golang": "go",
    "rubygems": "ruby", "ruby": "ruby",
    "maven": "java", "java": "java",
    "packagist": "php", "php": "php",
    "crates.io": "rust", "cargo": "rust", "rust": "rust",
    "nuget": "csharp", "csharp": "csharp", ".net": "csharp",
}


def _ecosystem_family(ecosystem: str) -> str:
    """Normalize any accepted ecosystem spelling to one of the family keys
    used by `_module_names`/`_import_patterns` below."""
    return _ECOSYSTEM_ALIASES.get(ecosystem.lower(), "js")


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
    family = _ecosystem_family(ecosystem)
    names = {package}
    if family == "python":
        # requests-oauthlib -> requests_oauthlib; also the bare first segment.
        names.add(package.replace("-", "_"))
        names.add(package.replace("-", "_").split(".")[0])
    elif family == "rust":
        # serde-json (Cargo.toml) is used in source as `serde_json`.
        names.add(package.replace("-", "_"))
    elif family in ("java", "php"):
        # Manifests name the artifact/vendor coordinate; source imports use
        # only the last dotted/slash-separated segment of that name.
        names.add(package.split(".")[-1])
        names.add(package.split("/")[-1])
    else:
        # Scoped npm packages are imported by their full name.
        names.add(package.split("/")[-1])
    return {n for n in names if n}


def _import_patterns(package: str, ecosystem: str) -> list[re.Pattern]:
    family = _ecosystem_family(ecosystem)
    patterns: list[re.Pattern] = []
    for name in _module_names(package, ecosystem):
        escaped = re.escape(name)
        if family == "python":
            patterns.append(
                re.compile(rf"^\s*(?:from\s+{escaped}(?:\.\w+)*\s+import\b|import\s+{escaped}\b)", re.MULTILINE)
            )
        elif family == "go":
            # A single-line `import "pkg"` or one line of a grouped
            # `import (\n\t"pkg"\n)` block — each import is its own line.
            patterns.append(re.compile(
                rf"""(?:import\s+"{escaped}(?:/[^"]*)?"|^\s*"{escaped}(?:/[^"]*)?")""",
                re.MULTILINE,
            ))
        elif family == "ruby":
            patterns.append(re.compile(rf"""require(?:_relative)?\s+['"]{escaped}(?:/[^'"]*)?['"]"""))
        elif family == "java":
            patterns.append(re.compile(rf"""import\s+(?:static\s+)?[\w.]*\b{escaped}\b[\w.]*\s*;"""))
        elif family == "php":
            patterns.append(re.compile(rf"""use\s+[\w\\]*\\?{escaped}\b""", re.IGNORECASE))
        elif family == "rust":
            patterns.append(re.compile(rf"""(?:use\s+{escaped}\b|extern\s+crate\s+{escaped}\b)"""))
        elif family == "csharp":
            patterns.append(re.compile(rf"""using\s+[\w.]*\b{escaped}\b[\w.]*\s*;"""))
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

    # --- Go modules ---
    go_mod = repo_path / "go.mod"
    if go_mod.exists():
        try:
            text = go_mod.read_text(encoding="utf-8", errors="ignore")
            # Single-line `require pkg v1.2.3` and lines inside a
            # `require (\n\tpkg v1.2.3\n)` block share the same shape once
            # the leading "require" keyword is optional.
            for match in re.finditer(
                r"^\s*(?:require\s+)?([\w.\-/]+\.[\w.\-/]+)\s+v[\w.\-+]+", text, re.MULTILINE
            ):
                declared[("Go", match.group(1))] = (True, False)
        except OSError:
            pass

    # --- Ruby (Bundler) ---
    gemfile_lock = repo_path / "Gemfile.lock"
    if gemfile_lock.exists():
        try:
            for line in gemfile_lock.read_text(encoding="utf-8", errors="ignore").splitlines():
                m = re.match(r"^\s{4}([A-Za-z0-9_.-]+)\s+\([\d.]+", line)
                if m:
                    declared.setdefault(("RubyGems", m.group(1)), (False, False))
        except OSError:
            pass
    gemfile = repo_path / "Gemfile"
    if gemfile.exists():
        try:
            text = gemfile.read_text(encoding="utf-8", errors="ignore")
            for match in re.finditer(r"""^\s*gem\s+['"]([A-Za-z0-9_.-]+)['"]""", text, re.MULTILINE):
                declared[("RubyGems", match.group(1))] = (True, False)
        except OSError:
            pass

    # --- Java/Kotlin (Maven / Gradle) ---
    pom = repo_path / "pom.xml"
    if pom.exists():
        try:
            import xml.etree.ElementTree as ET

            root = ET.fromstring(pom.read_text(encoding="utf-8", errors="ignore"))
            ns = {"m": "http://maven.apache.org/POM/4.0.0"}
            deps = root.findall(".//m:dependencies/m:dependency", ns) or root.findall(".//dependency")
            for dep in deps:
                artifact = dep.find("m:artifactId", ns)
                if artifact is None:
                    artifact = dep.find("artifactId")
                scope = dep.find("m:scope", ns)
                if scope is None:
                    scope = dep.find("scope")
                if artifact is not None and artifact.text:
                    is_dev = bool(scope is not None and scope.text == "test")
                    declared[("Maven", artifact.text.strip())] = (True, is_dev)
        except Exception:
            pass
    for gradle_name in ("build.gradle", "build.gradle.kts"):
        gradle = repo_path / gradle_name
        if not gradle.exists():
            continue
        try:
            text = gradle.read_text(encoding="utf-8", errors="ignore")
            for match in re.finditer(
                r"""(?:implementation|api|compile|testImplementation)\s*[\(\s]\s*['"]([\w.\-]+):([\w.\-]+):""",
                text,
            ):
                declared.setdefault(("Maven", match.group(2)), (True, "test" in match.group(0)))
        except OSError:
            pass

    # --- PHP (Composer) ---
    composer = repo_path / "composer.json"
    if composer.exists():
        try:
            doc = json.loads(composer.read_text(encoding="utf-8", errors="ignore"))
            for section in ("require", "require-dev"):
                is_dev = section == "require-dev"
                for name in (doc.get(section) or {}):
                    if name == "php" or name.startswith("ext-"):
                        continue
                    declared[("Packagist", name)] = (True, is_dev)
        except (ValueError, TypeError, OSError):
            pass

    # --- Rust (Cargo) ---
    cargo = repo_path / "Cargo.toml"
    if cargo.exists():
        try:
            text = cargo.read_text(encoding="utf-8", errors="ignore")
            in_deps = False
            for line in text.splitlines():
                stripped = line.strip()
                if stripped.startswith("["):
                    in_deps = stripped.startswith("[dependencies") or stripped.startswith("[dev-dependencies")
                    is_dev_section = "dev-dependencies" in stripped
                    continue
                if not in_deps or not stripped or stripped.startswith("#"):
                    continue
                m = re.match(r"""^([A-Za-z0-9_.\-]+)\s*=""", stripped)
                if m:
                    declared[("crates.io", m.group(1))] = (True, is_dev_section)
        except OSError:
            pass

    # --- .NET (NuGet) ---
    for csproj in repo_path.glob("*.csproj"):
        try:
            import xml.etree.ElementTree as ET

            root = ET.fromstring(csproj.read_text(encoding="utf-8", errors="ignore"))
            for ref in root.findall(".//PackageReference"):
                name = ref.get("Include") or ref.get("Update")
                if name:
                    declared[("NuGet", name)] = (True, False)
        except Exception:
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


def _first_range(vuln: dict, package: str) -> str:
    """Describe the advisory's first range, for display when no installed
    version is available to validate against."""
    for entry in vuln.get("affected", []) or []:
        if not isinstance(entry, dict):
            continue
        name = ((entry.get("package") or {}).get("name") or "").lower()
        if name and name != package.lower():
            continue
        for rng in entry.get("ranges", []) or []:
            if str((rng or {}).get("type", "")).upper() == "GIT":
                continue
            low = high = ""
            for event in (rng or {}).get("events", []) or []:
                if not isinstance(event, dict):
                    continue
                if event.get("introduced"):
                    low = str(event["introduced"])
                if event.get("fixed"):
                    high = str(event["fixed"])
            if low or high:
                return f">={low or '0'}, <{high}" if high else f">={low or '0'}"
    return ""


def parse_osv_vulnerability(vuln: dict, package: str, installed: str = "") -> dict:
    """Pull the version facts and real severity out of an OSV record.

    The vulnerable range reported is the interval the *installed* version
    falls in. An advisory typically carries one range per maintained major
    branch, so quoting the first one prints a range the version is not in.
    """
    if installed:
        match = evaluate(vuln, package, installed)
    else:
        # No installed version to test against (display-only callers). Fall
        # back to describing the advisory's first range rather than returning
        # nothing — but never claim the range was validated.
        match = RangeMatch(True, vulnerable_range=_first_range(vuln, package),
                           reason="no installed version supplied; range not validated")

    fixed = match.fixed_version
    if not fixed:
        # Fall back to the fixed version of the matching branch, if any.
        for entry in vuln.get("affected", []) or []:
            if not isinstance(entry, dict):
                continue
            name = ((entry.get("package") or {}).get("name") or "").lower()
            if name and name != package.lower():
                continue
            for rng in entry.get("ranges", []) or []:
                for event in (rng or {}).get("events", []) or []:
                    if isinstance(event, dict) and event.get("fixed"):
                        candidate = str(event["fixed"])
                        if match.vulnerable_range.endswith(f"<{candidate}"):
                            fixed = candidate
                            break

    return {
        "advisory_id": str(vuln.get("id") or ""),
        "summary": str(vuln.get("summary") or "")[:300],
        "vulnerable_range": match.vulnerable_range,
        "fixed_version": fixed,
        "severity": _osv_severity(vuln),
        "aliases": [str(a) for a in (vuln.get("aliases") or [])][:4],
        "affected": match.affected,
        "range_reason": match.reason,
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


def _dependency_finding(df) -> FindingCandidate:
    """Turn one advisory into a finding whose wording matches the evidence.

    Severity comes from what we established about *this* codebase, not from
    the advisory's own rating: an advisory can be Critical while the affected
    function is never called here.
    """
    label = CLASSIFICATION_LABEL.get(df.classification, "Vulnerable Dependency Present")

    # Shared with the source_findings writer so the two views cannot drift.
    severity = dependency_severity(df.classification, df.severity)

    fixed = df.fixed_version or "no fixed version published"
    remediation = (
        f"Upgrade {df.package} from {df.version} to {fixed}."
        if df.fixed_version
        else f"No patched version is published for {df.package} {df.version}. "
        "Check the advisory for a workaround, or replace the dependency."
    )
    if not df.is_direct:
        remediation += (
            " This is a transitive dependency — update the parent package that "
            "requires it, or pin an override."
        )
    if df.is_development:
        remediation += (
            " It is a development dependency, so it should not be present in a "
            "production build at all."
        )

    evidence_lines = [
        f"Package: {df.package} {df.version} ({df.ecosystem})",
        f"Dependency type: {df.dependency_kind}",
        f"Advisory: {df.advisory_id or 'unknown'}",
        f"Vulnerable range: {df.affected_versions or 'unspecified'}",
        f"Patched version: {fixed}",
        f"Package imported: {'yes' if df.is_used else 'no'}",
        f"Vulnerable functionality named by advisory: "
        + (", ".join(df.vulnerable_symbols[:4]) if df.vulnerable_symbols else "not identified"),
        f"Vulnerable functionality used: {'yes' if df.functionality_used else 'no'}"
        + (f" ({', '.join(df.call_sites[:2])})" if df.call_sites else ""),
        f"Reachable from attacker-controlled input: "
        + (
            f"yes ({', '.join(df.tainted_call_sites[:2])})"
            if df.reachable_from_input
            else "no path found"
        ),
    ]

    impact = CLASSIFICATION_MEANING.get(df.classification, "")
    if df.classification in (DEPENDENCY_PRESENT, FUNCTIONALITY_USED):
        impact += (
            " Keeping it current is good hygiene, but on this evidence it is "
            "not an exploitable vulnerability in this application."
        )

    return FindingCandidate(
        title=f"{label}: {df.package} {df.version}",
        category="dependency_vulnerability",
        severity=severity,
        # Static analysis never confirms exploitability.
        confidence="potential",
        url="",
        evidence="\n".join(evidence_lines),
        response_summary="Software composition analysis (OSV) + reachability",
        description=(
            f"{df.package} {df.version} is affected by {df.advisory_id or 'a published advisory'}"
            + (f": {df.advisory_summary}" if df.advisory_summary else ".")
            + (f" {df.reachability_notes}" if df.reachability_notes else "")
        ),
        impact=impact,
        remediation=remediation,
        dedup_key=f"repo_dep|{df.package}|{df.advisory_id}",
        exploitability=df.classification,
        dependency={
            "package": df.package,
            "version": df.version,
            "ecosystem": df.ecosystem,
            "advisory_id": df.advisory_id,
            "vulnerable_range": df.affected_versions,
            "fixed_version": df.fixed_version,
            "dependency_kind": df.dependency_kind,
            "is_direct": df.is_direct,
            "is_development": df.is_development,
            "is_used": df.is_used,
            "functionality_used": df.functionality_used,
            "reachable_from_input": df.reachable_from_input,
            "vulnerable_symbols": df.vulnerable_symbols[:6],
            "symbols_found": df.symbols_found[:6],
            "call_sites": df.call_sites[:4],
            "tainted_call_sites": df.tainted_call_sites[:4],
            "classification": df.classification,
        },
    )
