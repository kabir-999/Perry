import asyncio
import os
import shutil
import subprocess
import tempfile
import re
import json
from dataclasses import dataclass, field
from pathlib import Path

from app.config import settings
from app.services.dependency_analysis import (
    analyze_usage,
    parse_osv_vulnerability,
    read_declared_dependencies,
)
from app.services.reachability import (
    analyze_reachability,
    classify as classify_reachability,
    extract_vulnerable_symbols,
)
from app.services.repo_discovery import RepoCandidate
from app.services.repo_correlator import SourceFinding, DependencyFinding
from app.services.secret_redactor import SECRET_KEY_PATTERNS, _looks_like_secret, redact_env_values
from app.services.scope import TargetScope

try:
    import git
except ImportError:
    git = None

@dataclass
class RepoAnalysisResult:
    repo: RepoCandidate
    secret_findings: list[SourceFinding] = field(default_factory=list)
    code_findings: list[SourceFinding] = field(default_factory=list)
    dependency_findings: list[DependencyFinding] = field(default_factory=list)
    files_analyzed: int = 0
    status: str = "skipped"  # "completed" | "skipped" | "error"
    error: str = ""


async def analyze_repository(repo: RepoCandidate, scope: TargetScope) -> RepoAnalysisResult:
    """Clone and analyze a public repository for secrets, security issues, and vulnerable dependencies."""
    result = RepoAnalysisResult(repo=repo)
    
    temp_dir = tempfile.mkdtemp(prefix=f"web_fuzzer_{repo.name}_")
    try:
        clone_url = f"https://{repo.provider}.com/{repo.owner}/{repo.name}.git"

        try:
            await asyncio.wait_for(
                asyncio.to_thread(_sparse_clone, clone_url, temp_dir),
                timeout=getattr(settings, "REPO_CLONE_TIMEOUT_SECONDS", 120.0),
            )
        except asyncio.TimeoutError:
            result.status = "error"
            result.error = (
                "Repository download timed out. The repository may be very "
                "large or the network is slow."
            )
            return result
        except Exception as e:
            result.status = "error"
            result.error = _clone_error_message(str(e))
            return result
            
        # Analyze
        repo_path = Path(temp_dir)
        files_to_analyze = _gather_files(repo_path)
        
        # Limit max files
        max_files = getattr(settings, "REPO_MAX_FILES", 500)
        if len(files_to_analyze) > max_files:
            # Sort to prioritize important directories
            files_to_analyze = _prioritize_files(files_to_analyze)[:max_files]
            
        result.files_analyzed = len(files_to_analyze)
        
        # Run analyzers
        result.secret_findings = _scan_secrets(repo_path, files_to_analyze)
        result.code_findings = _scan_code_security(repo_path, files_to_analyze)
        
        # Run SCA concurrently since it makes network requests. Usage analysis
        # needs the same file list, so advisories can be classified by whether
        # the package is actually reachable rather than merely present.
        result.dependency_findings = await _scan_dependencies(
            repo_path, files_to_analyze
        )
        
        result.status = "completed"
        
    finally:
        # Cleanup
        shutil.rmtree(temp_dir, ignore_errors=True)
        
    return result


# Binary/media extensions excluded at fetch time. Keeping them out of the
# working tree is what makes a large repo cloneable at all: SafeOps is 144 MB
# on disk but only ~4 MB of it is source.
_SKIP_BLOB_PATTERNS = [
    "*.mp4", "*.mov", "*.avi", "*.webm", "*.mkv", "*.mp3", "*.wav", "*.flac",
    "*.zip", "*.tar", "*.gz", "*.bz2", "*.7z", "*.rar", "*.dmg", "*.iso",
    "*.png", "*.jpg", "*.jpeg", "*.gif", "*.bmp", "*.tiff", "*.webp", "*.ico",
    "*.psd", "*.ai", "*.sketch", "*.pdf",
    "*.woff", "*.woff2", "*.ttf", "*.eot", "*.otf",
    "*.bin", "*.exe", "*.dll", "*.so", "*.dylib", "*.jar", "*.war",
    "*.pkl", "*.h5", "*.onnx", "*.pt", "*.pth", "*.safetensors", "*.ckpt",
]


def _sparse_clone(clone_url: str, temp_dir: str) -> None:
    """Fetch only the source files, shallow and blobless.

    A plain ``--depth 1`` clone still downloads every binary in the tip commit,
    which is what made large repositories time out. Combining a blobless
    partial clone with a sparse checkout that excludes media and model files
    means git only ever transfers blobs we are going to read.
    """
    def run(*args: str) -> None:
        subprocess.run(
            ["git", *args],
            cwd=temp_dir,
            check=True,
            capture_output=True,
            text=True,
            timeout=getattr(settings, "REPO_CLONE_TIMEOUT_SECONDS", 120.0),
        )

    run("init", "-q", ".")
    run("remote", "add", "origin", clone_url)
    run("sparse-checkout", "init", "--no-cone")
    run("sparse-checkout", "set", "/*", *[f"!{p}" for p in _SKIP_BLOB_PATTERNS])
    run("fetch", "--depth", "1", "--filter=blob:none", "--no-tags", "-q", "origin", "HEAD")
    run("checkout", "-q", "FETCH_HEAD")


def _clone_error_message(raw: str) -> str:
    """Turn a git failure into something the user can act on."""
    lowered = raw.lower()
    if "not found" in lowered or "repository not found" in lowered:
        return (
            "Repository not found. It may be private, renamed, or deleted — "
            "only public repositories can be analyzed."
        )
    if "authentication" in lowered or "could not read username" in lowered:
        return "Repository requires authentication; only public repositories can be analyzed."
    if "timed out" in lowered or "timeout" in lowered:
        return "Repository download timed out. The repository may be very large."
    if "could not resolve host" in lowered or "network" in lowered:
        return "Could not reach the repository host. Check network connectivity."
    return "Could not download the repository for analysis."


def _gather_files(repo_path: Path) -> list[Path]:
    """Gather files to analyze, skipping ignored directories and binary files."""
    skip_dirs = {".git", "node_modules", "dist", "build", "__pycache__", "vendor", "venv", ".venv"}
    skip_exts = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".tar", ".gz", ".mp4", ".woff", ".ttf", ".eot"}
    
    files = []
    for root, dirs, filenames in os.walk(repo_path):
        # Modify dirs in-place to skip ignored directories
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        
        for name in filenames:
            if any(name.lower().endswith(ext) for ext in skip_exts):
                continue
            files.append(Path(root) / name)
            
    return files


def _prioritize_files(files: list[Path]) -> list[Path]:
    """Prioritize source code files over others when truncating the list."""
    def _score(p: Path) -> int:
        score = 0
        p_str = str(p).lower()
        if "src/" in p_str or "app/" in p_str or "api/" in p_str:
            score -= 10
        if p.name in {"package.json", "requirements.txt", ".env", "config.json"}:
            score -= 20
        return score
        
    return sorted(files, key=_score)


def _scan_secrets(repo_path: Path, files: list[Path]) -> list[SourceFinding]:
    """Scan files for hardcoded secrets and env files."""
    findings = []
    
    for file_path in files:
        rel_path = str(file_path.relative_to(repo_path))
        
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
            
        # Specialized env file parsing
        if rel_path.endswith(".env") or ".env." in rel_path:
            is_example = "example" in rel_path.lower()
            lines = content.splitlines()
            for i, line in enumerate(lines):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("=", 1)
                if len(parts) == 2:
                    key, val = [p.strip() for p in parts]
                    val_lower = val.lower()
                    is_placeholder = (
                        not val
                        or val_lower in ("null", "none", "true", "false")
                        or "your_" in val_lower
                        or "changeme" in val_lower
                        or val_lower == "example"
                        or val_lower == "test"
                    )
                    
                    if not is_placeholder and (SECRET_KEY_PATTERNS.search(key) or _looks_like_secret(val)):
                        # Only flag .env.example if it has real-looking secrets (entropy/patterns)
                        if is_example and not _looks_like_secret(val):
                            continue
                            
                        findings.append(
                            SourceFinding(
                                finding_type="env_secret",
                                file=rel_path,
                                line=i+1,
                                severity="critical",
                                confidence="high",
                                evidence=f"{key}=[REDACTED]",
                                secret_type=key,
                                redacted_value="[REDACTED]",
                                code_context=f"{key}=[REDACTED]"
                            )
                        )
            continue
            
        # General secret scanning for code files
        # Look for pattern: KEY = "VALUE" or "KEY": "VALUE"
        lines = content.splitlines()
        for i, line in enumerate(lines):
            # Very basic regex for variable assignment
            # e.g., const API_KEY = "sk_live_123456789";
            match = re.search(r'(?i)(?:api[_-]?key|secret|password|token)\s*[:=]\s*(["\'])([^"\']+)\1', line)
            if match:
                key_context = line[:match.start(2)].strip()
                val = match.group(2)
                
                val_lower = val.lower()
                is_placeholder = (
                    not val
                    or "your_" in val_lower
                    or "changeme" in val_lower
                    or val_lower == "example"
                )
                
                if not is_placeholder and _looks_like_secret(val):
                    redacted_line = line.replace(val, "[REDACTED]")
                    findings.append(
                        SourceFinding(
                            finding_type="hardcoded_secret",
                            file=rel_path,
                            line=i+1,
                            severity="critical",
                            confidence="high",
                            evidence=redacted_line.strip(),
                            secret_type="Hardcoded Secret",
                            redacted_value="[REDACTED]",
                            code_context=redacted_line.strip()
                        )
                    )
                    
    return findings


def _scan_code_security(repo_path: Path, files: list[Path]) -> list[SourceFinding]:
    """Scan code for common security anti-patterns."""
    findings = []
    
    _PATTERNS = [
        # SQL Injection (string concat in queries)
        (re.compile(r'(?i)SELECT\s+.*?\s+FROM\s+.*?\s+WHERE\s+.*?\s*[=<>]\s*(?:"\s*\+\s*\w+|\w+\s*\+\s*")'), "sql_injection", "high", "SQL Injection pattern (string concatenation in query)"),
        # Command Injection
        (re.compile(r'(?i)(?:exec|system|popen|subprocess\.call|eval)\s*\([^)]*\w+\s*\+\s*\w+[^)]*\)'), "command_injection", "high", "Command Injection pattern (unsafe execution)"),
        # Weak Crypto
        (re.compile(r'(?i)md5\s*\(|sha1\s*\('), "weak_crypto", "low", "Weak cryptographic hash function (MD5/SHA1)"),
    ]
    
    for file_path in files:
        rel_path = str(file_path.relative_to(repo_path))
        
        # Skip non-code files
        if not rel_path.endswith((".py", ".js", ".ts", ".java", ".go", ".php", ".rb")):
            continue
            
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
            
        lines = content.splitlines()
        for i, line in enumerate(lines):
            line_str = line.strip()
            if not line_str or line_str.startswith(("//", "#")):
                continue
                
            for pattern, finding_type, severity, desc in _PATTERNS:
                if pattern.search(line_str):
                    # Redact any secrets in the line before saving
                    safe_line = redact_env_values(line_str)
                    findings.append(
                        SourceFinding(
                            finding_type=finding_type,
                            file=rel_path,
                            line=i+1,
                            severity=severity,
                            confidence="potential",
                            evidence=safe_line,
                            secret_type="",
                            redacted_value="",
                            code_context=safe_line
                        )
                    )
                    
    return findings


async def _scan_dependencies(
    repo_path: Path, files: list[Path]
) -> list[DependencyFinding]:
    """Scan declared dependencies against OSV.dev, then establish reachability.

    An advisory alone says nothing about this application. Each hit is passed
    through usage analysis so the report can distinguish a package that is
    merely present from one that request-handling code actually imports.
    """
    findings: list[DependencyFinding] = []
    declared = read_declared_dependencies(repo_path)

    # Check package.json
    pkg_json_path = repo_path / "package.json"
    if pkg_json_path.exists():
        try:
            pkg = json.loads(pkg_json_path.read_text(encoding="utf-8"))
            deps = pkg.get("dependencies", {})
            dev_deps = pkg.get("devDependencies", {})
            all_deps = {**deps, **dev_deps}
            findings.extend(
                await _query_osv("npm", all_deps, repo_path, files, declared)
            )
        except Exception:
            pass

    # Check requirements.txt
    req_txt_path = repo_path / "requirements.txt"
    if req_txt_path.exists():
        try:
            content = req_txt_path.read_text(encoding="utf-8")
            deps = {}
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = re.split(r'[=><~]+', line)
                    if len(parts) >= 2:
                        deps[parts[0].strip()] = parts[1].strip()

            findings.extend(
                await _query_osv("PyPI", deps, repo_path, files, declared)
            )
        except Exception:
            pass

    return findings


async def _query_osv(
    ecosystem: str,
    deps: dict[str, str],
    repo_path: Path,
    files: list[Path],
    declared: dict,
) -> list[DependencyFinding]:
    """Query OSV.dev for known advisories affecting the pinned versions."""
    findings: list[DependencyFinding] = []
    if not deps:
        return findings

    import httpx

    # We query sequentially to avoid rate limits, OSV allows batch queries but it's complex
    # For a simple implementation, we'll just check a max of 20 dependencies
    items = list(deps.items())[:20]

    async with httpx.AsyncClient() as client:
        for package, version in items:
            # Clean up version string (remove ^, ~, etc.)
            clean_version = re.sub(r'^[^\d]+', '', version)
            if not clean_version:
                continue

            payload = {
                "version": clean_version,
                "package": {
                    "name": package,
                    "ecosystem": ecosystem
                }
            }

            try:
                # OSV API
                res = await client.post("https://api.osv.dev/v1/query", json=payload, timeout=5.0)
                if res.status_code != 200:
                    continue
                vulns = res.json().get("vulns", [])
            except Exception:
                continue

            if not vulns:
                continue

            # Reachability is a property of the package, so it is established
            # once and shared by every advisory against it.
            usage = analyze_usage(repo_path, files, package, ecosystem, declared)

            for vuln in vulns:
                details = parse_osv_vulnerability(vuln, package)

                # Which functionality does the advisory actually blame, and can
                # request data reach it? Neither is inferred from the import.
                symbols = extract_vulnerable_symbols(
                    f"{details['summary']} {vuln.get('details') or ''}", package
                )
                reach = analyze_reachability(
                    repo_path, files, package, symbols, usage.runtime_import_files
                )
                classification = classify_reachability(reach, is_used=usage.is_used)
                findings.append(
                    DependencyFinding(
                        package=package,
                        version=clean_version,
                        ecosystem=ecosystem,
                        advisory_id=details["advisory_id"],
                        # Advisory severity when OSV states one; otherwise
                        # "medium" as a neutral placeholder rather than
                        # assuming the worst.
                        severity=details["severity"] or "medium",
                        affected_versions=details["vulnerable_range"] or version,
                        fixed_version=details["fixed_version"],
                        source="osv",
                        classification=classification,
                        is_direct=usage.is_direct,
                        is_development=usage.is_development,
                        dependency_kind=usage.dependency_kind(),
                        is_used=usage.is_used,
                        functionality_used=reach.functionality_used,
                        reachable_from_input=reach.reachable_from_input,
                        vulnerable_symbols=list(reach.symbols_searched),
                        symbols_found=list(reach.symbols_found),
                        call_sites=list(reach.call_sites),
                        tainted_call_sites=list(reach.tainted_call_sites),
                        import_sites=list(usage.import_sites),
                        advisory_summary=details["summary"],
                        usage_notes=usage.notes,
                        reachability_notes=reach.notes,
                    )
                )
                # One advisory per package keeps the report readable.
                break

    return findings
