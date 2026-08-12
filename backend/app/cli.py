"""
Sentinel CLI — repository scanning for local development and CI.

    sentinel scan .
    sentinel scan . --fail-on high --json sentinel-report.json

Runs the same Sentinel Core the web dashboard uses: the AST-based SAST engine,
secret detection, and dependency analysis with strict version-range validation
and reachability. Scoring is the same deterministic Sentinel Risk Model, so a
CI run and a dashboard scan of the same code produce the same number.

No network target is involved, so no ownership verification applies — the
developer ran this against a checkout they already have.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from app.services.finding_types import FindingCandidate
from app.services.repo_analyzer import (
    _gather_files,
    _prioritize_files,
    _sast_findings,
    _scan_dependencies,
    _scan_secrets,
)
from app.services.risk_model import calculate_sentinel_risk
from app.services.severity_policy import apply_policy

# Exit codes: 0 clean, 1 gate failed, 2 usage/error.
EXIT_OK, EXIT_GATE_FAILED, EXIT_ERROR = 0, 1, 2

_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def _to_finding(sf, category: str) -> FindingCandidate:
    """Express a source finding in the standard Sentinel finding structure."""
    return FindingCandidate(
        title=f"{sf.finding_type.replace('_', ' ').title()} in {sf.file}",
        category=category,
        severity=sf.severity,
        confidence=sf.confidence,
        url="",
        parameter=sf.file,
        evidence=sf.evidence,
        description=sf.code_context,
        dedup_key=f"{sf.finding_type}|{sf.file}|{sf.line}",
    )


async def scan_path(root: Path, *, skip_deps: bool = False) -> dict:
    """Analyse a checkout and return findings plus the deterministic score."""
    files = _gather_files(root)
    if len(files) > 2000:
        files = _prioritize_files(files)[:2000]

    secrets = _scan_secrets(root, files)
    code = _sast_findings(root, files)
    deps = [] if skip_deps else await _scan_dependencies(root, files)

    findings: list[FindingCandidate] = []
    findings += [_to_finding(s, "information_exposure") for s in secrets]
    findings += [_to_finding(c, "code_security") for c in code]

    from app.services.deep_scan import _dependency_finding

    findings += [_dependency_finding(d) for d in deps]

    # Same evidence-based normalisation the web pipeline applies.
    apply_policy(findings)
    risk = calculate_sentinel_risk(findings)

    counts = {level: 0 for level in _SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    return {
        "files_analyzed": len(files),
        "counts": counts,
        "risk": risk,
        "findings": [
            {
                "title": f.title,
                "severity": f.severity,
                "confidence": f.confidence,
                "category": f.category,
                "location": f.parameter,
                "evidence": (f.evidence or "")[:600],
                "remediation": f.remediation,
            }
            for f in findings
        ],
    }


def _gate(result: dict, fail_on: str | None, max_risk: int | None) -> tuple[bool, str]:
    """Decide whether the build should fail, and say precisely why."""
    counts = result["counts"]
    score = result["risk"]["score"]

    if fail_on:
        threshold = _SEVERITY_ORDER.index(fail_on)
        for level in _SEVERITY_ORDER[threshold:]:
            if counts.get(level, 0):
                return False, (
                    f"{counts[level]} {level}-severity finding(s) at or above "
                    f"the configured '{fail_on}' threshold."
                )
    if max_risk is not None and score > max_risk:
        return False, f"Risk score {score} exceeds the configured maximum of {max_risk}."
    return True, ""


def _render(result: dict, passed: bool, reason: str) -> str:
    counts = result["counts"]
    risk = result["risk"]
    lines = [
        "",
        "Sentinel Security Gate",
        "",
        f"Critical: {counts.get('critical', 0)}",
        f"High: {counts.get('high', 0)}",
        f"Medium: {counts.get('medium', 0)}",
        f"Low: {counts.get('low', 0)}",
        "",
        f"Risk: {risk['score']}/100 {risk['severity']}",
        f"Files analyzed: {result['files_analyzed']}",
        "",
        f"Status: {'PASSED' if passed else 'FAILED'}",
    ]
    if not passed:
        lines += ["", "Reason:", reason]
    if risk.get("contributors"):
        lines += ["", "Top contributors:"]
        for c in risk["contributors"][:5]:
            detail = (
                f"CVSS v4.0 {c['cvss']['base_score']} {c['cvss']['severity']}"
                if c.get("cvss")
                else f"Hardening ({c['hardening']['rule']})"
                if c.get("hardening")
                else "Informational"
            )
            lines.append(f"  - {c['title']}  [{detail}]")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a repository or directory")
    scan.add_argument("path", nargs="?", default=".", help="Directory to scan")
    scan.add_argument(
        "--fail-on", choices=_SEVERITY_ORDER,
        help="Fail the build at or above this severity",
    )
    scan.add_argument("--max-risk", type=int, help="Fail if the risk score exceeds this")
    scan.add_argument("--json", dest="json_out", help="Write machine-readable output here")
    scan.add_argument("--skip-deps", action="store_true",
                      help="Skip dependency analysis (no network calls)")
    scan.add_argument("--quiet", action="store_true", help="Only print the gate result")

    args = parser.parse_args(argv)

    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"sentinel: {root} is not a directory", file=sys.stderr)
        return EXIT_ERROR

    try:
        result = asyncio.run(scan_path(root, skip_deps=args.skip_deps))
    except KeyboardInterrupt:
        return EXIT_ERROR

    passed, reason = _gate(result, args.fail_on, args.max_risk)
    result["gate"] = {"passed": passed, "reason": reason}

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(result, indent=2), encoding="utf-8")

    if not args.quiet:
        print(_render(result, passed, reason))
    else:
        print(f"Sentinel: {result['risk']['score']}/100 "
              f"{'PASSED' if passed else 'FAILED'}")

    return EXIT_OK if passed else EXIT_GATE_FAILED


if __name__ == "__main__":
    raise SystemExit(main())
