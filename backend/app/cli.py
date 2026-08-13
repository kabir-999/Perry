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

Two independent gates decide the exit code:

    Severity Gate  — did any finding meet/exceed --fail-on?
    Risk Gate      — did the overall risk score exceed --max-risk?

A low overall risk score never overrides a failed severity gate, and vice
versa: each gate is evaluated and reported on its own.
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

# Exit codes: 0 all configured gates passed, 1 a gate failed, 2 usage/error.
EXIT_OK, EXIT_GATE_FAILED, EXIT_ERROR = 0, 1, 2

_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

# Display taxonomy shown to the user/CI logs. This is presentation only — it
# never changes scoring, dedup, or the underlying `category` field used
# elsewhere in the pipeline.
_CATEGORY_DISPLAY = {
    "code_security": "Code Vulnerability",
    "input_validation": "Code Vulnerability",
    "source_correlation": "Code Vulnerability",
    "dependency_vulnerability": "Dependency Vulnerability",
    "information_exposure": "Secret Exposure",
    "security_headers": "Security Misconfiguration",
    "configuration": "Security Misconfiguration",
    "attack_surface": "Attack Surface",
    "authentication": "Authentication",
    "authorization": "Authorization",
}


def _display_category(category: str, *, hygiene: bool = False) -> str:
    if hygiene:
        return "Secret Hygiene"
    return _CATEGORY_DISPLAY.get(category, "Security Hardening")


_HYGIENE_NOTE = (
    "File is already covered by .gitignore.\n"
    "                No repository exposure was detected.\n"
    "                Reported for hygiene purposes only."
)


def _to_finding(sf, category: str) -> FindingCandidate:
    """Express a source finding in the standard Sentinel finding structure."""
    hygiene = getattr(sf, "local_only", False)
    # A hygiene-only secret must not be matched by the risk model's
    # vuln-class lookup (which keys off this prefix and would otherwise
    # score it with a full CVSS vector regardless of severity) — prefixing
    # it keeps the finding informational, i.e. zero risk-score contribution.
    key_prefix = f"hygiene_{sf.finding_type}" if hygiene else sf.finding_type
    return FindingCandidate(
        title=f"{sf.finding_type.replace('_', ' ').title()} in {sf.file}",
        category=category,
        severity=sf.severity,
        confidence=sf.confidence,
        url="",
        parameter=sf.file,
        evidence=sf.evidence,
        description=sf.code_context,
        dedup_key=f"{key_prefix}|{sf.file}|{sf.line}",
    )


async def scan_path(root: Path, *, skip_deps: bool = False) -> dict:
    """Analyse a checkout and return findings plus the deterministic score."""
    files = _gather_files(root)
    if len(files) > 2000:
        files = _prioritize_files(files)[:2000]

    secrets = _scan_secrets(root, files)
    code = _sast_findings(root, files)
    deps = [] if skip_deps else await _scan_dependencies(root, files)

    secret_findings = [_to_finding(s, "information_exposure") for s in secrets]

    # Secrets are already redacted at the source (`SourceFinding.evidence`/
    # `code_context` never contain the raw value) — this map only carries the
    # secret *type*, *location*, and hygiene status through for display,
    # never the value. Keyed by the finding's own dedup_key (rather than
    # rebuilding it) so it stays correct if _to_finding's key format changes.
    secret_meta = {
        f.dedup_key: {
            "secret_type": s.secret_type,
            "location": f"{s.file}:{s.line}",
            "hygiene": getattr(s, "local_only", False),
        }
        for s, f in zip(secrets, secret_findings)
    }

    findings: list[FindingCandidate] = []
    findings += secret_findings
    findings += [_to_finding(c, "code_security") for c in code]

    from app.services.deep_scan import _dependency_finding

    findings += [_dependency_finding(d) for d in deps]

    # Same evidence-based normalisation the web pipeline applies.
    apply_policy(findings)
    risk = calculate_sentinel_risk(findings)

    counts = {level: 0 for level in _SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    out_findings = []
    for f in findings:
        meta = secret_meta.get(f.dedup_key)
        hygiene = bool(meta and meta.get("hygiene"))
        entry = {
            "dedup_key": f.dedup_key,
            "title": f.title,
            "severity": f.severity,
            "confidence": f.confidence,
            "category": f.category,
            "category_display": _display_category(f.category, hygiene=hygiene),
            "location": meta["location"] if meta else f.parameter,
            "evidence": (f.evidence or "")[:600],
            "remediation": f.remediation,
        }
        if meta:
            entry["secret_type"] = meta["secret_type"]
        if hygiene:
            entry["status"] = "IGNORED_NOT_EXPOSED"
            entry["note"] = (
                "File is already covered by .gitignore. No repository "
                "exposure was detected. Reported for hygiene purposes only."
            )
        out_findings.append(entry)

    return {
        "files_analyzed": len(files),
        "counts": counts,
        "risk": risk,
        "findings": out_findings,
    }


def _severity_gate(counts: dict, fail_on: str | None) -> tuple[dict, str | None]:
    """Evaluate the severity gate independently of risk score."""
    if not fail_on:
        return {"threshold": None, "status": "PASSED", "violations": 0}, None

    idx = _SEVERITY_ORDER.index(fail_on)
    violating = [(level, counts.get(level, 0)) for level in reversed(_SEVERITY_ORDER[idx:]) if counts.get(level, 0)]
    total = sum(c for _, c in violating)

    gate = {"threshold": fail_on.upper(), "status": "FAILED" if total else "PASSED", "violations": total}
    if not violating:
        return gate, None

    parts = ", ".join(f"{c} {level.upper()}" for level, c in violating)
    noun = "finding" if total == 1 else "findings"
    verb = "meets/exceeds" if total == 1 else "meet/exceed"
    reason = f"{parts} {noun} {verb} the configured {fail_on.upper()} threshold."
    return gate, reason


def _risk_gate(score: int, max_risk: int | None) -> tuple[dict, str | None]:
    """Evaluate the risk-score gate independently of severity."""
    if max_risk is None:
        return {"maximum": None, "status": "PASSED", "score": score}, None

    if score > max_risk:
        gate = {"maximum": max_risk, "status": "FAILED", "score": score}
        return gate, f"{score}/100 exceeds the configured maximum of {max_risk}."

    return {"maximum": max_risk, "status": "PASSED", "score": score}, None


def _render(result: dict, severity_gate: dict, sev_reason: str | None,
            risk_gate: dict, risk_reason: str | None, overall_passed: bool) -> str:
    counts = result["counts"]
    risk = result["risk"]

    lines = [
        "",
        "Sentinel Security Gate",
        "",
        "Findings",
        "────────",
        f"Critical: {counts.get('critical', 0)}",
        f"High:     {counts.get('high', 0)}",
        f"Medium:   {counts.get('medium', 0)}",
        f"Low:      {counts.get('low', 0)}",
        f"Info:     {counts.get('info', 0)}",
        "",
        "Risk Score",
        "──────────",
        f"{risk['score']}/100 {risk['severity']}",
        "",
        f"Files analyzed: {result['files_analyzed']}",
        "",
        "Security Gates",
        "──────────────",
    ]

    if severity_gate["threshold"] is None:
        lines.append("Severity Gate: PASSED (not configured)")
    else:
        lines.append(f"Severity Gate: {severity_gate['status']}")
        lines.append(f"  {sev_reason}" if sev_reason else
                      f"  No findings at or above the configured {severity_gate['threshold']} threshold.")

    lines.append("")

    if risk_gate["maximum"] is None:
        lines.append("Risk Gate: PASSED (not configured)")
    else:
        lines.append(f"Risk Gate: {risk_gate['status']}")
        lines.append(f"  {risk_reason}" if risk_reason else
                      f"  {risk_gate['score']}/100 <= configured maximum {risk_gate['maximum']}.")

    lines += ["", f"Status: {'PASSED' if overall_passed else 'FAILED'}"]

    if not overall_passed:
        reasons = [r for r in (sev_reason, risk_reason) if r]
        if len(reasons) > 1:
            lines += ["", "Reasons:"]
            lines += [f"- {r}" for r in reasons]
        else:
            lines += ["", "Reason:", reasons[0]]

    findings_by_key = {f["dedup_key"]: f for f in result["findings"] if f["dedup_key"]}
    findings_by_title = {f["title"]: f for f in result["findings"]}

    if risk.get("contributors"):
        lines += ["", "Top Contributors", "─────────────────"]
        for c in risk["contributors"][:5]:
            info = findings_by_key.get(c["finding_id"]) or findings_by_title.get(c["finding_id"])
            severity_label = info["severity"].upper() if info else "INFO"
            hygiene = bool(info and info.get("status") == "IGNORED_NOT_EXPOSED")
            category_display = (
                _display_category(info["category"], hygiene=hygiene)
                if info else "Security Hardening"
            )

            lines.append(f"{severity_label:<9} {c['title']}")
            if c.get("cvss"):
                lines.append(f"          CVSS v4.0: {c['cvss']['base_score']}")
            if info and info.get("secret_type"):
                lines.append(f"          Type: {info['secret_type']}")
                lines.append(f"          Location: {info['location']}")
            lines.append(f"          Category: {category_display}")
            if hygiene:
                lines.append("          Status: IGNORED / NOT EXPOSED")
                lines.append(f"          Note: {_HYGIENE_NOTE}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a repository or directory")
    scan.add_argument("path", nargs="?", default=".", help="Directory to scan")
    scan.add_argument(
        "--fail-on", choices=_SEVERITY_ORDER,
        help="Fail the severity gate at or above this severity",
    )
    scan.add_argument("--max-risk", type=int, help="Fail the risk gate if the score exceeds this")
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

    score = result["risk"]["score"]
    severity_gate, sev_reason = _severity_gate(result["counts"], args.fail_on)
    risk_gate, risk_reason = _risk_gate(score, args.max_risk)
    overall_passed = severity_gate["status"] == "PASSED" and risk_gate["status"] == "PASSED"

    result["gates"] = {
        "severity": severity_gate,
        "risk": risk_gate,
        "overall": "PASSED" if overall_passed else "FAILED",
    }
    result["risk_score"] = score
    result["risk_level"] = result["risk"]["severity"]
    result["exit_code"] = EXIT_OK if overall_passed else EXIT_GATE_FAILED

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(result, indent=2), encoding="utf-8")

    if not args.quiet:
        print(_render(result, severity_gate, sev_reason, risk_gate, risk_reason, overall_passed))
    else:
        print(f"Sentinel: {score}/100 {'PASSED' if overall_passed else 'FAILED'}")

    return result["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
