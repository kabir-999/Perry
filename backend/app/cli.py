"""
Perry CLI — repository scanning for local development and CI.

    Perry scan .
    Perry scan . --fail-on high --json Perry-report.json

Runs the same Perry Core the web dashboard uses: the AST-based SAST engine,
secret detection, and dependency analysis with strict version-range validation
and reachability. Scoring is the same deterministic Perry Risk Model, so a
CI run and a dashboard scan of the same code produce the same number.

No network target is involved, so no ownership verification applies — the
developer ran this against a checkout they already have.

Two independent gates decide the exit code:

    Severity Gate  — did any finding meet/exceed --fail-on?
    Risk Gate      — did the overall risk score exceed --max-risk?

A low overall risk score never overrides a failed severity gate, and vice
versa: each gate is evaluated and reported on its own.

A second subcommand, `custom-test`, runs user-defined test cases against a
*live* URL (unlike `scan`, this does send network requests) — see its own
docstring below for the authorization gate this requires.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from pydantic import ValidationError

from app.services.finding_types import FindingCandidate
from app.services.repo_analyzer import (
    _gather_files,
    _prioritize_files,
    _sast_findings,
    _scan_dependencies,
    _scan_secrets,
)
from app.services.risk_engine import level_for_score, overall_confirmed_risk, score_all
from app.services.severity_policy import apply_policy


def _risk_from_findings(findings: list[FindingCandidate]) -> dict:
    """Deterministic 5-factor risk for the CLI, matching the web pipeline's one
    risk model: each finding scored by ``risk_engine`` and the overall score =
    the highest confirmed/validated finding's score. Returns a dict shaped for
    the report renderer (``score``/``severity``/``contributors``)."""
    score_all(findings)  # sets f.risk_score in place (5-factor formula)
    score = overall_confirmed_risk(findings)
    ranked = sorted(findings, key=lambda f: f.risk_score, reverse=True)
    contributors = [
        {"finding_id": f.dedup_key or f.title, "title": f.title,
         "contribution": round(f.risk_score, 1)}
        for f in ranked[:5]
    ]
    return {"score": score, "severity": level_for_score(score).upper(),
            "contributors": contributors}

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
    """Express a source finding in the standard Perry finding structure."""
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

    from app.services.sast_engine import compute_language_coverage

    languages = compute_language_coverage(root, files)

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

    from app.services.dependency_analysis import _dependency_finding

    findings += [_dependency_finding(d) for d in deps]

    # Same evidence-based normalisation the web pipeline applies.
    apply_policy(findings)
    risk = _risk_from_findings(findings)

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
        "languages": languages,
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
        "Perry Security Gate",
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
    ]

    languages = result.get("languages") or {}
    if languages:
        lines += ["Languages", "─────────"]
        for label, info in sorted(languages.items()):
            if info["files_skipped"]:
                lines.append(
                    f"{label}: {info['files_found']} file(s) found, "
                    f"{info['files_skipped']} skipped ({info['skip_reason']})"
                )
            else:
                lines.append(f"{label}: {info['files_analyzed']} file(s) analyzed")
        lines.append("")

    lines += [
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


# --------------------------------------------------------------------------
# custom-test — user-defined test cases against a live URL
# --------------------------------------------------------------------------
#
# Unlike `scan`, this sends real requests to a target you don't necessarily
# have a local checkout of, so the same authorization gate the web app
# enforces applies here too: either an explicit --authorized flag (for
# CI/CD, where nothing can block on a prompt) or an interactive Y/N
# confirmation. Refuses to send anything without one or the other — never
# assumes consent.

# Reserved keys in the shorthand syntax: everything else the developer
# writes becomes a request field (e.g. a login form's `name`/`password`).
# Deliberately does NOT include "name" — that's exactly as likely to be a
# real form field (a login form's username input, per the whole reason this
# shorthand exists) as it is to mean "the test's own title", so a preset
# spec's title is always auto-generated instead of reserving it.
_PRESET_RESERVED_KEYS = {"attack", "path", "method", "location", "target", "severity"}
_STRICT_KEY_ALIASES = {
    "payload": "test", "value": "test", "param": "input", "field": "input",
}

_SHORTHAND_HELP = (
    'A test is one comma-separated line of key=value pairs (":" or "-" also '
    "work as the separator). Two shapes:\n\n"
    "  Attack preset — pick a known attack, list your other fields (any key\n"
    "  except attack/path/method/location/target/severity is sent as a\n"
    "  request field — e.g. a login form's own \"name\"/\"password\"):\n"
    "    attack=sql injection, path=/products, id=1\n"
    "    attack=sql injection, path=/login, method=POST, name=kabir, password=1234\n"
    f"    (known attacks: {', '.join(sorted({'sqli', 'xss', 'traversal', 'cmd'}))} — aliases accepted)\n"
    "    Defaults to GET+query unless method=POST/PUT/... is given; the\n"
    "    payload tries each field in turn, or just `target=<field>` if set.\n\n"
    "  Fully custom — name your own validation condition:\n"
    "    name=Admin exposed, path=/admin, input=x, test=1, expected=contains:No auth\n"
)


def _isatty() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def _prompt_yes_no(question: str, *, default: bool = False) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    answer = input(f"{question} {suffix}: ").strip().lower()
    if not answer:
        return default
    return answer in ("y", "yes")


def _parse_kv_line(line: str) -> dict[str, str]:
    """Parse "attack=sql injection, name=kabir, password=1234" into a flat
    dict — lenient on purpose (accepts "=", ":", or "-" between key and
    value) so a developer can write a test case without hand-rolling JSON."""
    result: dict[str, str] = {}
    for token in line.split(","):
        token = token.strip()
        if not token or token.startswith("#"):
            continue
        best_idx = None
        for ch in ("=", ":", "-"):
            idx = token.find(ch)
            if idx > 0 and (best_idx is None or idx < best_idx):
                best_idx = idx
        if best_idx is None:
            continue
        key = token[:best_idx].strip().lower().replace(" ", "_")
        value = token[best_idx + 1:].strip()
        if key and value:
            result[key] = value
    return result


def _spec_from_shorthand(parsed: dict) -> tuple[str, dict]:
    """Classify one parsed line as an attack-preset spec or a fully-custom
    (strict-schema) spec, and fill in the shape each execution path expects."""
    if "attack" in parsed:
        fields = {k: v for k, v in parsed.items() if k not in _PRESET_RESERVED_KEYS}
        # Defaulting to POST whenever fields were given guessed wrong for
        # any GET-based endpoint that takes its data via the query string
        # (very common for the kind of ?id=/?q= surface this is often
        # pointed at) — GET+query is the safer, more broadly-correct
        # default; a real login form needs an explicit method=POST anyway.
        method = parsed.get("method", "").upper() or "GET"
        location = parsed.get("location") or ("query" if method == "GET" else "form")
        spec = {
            "attack": parsed["attack"],
            "path": parsed.get("path", ""),
            "method": method,
            "location": location,
            "target": parsed.get("target"),
            "severity": parsed.get("severity"),
            "name": f"{parsed['attack']} on {parsed.get('path', '?')}",
            "fields": fields,
        }
        return "preset", spec

    raw = {}
    for key, value in parsed.items():
        raw[_STRICT_KEY_ALIASES.get(key, key)] = value
    raw.setdefault("name", f"Custom test on {raw.get('path', '?')}")
    return "strict", raw


def _collect_custom_tests_interactively() -> tuple[list[dict], list[dict], list[str]]:
    print(_SHORTHAND_HELP)
    preset_specs: list[dict] = []
    strict_raw: list[dict] = []
    raw_lines: list[str] = []
    while True:
        line = input(f"Test #{len(raw_lines) + 1}: ").strip()
        if line:
            kind, spec = _spec_from_shorthand(_parse_kv_line(line))
            (preset_specs if kind == "preset" else strict_raw).append(spec)
            raw_lines.append(line)
        if not _prompt_yes_no("Add another custom test?", default=False):
            break
    return preset_specs, strict_raw, raw_lines


def _load_custom_tests_from_file(path: Path) -> tuple[list[dict], list[dict]]:
    """A test file is either one JSON array of strict-schema objects (the
    original format), or plain text with one shorthand line per test —
    whichever it is, detected automatically."""
    text = path.read_text(encoding="utf-8")
    try:
        raw = json.loads(text)
    except json.JSONDecodeError:
        preset_specs, strict_raw = [], []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            kind, spec = _spec_from_shorthand(_parse_kv_line(line))
            (preset_specs if kind == "preset" else strict_raw).append(spec)
        return preset_specs, strict_raw

    return [], (raw if isinstance(raw, list) else [raw])


def _validate_preset_specs(specs: list[dict]):
    from app.services.custom_tests import known_attack_names, resolve_attack_preset

    validated, errors = [], []
    for i, spec in enumerate(specs):
        if not spec.get("path"):
            errors.append(f"Attack test #{i + 1} ({spec['attack']}): missing 'path'.")
            continue
        if resolve_attack_preset(spec["attack"]) is None:
            errors.append(
                f"Attack test #{i + 1}: unknown attack '{spec['attack']}'. "
                f"Known: {', '.join(known_attack_names())}."
            )
            continue
        validated.append(spec)
    return validated, errors


def _validate_custom_tests(raw_cases: list[dict]):
    from app.schemas.scan import CustomTestCase

    validated = []
    errors = []
    for i, raw in enumerate(raw_cases):
        try:
            validated.append(CustomTestCase(**raw))
        except ValidationError as exc:
            errors.append(f"Test #{i + 1} ({raw.get('name', '?')}): {exc}")
    return validated, errors


async def run_all_custom_tests(url: str, strict_cases: list, preset_specs: list[dict]) -> dict:
    """Send every validated custom test (both shapes) at the live target and
    collect findings. Mirrors the web pipeline's custom_tests module exactly
    — same scope-checking, same evidence-based validation, no separate
    engine for either shape."""
    from app.config import settings
    from app.services import custom_tests as custom_tests_module
    from app.services.http_client import Fetcher, build_async_client
    from app.services.scope import build_scope

    scope = build_scope(url)
    client = build_async_client(
        timeout=settings.DEFAULT_REQUEST_TIMEOUT_SECONDS,
        connect_timeout=settings.FAST_CONNECT_TIMEOUT_SECONDS,
        max_connections=settings.HTTP_MAX_CONNECTIONS,
        max_keepalive=settings.HTTP_MAX_KEEPALIVE,
    )
    fetcher = Fetcher(
        client,
        concurrency=settings.DEFAULT_CONCURRENCY,
        request_budget=settings.DEFAULT_MAX_REQUESTS,
        max_response_bytes=settings.DEFAULT_MAX_RESPONSE_BYTES,
    )
    try:
        strict_dicts = [c.model_dump() for c in strict_cases]
        findings = await custom_tests_module.run_custom_tests(fetcher, scope, strict_dicts)
        findings += await custom_tests_module.run_attack_preset_tests(fetcher, scope, preset_specs)
    finally:
        await client.aclose()

    # Same evidence-based normalisation the web pipeline applies — a
    # declared severity can still be capped if it isn't actually earned.
    apply_policy(findings)

    all_names = [c.name for c in strict_cases] + [s["name"] for s in preset_specs]
    # Match on dedup_key, not .title — severity_policy.apply_policy rewrites
    # titles that make an unconfirmed attack claim (e.g. "SQL injection" ->
    # "possible SQL injection pattern"), which would break a title-based
    # lookup for exactly the common case (an unconfirmed preset finding).
    # Both custom_tests.py finding shapes embed the original spec/case name
    # as the dedup_key's 2nd "|"-segment specifically so it survives that.
    fired_names = set()
    for f in findings:
        parts = (f.dedup_key or "").split("|")
        if len(parts) > 1:
            fired_names.add(parts[1])
    results = [
        {"name": name, "status": "FINDING" if name in fired_names else "PASS"}
        for name in all_names
    ]

    counts = {level: 0 for level in _SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    return {
        "target": scope.origin,
        "tests_run": len(all_names),
        "results": results,
        "counts": counts,
        "findings": [
            {
                "name": f.title,
                "severity": f.severity,
                "confidence": f.confidence,
                "url": f.url,
                "parameter": f.parameter,
                "evidence": f.evidence,
                "description": f.description,
            }
            for f in findings
        ],
    }


def _render_custom_test_report(result: dict, gate: dict, reason: str | None, passed: bool) -> str:
    counts = result["counts"]
    lines = [
        "",
        "Perry Custom Test Report",
        "",
        f"Target: {result['target']}",
        f"Tests run: {result['tests_run']}",
        "",
        "Findings",
        "────────",
        f"Critical: {counts.get('critical', 0)}",
        f"High:     {counts.get('high', 0)}",
        f"Medium:   {counts.get('medium', 0)}",
        f"Low:      {counts.get('low', 0)}",
        f"Info:     {counts.get('info', 0)}",
        "",
    ]
    if gate["threshold"] is None:
        lines.append("Severity Gate: PASSED (not configured)")
    else:
        lines.append(f"Severity Gate: {gate['status']}")
        lines.append(f"  {reason}" if reason else
                      f"  No findings at or above the configured {gate['threshold']} threshold.")
    lines += ["", f"Status: {'PASSED' if passed else 'FAILED'}"]
    if not passed and reason:
        lines += ["", "Reason:", reason]

    lines += ["", "Results", "───────"]
    for r in result["results"]:
        lines.append(f"{r['status']:<8} {r['name']}")
    if result["findings"]:
        lines += ["", "Finding Detail", "──────────────"]
        for f in result["findings"]:
            lines.append(f"{f['severity'].upper():<9} {f['name']}")
            lines.append(f"          URL: {f['url']}")
            lines.append(f"          Evidence: {f['evidence']}")
    return "\n".join(lines) + "\n"


def _run_custom_test_command(args) -> int:
    # --- Gather test cases (either shape, from any source) ---------------
    raw_lines_for_save: list[str] = []
    if args.test:
        preset_raw, strict_raw = [], []
        for line in args.test:
            kind, spec = _spec_from_shorthand(_parse_kv_line(line))
            (preset_raw if kind == "preset" else strict_raw).append(spec)
        raw_lines_for_save = list(args.test)
    elif args.tests:
        try:
            preset_raw, strict_raw = _load_custom_tests_from_file(Path(args.tests))
        except OSError as exc:
            print(f"Perry: could not read {args.tests}: {exc}", file=sys.stderr)
            return EXIT_ERROR
    elif _isatty():
        if not _prompt_yes_no(
            "No custom test file supplied. Would you like to define a custom test now?",
            default=False,
        ):
            print("No custom tests to run.")
            return EXIT_OK
        preset_raw, strict_raw, raw_lines_for_save = _collect_custom_tests_interactively()
    else:
        print(
            "Perry: custom-test requires --tests <file> or --test <\"key=value,...\"> "
            "when running non-interactively (CI/CD). Run with no arguments interactively "
            "to see the shorthand syntax.",
            file=sys.stderr,
        )
        return EXIT_ERROR

    preset_specs, preset_errors = _validate_preset_specs(preset_raw)
    cases, strict_errors = _validate_custom_tests(strict_raw)
    errors = preset_errors + strict_errors
    if errors:
        print("Perry: invalid custom test case(s):", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return EXIT_ERROR
    if not preset_specs and not cases:
        print("No custom tests to run.")
        return EXIT_OK

    if args.save_tests:
        if raw_lines_for_save:
            Path(args.save_tests).write_text("\n".join(raw_lines_for_save) + "\n", encoding="utf-8")
        else:
            Path(args.save_tests).write_text(
                json.dumps([c.model_dump() for c in cases], indent=2), encoding="utf-8"
            )
        print(f"Saved test case(s) to {args.save_tests} for reuse in CI.")

    total = len(preset_specs) + len(cases)

    # --- Authorization gate ----------------------------------------------
    if not args.authorized:
        if _isatty():
            confirmed = _prompt_yes_no(
                f"This will send live request(s) for {total} custom test(s) to {args.url}. "
                "You must own this site or have explicit authorization to test it. Continue?",
                default=False,
            )
            if not confirmed:
                print("Aborted: authorization not confirmed.")
                return EXIT_ERROR
        else:
            print(
                "Perry: custom-test requires --authorized to send live requests "
                "in a non-interactive environment.",
                file=sys.stderr,
            )
            return EXIT_ERROR

    # --- Run ---------------------------------------------------------------
    try:
        result = asyncio.run(run_all_custom_tests(args.url, cases, preset_specs))
    except Exception as exc:
        print(f"Perry: custom-test failed: {exc}", file=sys.stderr)
        return EXIT_ERROR

    gate, reason = _severity_gate(result["counts"], args.fail_on)
    passed = gate["status"] == "PASSED"
    result["gate"] = gate

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(result, indent=2), encoding="utf-8")

    if not args.quiet:
        print(_render_custom_test_report(result, gate, reason, passed))
    else:
        print(f"Perry custom-test: {'PASSED' if passed else 'FAILED'}")

    return EXIT_OK if passed else EXIT_GATE_FAILED


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="Perry", description=__doc__)
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

    custom_test = sub.add_parser(
        "custom-test",
        help="Run user-defined test cases against a live URL (sends real requests)",
    )
    custom_test.add_argument("--url", required=True, help="Target URL to test")
    custom_test.add_argument(
        "--test", action="append", metavar="\"key=value,...\"",
        help='One shorthand test, e.g. --test "attack=sql injection, path=/login, '
             'method=POST, name=kabir, password=1234". Repeatable.',
    )
    custom_test.add_argument(
        "--tests",
        help="File of custom test case(s) — either a JSON array (the strict schema) "
             "or plain text with one shorthand line per test; prompted interactively "
             "if omitted and no --test was given",
    )
    custom_test.add_argument(
        "--authorized", action="store_true",
        help="Confirm you own/are authorized to test this target (required in CI/CD; "
             "prompted interactively otherwise)",
    )
    custom_test.add_argument(
        "--save-tests", help="Save interactively-defined test cases to this file for reuse in CI"
    )
    custom_test.add_argument(
        "--fail-on", choices=_SEVERITY_ORDER,
        help="Fail if any custom-test finding meets/exceeds this severity",
    )
    custom_test.add_argument("--json", dest="json_out", help="Write machine-readable output here")
    custom_test.add_argument("--quiet", action="store_true", help="Only print the pass/fail result")

    args = parser.parse_args(argv)

    if args.command == "custom-test":
        return _run_custom_test_command(args)

    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"Perry: {root} is not a directory", file=sys.stderr)
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
        print(f"Perry: {score}/100 {'PASSED' if overall_passed else 'FAILED'}")

    return result["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
