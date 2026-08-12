"""
Sentinel Risk Model v1 — deterministic, auditable risk scoring.

Two scales, deliberately never mixed:

  * **CVSS v4.0** scores actual vulnerabilities, using the official
    specification via the ``cvss`` library. Sentinel does not approximate it
    and does not adjust it. A CVSS score means what FIRST says it means.
  * **The Sentinel Hardening Model** scores configuration weaknesses — missing
    headers, weak cookies — on its own documented 0-100 scale, defined in
    ``hardening_model.json``. These are absent mitigations, not independently
    exploitable flaws, so forcing them through CVSS would misrepresent both.

Detection confidence and exploitation evidence are tracked separately again,
and are used *only* by the aggregation layer. Confidence never multiplies a
CVSS score, because a 90%-confident Critical is still a Critical.

Everything here is pure and deterministic: the same findings always produce
the same score. No model, no randomness, no LLM. The AI layer receives the
finished number and may explain it, never change it.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from cvss import CVSS4

# --------------------------------------------------------- classification

VULNERABILITY = "VULNERABILITY"
SECURITY_HARDENING = "SECURITY_HARDENING"
INFORMATIONAL = "INFORMATIONAL"
THIRD_PARTY_OBSERVATION = "THIRD_PARTY_OBSERVATION"

# Detection lifecycle. Independent of severity: a Critical can be merely
# suspected, and a Low can be fully demonstrated.
DETECTED = "DETECTED"
VALIDATED = "VALIDATED"
EXPLOIT_DEMONSTRATED = "EXPLOIT_DEMONSTRATED"

# How much each detection state is trusted during aggregation. This never
# touches the CVSS score.
_DETECTION_WEIGHT = {
    DETECTED: 0.80,
    VALIDATED: 0.95,
    EXPLOIT_DEMONSTRATED: 1.00,
}

# Sentinel presentation bands. NOT CVSS severity categories.
BANDS = [(80, "CRITICAL"), (60, "HIGH"), (40, "MODERATE"), (20, "LOW"), (0, "MINIMAL")]

METHODOLOGY = "Sentinel Risk Model v1"

_MODEL_PATH = Path(__file__).parent / "hardening_model.json"
with _MODEL_PATH.open(encoding="utf-8") as _fh:
    HARDENING_MODEL = json.load(_fh)


# ------------------------------------------------------------ CVSS mapping

# Base CVSS v4.0 metrics per vulnerability class, derived from what the
# scanner can actually observe about a web-facing finding. Metrics the scanner
# cannot determine are listed in `undetermined` and left at their CVSS default
# so the vector stays valid — the report states which were not established.
#
# AV:N  reachable over the network (the scanner reached it over HTTP)
# AT:N  no special attack prerequisites observed
# PR:N  no credentials were supplied by the scanner
_CVSS_PROFILES: dict[str, dict] = {
    "sql_injection": {
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "undetermined": ["SC", "SI", "SA"],
        "note": "Assumes the injected query reaches application data.",
    },
    "nosql_injection": {
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
        "undetermined": ["SC", "SI", "SA"],
    },
    "command_injection": {
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
        "undetermined": [],
    },
    "rce": {
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
        "undetermined": [],
    },
    "xss": {
        # Reflected XSS requires the victim to follow a link: UI:P.
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
        "undetermined": ["SC", "SI", "SA"],
        "note": "Modelled as reflected XSS; stored XSS would score higher.",
    },
    "path_traversal": {
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
        "undetermined": ["VI", "VA"],
    },
    "ssrf": {
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:L/SI:N/SA:N",
        "undetermined": ["SC", "SI", "SA"],
    },
    "open_redirect": {
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
        "undetermined": [],
    },
    "unsafe_deserialization": {
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
        "undetermined": [],
    },
    "code_execution": {
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
        "undetermined": [],
    },
    "auth_bypass": {
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
        "undetermined": [],
    },
    "sensitive_file_exposure": {
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
        "undetermined": ["VI", "VA"],
    },
    "hardcoded_secret": {
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
        "undetermined": ["VA"],
    },
}

# Scanner categories / dedup-key prefixes that denote a real vulnerability.
_VULN_KEYS = {
    # Web-scanner dedup prefixes
    "sqli": "sql_injection",
    # SAST engine class names (same vulnerability, different producer)
    "sql_injection": "sql_injection",
    "xss": "xss",
    "command_injection": "command_injection",
    "nosql_injection": "nosql_injection",
    "code_execution": "code_execution",
    "nosql": "nosql_injection",
    "cmd_injection": "command_injection",
    "reflected_xss": "xss",
    "path_traversal": "path_traversal",
    "ssrf": "ssrf",
    "open_redirect": "open_redirect",
    "sensitive_file": "sensitive_file_exposure",
    "hardcoded_secret": "hardcoded_secret",
    "env_secret": "hardcoded_secret",
    "unsafe_deserialization": "unsafe_deserialization",
    "code_execution": "code_execution",
    "auth_bypass": "auth_bypass",
}

# Scanner dedup-key prefixes that denote a hardening issue, mapped to a rule
# in hardening_model.json.
_HARDENING_KEYS = {
    "security_headers": None,          # resolved per missing header
    "insecure_cookie": None,           # resolved by cookie context
    "dir_listing": "directory_listing",
    "version_disclosure": "version_disclosure",
    "cors": "permissive_cors",
}

_HEADER_RULES = {
    "Content-Security-Policy": "missing_csp",
    "Strict-Transport-Security": "missing_hsts",
    "X-Frame-Options": "missing_x_frame_options",
    "X-Content-Type-Options": "missing_x_content_type_options",
    "Referrer-Policy": "missing_referrer_policy",
}


@dataclass
class CvssResult:
    vector: str
    base_score: float
    severity: str
    metrics: dict = field(default_factory=dict)
    undetermined: list[str] = field(default_factory=list)
    note: str = ""

    def as_dict(self) -> dict:
        return {
            "version": "CVSS:4.0",
            "vector": self.vector,
            "base_score": self.base_score,
            "severity": self.severity,
            "metrics": self.metrics,
            "undetermined_metrics": self.undetermined,
            "note": self.note,
        }


def _vuln_class(finding) -> str | None:
    """Which vulnerability profile a finding belongs to, if any."""
    key = (getattr(finding, "dedup_key", "") or "").lower()
    for prefix, cls in _VULN_KEYS.items():
        if key.startswith(prefix) or f"|{prefix}" in key:
            return cls
    # SAST findings carry their class as the finding type.
    for cls in _CVSS_PROFILES:
        if key.startswith(f"repo_code|") and cls in key:
            return cls
    return None


def score_cvss(vuln_class: str) -> CvssResult | None:
    """Official CVSS v4.0 base score for a vulnerability class."""
    profile = _CVSS_PROFILES.get(vuln_class)
    if profile is None:
        return None
    vector = profile["vector"]
    c = CVSS4(vector)
    metrics = {}
    for part in vector.split("/")[1:]:
        name, _, value = part.partition(":")
        metrics[name] = value
    return CvssResult(
        vector=vector,
        base_score=float(c.base_score),
        severity=str(c.severity).upper(),
        metrics=metrics,
        undetermined=list(profile.get("undetermined", [])),
        note=profile.get("note", ""),
    )


# ------------------------------------------------------------- hardening


def _hardening_rule(finding) -> str:
    key = (getattr(finding, "dedup_key", "") or "").lower()
    if key.startswith("security_headers"):
        # The heaviest missing header sets the rule for the group.
        evidence = getattr(finding, "evidence", "") or ""
        best, best_impact = "default", -1
        for label, rule in _HEADER_RULES.items():
            if label.lower() in evidence.lower():
                impact = HARDENING_MODEL["rules"][rule]["base_impact"]
                if impact > best_impact:
                    best, best_impact = rule, impact
        return best
    if key.startswith("insecure_cookie"):
        return "weak_cookie_session" if "session" in key else "weak_cookie_unknown"
    for prefix, rule in _HARDENING_KEYS.items():
        if rule and key.startswith(prefix):
            return rule
    return "default"


def hardening_impact(finding) -> tuple[str, float]:
    """(rule id, 0-100 Sentinel hardening weight). Never a CVSS score."""
    rule_id = _hardening_rule(finding)
    rule = HARDENING_MODEL["rules"].get(rule_id, HARDENING_MODEL["rules"]["default"])
    return rule_id, float(rule["base_impact"])


# -------------------------------------------------------------- exposure


def exposure_multiplier(affected_urls: int) -> float:
    """Bounded, diminishing breadth multiplier.

    Breadth matters — the same weakness on twenty pages is worse than on one —
    but linear multiplication turns a Low into a Critical purely by counting
    pages, which is meaningless. Tiers come from hardening_model.json and are
    hard-capped.
    """
    n = max(1, int(affected_urls or 1))
    for tier in HARDENING_MODEL["exposure"]["tiers"]:
        limit = tier["max_urls"]
        if limit is None or n <= limit:
            return float(tier["multiplier"])
    return float(HARDENING_MODEL["exposure"]["cap"])


# -------------------------------------------------- classify + confidence

# Scanner confidence words → numeric detection confidence.
_CONFIDENCE = {
    "confirmed": 0.95,
    "potential": 0.60,
    "uncertain": 0.35,
    "false_positive": 0.0,
}


def detection_status(finding) -> str:
    """DETECTED / VALIDATED / EXPLOIT_DEMONSTRATED from the evidence held."""
    demonstrated = bool(
        finding.confidence == "confirmed"
        and finding.evidence
        and (finding.request_summary or finding.response_summary)
        and finding.category not in ("dependency_vulnerability", "code_security")
    )
    if demonstrated:
        return EXPLOIT_DEMONSTRATED
    if finding.confidence == "confirmed":
        return VALIDATED
    return DETECTED


def classify(finding) -> str:
    """VULNERABILITY / SECURITY_HARDENING / INFORMATIONAL / THIRD_PARTY."""
    if not getattr(finding, "contributes_to_risk", True):
        return THIRD_PARTY_OBSERVATION
    if _vuln_class(finding) is not None:
        return VULNERABILITY
    if finding.category in ("security_headers", "configuration"):
        return SECURITY_HARDENING
    if finding.category in ("attack_surface",) or finding.severity == "info":
        return INFORMATIONAL
    if finding.category == "information_exposure":
        return SECURITY_HARDENING
    if finding.category == "dependency_vulnerability":
        # Scored by the reachability ladder, not CVSS — an advisory against an
        # unused package is not a vulnerability in this application.
        return SECURITY_HARDENING
    return INFORMATIONAL


def confidence_of(finding) -> float:
    return _CONFIDENCE.get(finding.confidence, 0.5)


# ---------------------------------------------------------- deduplication


def deduplicate(findings: list) -> list:
    """Merge findings describing one underlying problem.

    Three URLs missing the same five headers is one finding affecting three
    URLs, not fifteen vulnerabilities. Modules that independently detect the
    same issue collapse onto the same dedup key.
    """
    merged: dict[str, object] = {}
    order: list[str] = []
    for f in findings:
        key = getattr(f, "dedup_key", "") or f"{f.category}|{f.title}|{f.parameter}"
        existing = merged.get(key)
        if existing is None:
            merged[key] = f
            order.append(key)
            continue
        # Keep the strongest evidence, widen the affected set.
        samples = list(
            dict.fromkeys(
                (existing.affected_url_samples or []) + (f.affected_url_samples or [])
            )
        )
        existing.affected_url_samples = samples[:10]
        existing.affected_urls = max(
            existing.affected_urls or 1, f.affected_urls or 1, len(samples)
        )
        if _CONFIDENCE.get(f.confidence, 0) > _CONFIDENCE.get(existing.confidence, 0):
            existing.confidence = f.confidence
    return [merged[k] for k in order]


# ----------------------------------------------------------- aggregation


def _band(score: int) -> str:
    for threshold, label in BANDS:
        if score >= threshold:
            return label
    return "MINIMAL"


def calculate_sentinel_risk(findings: list) -> dict:
    """The one authoritative risk calculation. Pure and deterministic.

    A single severe vulnerability dominates: the strongest contributor sets
    the floor, and everything else can add only a bounded remainder of the
    distance to 100. That makes the score monotonic — removing a finding can
    never raise it — while still letting breadth register.
    """
    considered = deduplicate([f for f in findings if f.confidence != "false_positive"])

    contributors: list[dict] = []
    third_party = 0

    for f in considered:
        kind = classify(f)
        if kind == THIRD_PARTY_OBSERVATION:
            third_party += 1
            continue

        confidence = confidence_of(f)
        exposure = exposure_multiplier(getattr(f, "affected_urls", 1))
        status = detection_status(f)
        detection = _DETECTION_WEIGHT[status]

        entry: dict = {
            "finding_id": getattr(f, "dedup_key", "") or f.title,
            "title": f.title,
            "type": kind,
            "confidence": round(confidence, 2),
            "affected_urls": getattr(f, "affected_urls", 1),
            "exposure_multiplier": exposure,
            "detection_status": status,
        }

        if kind == VULNERABILITY:
            cvss = score_cvss(_vuln_class(f))
            if cvss is None:
                continue
            entry["cvss"] = cvss.as_dict()
            # CVSS 0-10 → 0-100, then Sentinel's own aggregation inputs.
            raw = cvss.base_score * 10.0
        elif kind == SECURITY_HARDENING:
            rule_id, impact = hardening_impact(f)
            entry["hardening"] = {
                "model": HARDENING_MODEL["model"],
                "rule": rule_id,
                "base_impact": impact,
                "scale": HARDENING_MODEL["scale"],
            }
            raw = impact
        else:
            entry["informational"] = True
            raw = 0.0

        contribution = raw * confidence * detection * exposure
        entry["contribution"] = round(min(100.0, contribution), 1)
        entry["contribution_note"] = (
            "Sentinel aggregation contribution — not a CVSS value."
        )
        contributors.append(entry)

    if not contributors:
        return {
            "score": 0,
            "severity": "MINIMAL",
            "methodology": METHODOLOGY,
            "findings_considered": 0,
            "third_party_excluded": third_party,
            "contributors": [],
            "explanation": "No in-scope findings with supporting evidence.",
        }

    contributors.sort(key=lambda c: c["contribution"], reverse=True)
    top = contributors[0]["contribution"]

    # Remaining findings add a bounded share of the distance to 100, with
    # diminishing weight, so volume can raise the score but never dominate it.
    tail = sum(
        c["contribution"] / (i + 2) for i, c in enumerate(contributors[1:])
    )
    tail_ratio = min(1.0, tail / 100.0)
    score = int(round(min(100.0, top + (100.0 - top) * 0.35 * tail_ratio)))

    return {
        "score": score,
        "severity": _band(score),
        "methodology": METHODOLOGY,
        "findings_considered": len(contributors),
        "third_party_excluded": third_party,
        "contributors": contributors[:20],
        "explanation": (
            f"Driven primarily by '{contributors[0]['title']}' "
            f"({contributors[0]['contribution']}/100 contribution)"
            + (
                f", with {len(contributors) - 1} further finding(s) adding "
                "a bounded amount."
                if len(contributors) > 1
                else "."
            )
        ),
    }
