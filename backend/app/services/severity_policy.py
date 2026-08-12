"""
Evidence-based severity policy.

Applied to every finding after the scanner produces it and before anything
scores, summarizes, or reports it. The rule throughout is that severity must
be justified by what was actually observed:

  * A missing hardening header is Low. It is a weakened defence, not an
    attack — it only rises if a finding elsewhere demonstrates the attack it
    would have mitigated.
  * A dependency advisory is capped by its exploitability classification, so
    an unused package cannot present as a High.
  * A title may not claim RCE, SQL injection, XSS, or session hijacking
    unless the finding is ``confirmed`` and carries evidence. Otherwise the
    claim is softened to "possible" and the severity is capped.

Everything here is deterministic and runs before the LLM, so the analyst is
shown language it cannot then escalate.
"""
from __future__ import annotations

import re

from app.services.reachability import (
    CONFIRMED_EXPLOITABLE,
    DEPENDENCY_PRESENT,
    FUNCTIONALITY_USED,
    POTENTIALLY_EXPLOITABLE,
    REACHABLE_FROM_INPUT,
)
from app.services.finding_types import FindingCandidate

_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def _cap(severity: str, ceiling: str) -> str:
    try:
        return (
            ceiling
            if _SEVERITY_ORDER.index(severity) > _SEVERITY_ORDER.index(ceiling)
            else severity
        )
    except ValueError:
        return ceiling


# Attack claims that require demonstrated evidence, and the neutral wording
# used when the scanner only saw a suggestive pattern.
_CLAIM_TERMS = {
    "remote code execution": "possible unsafe code execution pattern",
    "rce": "possible unsafe code execution pattern",
    "sql injection": "possible SQL injection pattern",
    "sqli": "possible SQL injection pattern",
    "command injection": "possible command injection pattern",
    "session hijacking": "weakened session protection",
    "cross-site scripting": "possible cross-site scripting pattern",
    "xss": "possible cross-site scripting pattern",
    "account takeover": "possible authentication weakness",
}

_CLAIM_RE = re.compile(
    r"\b(" + "|".join(re.escape(k) for k in sorted(_CLAIM_TERMS, key=len, reverse=True)) + r")\b",
    re.IGNORECASE,
)

# Severity ceiling per dependency classification.
_DEPENDENCY_CEILING = {
    DEPENDENCY_PRESENT: "low",
    FUNCTIONALITY_USED: "low",
    REACHABLE_FROM_INPUT: "medium",
    POTENTIALLY_EXPLOITABLE: "high",
    CONFIRMED_EXPLOITABLE: "critical",
}

# Confidence ceiling per classification — nothing static is ever "confirmed".
_DEPENDENCY_CONFIDENCE = {
    DEPENDENCY_PRESENT: "potential",
    FUNCTIONALITY_USED: "potential",
    REACHABLE_FROM_INPUT: "potential",
    POTENTIALLY_EXPLOITABLE: "potential",
    CONFIRMED_EXPLOITABLE: "confirmed",
}


# Which finding category a given header actually mitigates. Only a
# demonstrated finding in that category can raise the header above Low.
_HEADER_MITIGATES = {
    "content-security-policy": "input_validation",
    "x-xss-protection": "input_validation",
    "x-content-type-options": "input_validation",
    "x-frame-options": "clickjacking",
    "strict-transport-security": "transport",
    "referrer-policy": "information_exposure",
}


def _mitigated_category(title: str) -> str | None:
    lowered = (title or "").lower()
    for header, category in _HEADER_MITIGATES.items():
        if header in lowered:
            return category
    return None


def _has_demonstrated_evidence(f: FindingCandidate) -> bool:
    """True when the finding carries an observed request/response pair.

    A pattern matched in source code is not a demonstration; a payload that
    changed the application's response is.
    """
    if f.confidence != "confirmed":
        return False
    if f.category in ("dependency_vulnerability", "code_security"):
        return False
    return bool(f.evidence and (f.request_summary or f.response_summary))


def apply_policy(findings: list[FindingCandidate]) -> None:
    """Normalise severity, confidence, and wording across all findings."""
    demonstrated_categories = {
        f.category for f in findings if _has_demonstrated_evidence(f)
    }

    for f in findings:
        # --- Missing hardening headers -----------------------------------
        if f.category == "security_headers":
            # Low by default. A header only rises to Medium when another
            # finding *demonstrates* the specific attack that this header
            # would have mitigated — and never beyond Medium, because the
            # missing header is the mitigation gap, not the attack itself.
            mitigates = _mitigated_category(f.title)
            justified = mitigates is not None and mitigates in demonstrated_categories
            f.severity = _cap(f.severity, "medium" if justified else "low")
            if not justified:
                f.impact = (
                    "Reduces defence-in-depth. On its own this is not an "
                    "exploitable vulnerability — it removes a protection "
                    "that would limit the damage of another flaw."
                )

        # --- Attack-surface observations ---------------------------------
        # "A separate app answers on admin.example.com" is a fact about
        # exposure, not a demonstrated weakness in it. Capped at Low so a
        # discovery can never present as a vulnerability.
        if f.category == "attack_surface":
            f.severity = _cap(f.severity, "low")

        # --- Dependency advisories ---------------------------------------
        if f.category == "dependency_vulnerability":
            classification = f.exploitability or DEPENDENCY_PRESENT
            f.severity = _cap(f.severity, _DEPENDENCY_CEILING.get(classification, "low"))
            ceiling = _DEPENDENCY_CONFIDENCE.get(classification, "potential")
            if ceiling == "potential" and f.confidence == "confirmed":
                f.confidence = "potential"

        # --- Unearned attack claims --------------------------------------
        if not _has_demonstrated_evidence(f):
            f.title = _soften(f.title)
            f.description = _soften(f.description)
            f.impact = _soften(f.impact)
            # A pattern match must not present as a proven exploit.
            if f.category in ("code_security", "dependency_vulnerability"):
                f.severity = _cap(f.severity, "medium" if f.severity != "low" else "low")


def _soften(text: str) -> str:
    """Rewrite definite attack claims as the pattern that was observed."""
    if not text:
        return text

    def replace(match: re.Match) -> str:
        replacement = _CLAIM_TERMS[match.group(1).lower()]
        # Capitalise only at the start of a sentence. "SQL Injection" is
        # capitalised because SQL is an acronym, not because it opens one, so
        # keying off the matched text would capitalise mid-sentence.
        prefix = text[: match.start()].rstrip()
        if not prefix or prefix.endswith((".", "!", "?", ":", "\n")):
            return replacement[:1].upper() + replacement[1:]
        return replacement

    return _CLAIM_RE.sub(replace, text)
