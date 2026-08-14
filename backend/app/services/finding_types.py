"""
Shared dataclass for a candidate finding.

The deterministic scanner produces ``FindingCandidate`` objects (evidence
only). The risk engine scores them and the LLM analyst annotates them before
they are persisted as ``Finding`` rows. Keeping this in its own module avoids
import cycles between the check modules and the analyst.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Severity ordering, high to low, for sorting and risk roll-ups.
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}


@dataclass
class FindingCandidate:
    title: str
    category: str
    severity: str  # one of SEVERITY_ORDER
    confidence: str  # confirmed | potential | uncertain | false_positive
    url: str = ""
    method: str = "GET"
    parameter: str = ""
    evidence: str = ""
    request_summary: str = ""
    response_summary: str = ""
    description: str = ""
    impact: str = ""
    remediation: str = ""
    risk_score: float = 0.0
    # A stable key used to de-duplicate identical findings across pages
    # (fingerprint = finding_type + normalized evidence).
    dedup_key: str = ""
    # How many locations this (deduplicated) finding affects, and a few
    # sample URLs for evidence.
    affected_urls: int = 1
    affected_url_samples: list[str] = field(default_factory=list)

    # Scope attribution. A finding whose evidence came from a third-party
    # origin is reported, but never counted against the target.
    origin: str = ""
    scope_status: str = ""
    evidence_url: str = ""
    contributes_to_risk: bool = True

    # Exploitability classification — see services/dependency_analysis.py for
    # the vocabulary. Empty for findings where it does not apply.
    exploitability: str = ""
    # Dependency provenance, populated only for dependency advisories so the
    # report can state exactly what was and was not established.
    dependency: dict = field(default_factory=dict)

    # --- Evidence fields (Part 9) --------------------------------------
    # Where the tested parameter lived: query | form | json | path | header |
    # cookie | multipart | graphql_variable. Empty when the finding isn't
    # parameter-specific.
    parameter_location: str = ""
    # The identity the triggering request(s) were sent as, e.g.
    # "unauthenticated", "authenticated as scanner test account",
    # "scanner account A vs scanner account B".
    auth_context: str = ""
    # How to reproduce this exact finding, e.g. "Reproducible - replay the
    # recorded request" vs "Single observation, not replayed".
    reproducibility: str = ""

    def key(self) -> str:
        return self.dedup_key or f"{self.category}|{self.url}|{self.parameter}"


@dataclass
class FastCheck:
    """One line item in the fast-scan initial assessment."""

    label: str
    status: str  # pass | warning | fail | info | error
    detail: str = ""
    findings: list[FindingCandidate] = field(default_factory=list)
