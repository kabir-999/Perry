"""
LLM Security Analyst (Groq).

One Groq call per completed scan. It receives the aggregated ``ScanSummary``
(summarized evidence only — never raw HTML) and returns a single, validated
``SecurityAssessment``: overall risk score/level, a plain-language summary,
per-factor analysis, severity statistics, and an overall recommendation.

Contract:
  * The deterministic scanner is the only source of evidence.
  * Groq — not the scanner, not the frontend — determines severity,
    confidence, impact, and the overall risk score/level.
  * The response is validated with Pydantic. On malformed output we retry
    once, then give up and report the assessment as *unavailable* — we never
    fabricate a risk score.
  * The API key lives only in settings and never reaches the frontend.
"""
from __future__ import annotations

import json
import logging

from pydantic import BaseModel, Field, ValidationError

from app.config import settings

logger = logging.getLogger("scanner.llm")

_LEVELS = ["minimal", "low", "medium", "high", "critical"]

_SYSTEM_PROMPT = (
    "You are an expert web application security analyst.\n\n"
    "You will receive structured evidence collected by a web application "
    "security scanner. Analyze ONLY the evidence provided.\n\n"
    "EVIDENCE STRENGTH. Every finding carries an evidence_strength field. It "
    "constrains what you may claim:\n"
    "  * demonstrated — the scanner sent a request and observed a response "
    "proving the issue. Only these may be described as confirmed or "
    "exploited.\n"
    "  * observed — a pattern was seen in source code or configuration. "
    "Describe it as a pattern that may be exploitable; never as proven.\n"
    "  * reported — a third party published an advisory about a component. "
    "This says nothing about whether THIS application is affected.\n"
    "You may never raise a finding above the certainty its evidence_strength "
    "allows, no matter how severe the issue would be if real.\n\n"
    "DEPENDENCIES. A known CVE/GHSA against a package version is NOT by itself "
    "an exploitable vulnerability in this application, and neither is the fact "
    "that the package is imported. Each finding carries one of five "
    "classifications — use its exact language and never promote it:\n"
    "  * dependency_present — the affected version is installed, but the "
    "specific functionality the advisory blames was not found in the code. "
    "Report as 'Vulnerable Dependency Present'. Hygiene issue, Low.\n"
    "  * functionality_used — the vulnerable function/API is called, but no "
    "path was found from attacker-controlled input to it. Report as "
    "'Vulnerable Functionality Used'. Low.\n"
    "  * reachable_from_input — request data reaches the vulnerable call. "
    "Report as 'Vulnerable Functionality Reachable From Input'. Medium.\n"
    "  * potentially_exploitable — used AND reachable from a request handler. "
    "Report as 'Potentially Exploitable' and say plainly that a working attack "
    "was NOT demonstrated.\n"
    "  * confirmed_exploitable — only when the scanner demonstrated the attack.\n"
    "The advisory's own severity does NOT set the finding severity: a Critical "
    "CVE in a function this application never calls is Low here. Never treat an "
    "import, or the fact that the site is reachable over HTTP, as evidence of "
    "exploitability.\n"
    "When you describe a dependency finding, state the affected version, the "
    "advisory ID, the vulnerable version range, the patched version, whether it "
    "is direct or transitive and production or development, whether the "
    "vulnerable functionality is used (and where), and whether a path from "
    "attacker-controlled input was found. All of these are in the dependency "
    "object — do not guess any of them.\n\n"
    "SCOPE. The payload separates `findings` (the target's own) from "
    "`third_party_observations` (responses from external services such as an "
    "Atlassian login page or a GitHub repository, reached from the target). "
    "Your summary, risk factors, statistics, and score must be built ONLY from "
    "`findings`. Never attribute a third-party observation to the target — "
    "saying 'the target has missing security headers' when the evidence came "
    "from atlassian.net is factually wrong. You may mention third-party "
    "observations in a separate sentence, explicitly named as an external "
    "service and excluded from the target's risk.\n\n"
    "SOURCE CODE. `source_code_analysis.available` tells you whether a "
    "repository was actually analysed. When it is false, say source-code "
    "analysis was not available — never report 'no code issues found', which "
    "claims a clean result that was never established.\n\n"
    "TECHNOLOGY. Detecting Cloudflare, nginx, Apache, React, etc. is "
    "informational. It is not information exposure and not a vulnerability. "
    "Only a disclosed version number is a finding.\n\n"
    "HSTS. Do not describe a missing Strict-Transport-Security header as proof "
    "that a downgrade attack exists. Say that browsers which have not "
    "previously received an HSTS policy may be more exposed to downgrade or "
    "first-connection interception. Keep 'HTTP available', 'HTTP redirects to "
    "HTTPS', 'HSTS present' and 'HSTS missing' as distinct facts.\n\n"
    "COVERAGE CLAIMS. Never write that the rest of the site is secure or that "
    "all other pages have proper headers — the scan tested a sample. Say what "
    "was tested and what passed, e.g. 'missing headers were identified on a "
    "subset of in-scope URLs; other tested controls passed and no active "
    "exploitation was demonstrated'.\n\n"
    "CONSISTENCY. Each finding carries scanner_severity, and the payload "
    "carries scanner_max_severity. The severity you give a risk factor MUST "
    "match the scanner_severity of the finding it describes — you may lower it "
    "if the evidence is weaker than the scanner assumed, but never raise it. "
    "The same issue must not appear as Low in one place and Medium in another.\n\n"
    "ATTACK SURFACE. A finding that a separate application responds on a "
    "dev/admin/staging host is a discovery about exposure, not a vulnerability. "
    "Report it as an exposed development/admin surface and state that "
    "authentication, reachable admin functions, debug mode, and data exposure "
    "were NOT tested. Do not describe consequences that would only follow if "
    "those untested conditions were true.\n\n"
    "MISSING SECURITY HEADERS are Low by default. They are weakened "
    "defence-in-depth, not attacks. Raise one above Low ONLY if another finding "
    "with evidence_strength=demonstrated shows the attack that header would "
    "have mitigated.\n\n"
    "PROHIBITED CLAIMS. Do not state that remote code execution, SQL injection, "
    "cross-site scripting, session hijacking, or account takeover is present "
    "unless a finding with evidence_strength=demonstrated shows the attack "
    "path. Otherwise describe the observation ('a query is built by string "
    "concatenation') and what it could allow if reachable.\n\n"
    "Do not invent vulnerabilities.\n"
    "Do not invent evidence.\n"
    "Do not treat technology detection (nginx, Cloudflare, Apache, etc.) as a "
    "vulnerability or let it raise the risk score by itself.\n"
    "Exposed credentials found in public source code ARE immediately "
    "actionable — treat a verified secret as high severity.\n\n"
    "OVERALL RISK. Base risk_score on the single strongest evidence-backed "
    "finding, NOT on how many findings there are. A long list of "
    "known_vulnerable_dependency and missing-header findings is a Low or "
    "Medium site. One demonstrated injection is High or Critical on its own. "
    "Never let volume alone drive the score.\n\n"
    "Provide an overall risk score from 0 to 100 using these levels:\n"
    "0-19 Minimal, 20-39 Low, 40-59 Medium, 60-79 High, 80-100 Critical.\n"
    "The risk_level MUST be consistent with the risk_score band.\n\n"
    "Explain the security posture in language a non-technical user can "
    "understand. For every meaningful finding provide: title, severity, "
    "confidence (0.0-1.0), affected_urls, evidence, explanation, impact, and "
    "recommendation. Set confidence to reflect evidence_strength: demonstrated "
    "0.9-1.0, observed 0.4-0.7, reported 0.2-0.5. Also set the "
    "exploitability field to the classification you were given, and "
    "evidence_strength to the value from the finding.\n\n"
    "In the summary, state explicitly what was proven versus what is "
    "precautionary, so the reader knows which items need action today.\n\n"
    "Return ONLY the requested structured JSON."
)

_RESPONSE_SHAPE = (
    '{\n'
    '  "risk_score": <int 0-100>,\n'
    '  "risk_level": "Minimal|Low|Medium|High|Critical",\n'
    '  "summary": "<plain-language security posture>",\n'
    '  "risk_factors": [\n'
    '    {"title": "...", "severity": "Minimal|Low|Medium|High|Critical",\n'
    '     "confidence": <float 0-1>, "affected_urls": <int>,\n'
    '     "evidence": "...", "impact": "...", "explanation": "...",\n'
    '     "recommendation": "...",\n'
    '     "evidence_strength": "demonstrated|observed|reported",\n'
    '     "exploitability": "dependency_present|functionality_used'
    '|reachable_from_input|potentially_exploitable|confirmed_exploitable|" }\n'
    '  ],\n'
    '  "statistics": {"critical": 0, "high": 0, "medium": 0, "low": 0, "minimal": 0},\n'
    '  "overall_recommendation": "..."\n'
    '}'
)


class RiskFactor(BaseModel):
    title: str = ""
    severity: str = "low"
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    affected_urls: int = 0
    evidence: str = ""
    impact: str = ""
    explanation: str = ""
    recommendation: str = ""
    # How well-supported the factor is, and (for dependencies) which of the
    # three exploitability classifications it falls under.
    evidence_strength: str = ""
    exploitability: str = ""


class AssessmentStatistics(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    minimal: int = 0


class SecurityAssessment(BaseModel):
    risk_score: int = 0
    risk_level: str = "minimal"
    summary: str = ""
    risk_factors: list[RiskFactor] = []
    statistics: AssessmentStatistics = AssessmentStatistics()
    overall_recommendation: str = ""


# User-facing unavailability messages (never leak internals).
REASON_NOT_CONFIGURED = "AI analysis unavailable: GROQ_API_KEY is not configured."
REASON_API_ERROR = "AI analysis temporarily unavailable."
REASON_INVALID = "AI analysis temporarily unavailable."


class SecurityAnalyst:
    def __init__(self) -> None:
        self._client = None

    @property
    def enabled(self) -> bool:
        return settings.groq_configured

    def _get_client(self):
        if self._client is None:
            from groq import AsyncGroq

            self._client = AsyncGroq(
                api_key=settings.GROQ_API_KEY,
                timeout=settings.GROQ_REQUEST_TIMEOUT_SECONDS,
            )
        return self._client

    async def analyze(self, summary: dict) -> tuple[SecurityAssessment | None, str]:  # noqa: C901
        """Run one Groq call. Returns (assessment, "") on success or
        (None, user_facing_reason) on failure — never a fabricated score."""
        if not self.enabled:
            return None, REASON_NOT_CONFIGURED

        user_prompt = (
            "Analyze the following aggregated scan evidence and return ONLY "
            "JSON in exactly this shape:\n" + _RESPONSE_SHAPE + "\n\nSCAN DATA:\n"
            + json.dumps(summary)
        )
        messages = [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]

        last_error = REASON_API_ERROR
        # One initial attempt + one retry on malformed output.
        for attempt in range(2):
            try:
                client = self._get_client()
                completion = await client.chat.completions.create(
                    model=settings.GROQ_MODEL,
                    messages=messages,
                    temperature=0.1,
                    response_format={"type": "json_object"},
                )
                raw = completion.choices[0].message.content or ""
            except Exception as exc:
                logger.warning("Groq API error (attempt %d): %s", attempt + 1, exc)
                last_error = REASON_API_ERROR
                continue

            assessment = self._parse(raw)
            if assessment is not None:
                return self._normalize(
                    assessment, summary.get("scanner_max_severity", "")
                ), ""
            last_error = REASON_INVALID
            # nudge the retry to be stricter
            messages.append(
                {
                    "role": "user",
                    "content": "Your previous response was not valid JSON in "
                    "the required shape. Return ONLY the JSON object.",
                }
            )

        return None, last_error

    @staticmethod
    def _normalize(a: SecurityAssessment, scanner_max: str = "") -> SecurityAssessment:
        a.risk_score = max(0, min(100, int(a.risk_score)))
        for rf in a.risk_factors:
            sev = (rf.severity or "").strip().lower()
            rf.severity = sev if sev in _LEVELS else "low"

        _enforce_evidence_policy(a, scanner_max)

        level = (a.risk_level or "").strip().lower()
        if level not in _LEVELS:
            level = _level_for_score(a.risk_score)
        a.risk_level = level
        # The band and the score must agree; the score is authoritative.
        if _level_for_score(a.risk_score) != a.risk_level:
            a.risk_level = _level_for_score(a.risk_score)
        return a

    @staticmethod
    def _parse(raw: str) -> SecurityAssessment | None:
        text = raw.strip()
        if not text.startswith("{"):
            start, end = text.find("{"), text.rfind("}")
            if start >= 0 and end > start:
                text = text[start : end + 1]
        try:
            data = json.loads(text)
        except (ValueError, TypeError):
            logger.warning("Groq returned non-JSON output.")
            return None
        try:
            return SecurityAssessment.model_validate(data)
        except ValidationError as exc:
            logger.warning("Groq output failed schema validation: %s", exc)
            return None


# Severity ceilings the analyst cannot exceed, keyed by how strong the
# underlying evidence is. The prompt asks for these; this enforces them, so a
# model that ignores the instruction still cannot publish an unearned Critical.
_STRENGTH_CEILING = {"reported": "low", "observed": "medium"}
_EXPLOITABILITY_CEILING = {
    "dependency_present": "low",
    "known_vulnerable_dependency": "low",  # legacy value on older scans
    "functionality_used": "low",
    "reachable_from_input": "medium",
    "potentially_exploitable": "high",
}
_CONFIDENCE_CEILING = {"reported": 0.5, "observed": 0.7}

# Representative score at the top of each band, used to cap the overall score
# at the strongest single factor.
_BAND_TOP = {"minimal": 19, "low": 39, "medium": 59, "high": 79, "critical": 100}


def _cap_level(level: str, ceiling: str) -> str:
    try:
        return ceiling if _LEVELS.index(level) > _LEVELS.index(ceiling) else level
    except ValueError:
        return ceiling


def _enforce_evidence_policy(a: SecurityAssessment, scanner_max: str = "") -> None:
    """Hold the assessment to the evidence it was given.

    Two rules: a factor may not exceed the certainty its evidence supports,
    and the overall score may not exceed the strongest single factor — so a
    long list of advisories cannot add up to a Critical site.
    """
    # The analyst cannot rate anything above the scanner's own worst finding.
    ceiling_from_scanner = scanner_max if scanner_max in _LEVELS else None

    for rf in a.risk_factors:
        if ceiling_from_scanner:
            rf.severity = _cap_level(rf.severity, ceiling_from_scanner)
        strength = (rf.evidence_strength or "").strip().lower()
        exploitability = (rf.exploitability or "").strip().lower()

        ceiling = None
        if exploitability in _EXPLOITABILITY_CEILING:
            ceiling = _EXPLOITABILITY_CEILING[exploitability]
        elif strength in _STRENGTH_CEILING:
            ceiling = _STRENGTH_CEILING[strength]
        if ceiling:
            rf.severity = _cap_level(rf.severity, ceiling)

        limit = _CONFIDENCE_CEILING.get(strength)
        if limit is not None and rf.confidence > limit:
            rf.confidence = limit

    if not a.risk_factors:
        return

    strongest = max(
        (_LEVELS.index(rf.severity) for rf in a.risk_factors if rf.severity in _LEVELS),
        default=0,
    )
    a.risk_score = min(a.risk_score, _BAND_TOP[_LEVELS[strongest]])

    # Statistics must describe the factors as finally classified, not as the
    # model first labelled them.
    counts = {level: 0 for level in _LEVELS}
    for rf in a.risk_factors:
        if rf.severity in counts:
            counts[rf.severity] += 1
    a.statistics = AssessmentStatistics(**counts)


def _level_for_score(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "minimal"


security_analyst = SecurityAnalyst()
