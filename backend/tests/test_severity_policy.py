from app.services.finding_types import FindingCandidate
from app.services.severity_policy import apply_policy


def _finding(**overrides) -> FindingCandidate:
    defaults = dict(
        title="Reflected XSS pattern",
        category="input_validation",
        severity="high",
        confidence="potential",
    )
    defaults.update(overrides)
    return FindingCandidate(**defaults)


def test_unconfirmed_input_validation_finding_is_capped():
    """A pattern-matched, unconfirmed XSS/traversal finding must not keep
    a High severity — this was the biggest gap found in the audit: only
    code_security/dependency_vulnerability were capped before, so
    input_validation and authentication findings kept an unearned High."""
    f = _finding(category="input_validation", severity="high", confidence="potential")
    apply_policy([f])
    assert f.severity == "medium"


def test_unconfirmed_authentication_finding_is_capped():
    f = _finding(
        title="Sensitive API endpoint accessible without authentication",
        category="authentication",
        severity="high",
        confidence="potential",
    )
    apply_policy([f])
    assert f.severity == "medium"


def test_confirmed_and_demonstrated_finding_is_not_capped():
    """A finding backed by an actual observed request/response pair keeps
    its severity — the cap only ever applies to unproven pattern matches."""
    f = _finding(
        category="input_validation",
        severity="high",
        confidence="confirmed",
        evidence="payload reflected unescaped in response",
        response_summary="<script>evidence</script> present in body",
    )
    apply_policy([f])
    assert f.severity == "high"


def test_low_severity_is_never_raised_by_the_cap():
    f = _finding(category="authentication", severity="low", confidence="potential")
    apply_policy([f])
    assert f.severity == "low"


def test_confirmed_secret_is_not_capped_by_the_generic_evidence_rule():
    """A secret match has no request/response pair by definition — it is
    its own evidence. Generalizing the "unearned attack claim" cap to every
    category (instead of just the attack-claim categories) would otherwise
    flatten every confirmed, committed secret to Medium, which defeats the
    point of ever reporting a secret as Critical."""
    f = _finding(
        title="Hardcoded Secret in config.py",
        category="information_exposure",
        severity="critical",
        confidence="confirmed",
    )
    apply_policy([f])
    assert f.severity == "critical"
