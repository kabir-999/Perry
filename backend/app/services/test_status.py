"""
Test-status vocabulary for the security-test matrix.

Replaces the old ad hoc `"pass"/"finding"/"not_applicable"/"not_authorized"/
"inconclusive"` strings with a status that separates "we looked and it's
fine" from "we never actually looked" — the distinction the old vocabulary
collapsed, which is exactly why Sentinel could report `API Security: PASS`
against a target where zero API endpoints were ever discovered.
"""
from __future__ import annotations


class TestStatus:
    # The test ran against real discovered attack surface and found a issue.
    VULNERABLE = "VULNERABLE"
    # The test ran against real discovered attack surface and found nothing.
    NOT_VULNERABLE = "NOT_VULNERABLE"
    # The test's attack surface was never discovered, or the test could not
    # run for a scope/authorization/budget reason — never a claim of safety.
    NOT_TESTED = "NOT_TESTED"
    # The test ran but produced ambiguous evidence (e.g. no credential
    # supplied to probe an authorization boundary that does exist).
    INCONCLUSIVE = "INCONCLUSIVE"
    # This test class does not apply to this target at all (e.g. no
    # authentication system exists to test authorization against).
    NOT_APPLICABLE = "NOT_APPLICABLE"


ALL_STATUSES = (
    TestStatus.VULNERABLE,
    TestStatus.NOT_VULNERABLE,
    TestStatus.NOT_TESTED,
    TestStatus.INCONCLUSIVE,
    TestStatus.NOT_APPLICABLE,
)
