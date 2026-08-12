"""
Declarative security test-case registry.

Wraps the deterministic active checks as ``SecurityTestCase`` objects so new
tests can be added (by a developer/security professional) without touching the
deep-scan orchestrator. Normal users never see or configure these — the deep
scan simply runs every enabled test case whose ``applies`` predicate matches.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Awaitable, Callable

from app.services import security_checks
from app.services.discovery_types import DiscoveredParam
from app.services.finding_types import FindingCandidate
from app.services.http_client import Fetcher

ParamPredicate = Callable[[DiscoveredParam], bool]
ParamRunner = Callable[[Fetcher, str, str], Awaitable[list[FindingCandidate]]]

_REDIRECT_NAMES = {"url", "redirect", "next", "return", "dest", "u"}


@dataclass
class SecurityTestCase:
    name: str
    category: str
    target_type: str  # "parameter" | "response" | "endpoint"
    enabled: bool
    applies: ParamPredicate
    run: ParamRunner


# Built-in, non-destructive parameter test cases. Add new ones here.
PARAMETER_TEST_CASES: list[SecurityTestCase] = [
    SecurityTestCase(
        "reflected_xss", "input_validation", "parameter", True,
        lambda p: True, security_checks.check_reflected_xss,
    ),
    SecurityTestCase(
        "sql_injection", "input_validation", "parameter", True,
        lambda p: True, security_checks.check_sql_injection,
    ),
    SecurityTestCase(
        "open_redirect", "input_validation", "parameter", True,
        lambda p: p.name.lower() in _REDIRECT_NAMES,
        security_checks.check_open_redirect,
    ),
    SecurityTestCase(
        "path_traversal", "input_validation", "parameter", True,
        lambda p: security_checks.looks_pathish(p.name),
        security_checks.check_path_traversal,
    ),
]


def enabled_parameter_test_cases() -> list[SecurityTestCase]:
    return [tc for tc in PARAMETER_TEST_CASES if tc.enabled]
