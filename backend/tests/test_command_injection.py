"""Dedicated tests for the OS command-injection detector.

Command injection is implemented in the active engine (``_test_target`` runs
the ``cmd_injection`` payload family against command-ish parameters and
``_cmd_detect`` looks for command-output evidence). These tests exercise that
real detector via FakeFetcher.

The responder simulates a host that executes shell metacharacters: command
output appears only when the decoded parameter value actually contains the
injection. The detector still has to analyse the response — it is never told
which payload was sent.
"""
from urllib.parse import parse_qs, urlsplit

from app.services.active_engine import ParamTarget, ProbeRecorder, _test_target
from fixtures import FakeFetcher, ok_result

URL = "https://example.com/exec"
CMD_OUTPUT = "uid=1000(scanner) gid=1000(scanner) groups=1000(scanner)"


def _cmd_value(url: str) -> str:
    return (parse_qs(urlsplit(url).query).get("cmd") or [""])[0]


def _responder_for(injection: str):
    """Return command output only when the decoded ``cmd`` value contains the
    given injection; the baseline value and unrelated payloads stay benign."""
    def responder(url, **kwargs):
        value = _cmd_value(url)
        if injection in value:
            return ok_result(url, text=f"PING host ...\n{CMD_OUTPUT}\n")
        return ok_result(url, text="<p>Host is reachable.</p>")

    return responder


def _cmd_findings(findings):
    return [f for f in findings if f.dedup_key.startswith("cmd_injection")]


async def test_cmd_injection_semicolon():
    fetcher = FakeFetcher(_responder_for(";id"))
    findings = await _test_target(fetcher, ParamTarget(url=URL, name="cmd", location="query"))
    cmd = _cmd_findings(findings)
    assert len(cmd) == 1
    assert "uid=1000" in cmd[0].evidence


async def test_cmd_injection_pipe():
    fetcher = FakeFetcher(_responder_for("|id"))
    findings = await _test_target(fetcher, ParamTarget(url=URL, name="cmd", location="query"))
    assert len(_cmd_findings(findings)) == 1


async def test_cmd_injection_backtick():
    fetcher = FakeFetcher(_responder_for("`id`"))
    findings = await _test_target(fetcher, ParamTarget(url=URL, name="cmd", location="query"))
    assert len(_cmd_findings(findings)) == 1


async def test_cmd_injection_command_substitution():
    fetcher = FakeFetcher(_responder_for("$(id)"))
    findings = await _test_target(fetcher, ParamTarget(url=URL, name="cmd", location="query"))
    assert len(_cmd_findings(findings)) == 1


async def test_cmd_injection_negative():
    """A normal application response with no command-execution evidence must
    not be reported as vulnerable."""
    fetcher = FakeFetcher(lambda url, **k: ok_result(url, text="<p>Host is reachable.</p>"))
    findings = await _test_target(fetcher, ParamTarget(url=URL, name="cmd", location="query"))
    assert _cmd_findings(findings) == []


async def test_cmd_injection_probe_log_records_every_attempt():
    """The probe recorder logs each payload sent (hit or miss) with a stable
    machine name and an explicit verdict — the per-test-case JSON log."""
    rec = ProbeRecorder()
    fetcher = FakeFetcher(_responder_for(";id"))
    await _test_target(
        fetcher, ParamTarget(url=URL, name="cmd", location="query"), recorder=rec
    )
    cmd_entries = [e for e in rec.entries if e["test"] == "cmd_injection"]
    assert cmd_entries, "expected at least one recorded command-injection probe"
    assert cmd_entries[0]["name"] == "cmd_injection_semicolon"
    assert any(e["verdict"] == "vulnerable" and e["evidence"] for e in cmd_entries)
