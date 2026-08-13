"""Expanded SQLi tests: error / boolean / time based (+ DB fingerprint).

The Phase 1 error-based SQLi tests remain in place; these cover the new modes.
"""
from urllib.parse import parse_qs, urlsplit

from app.services.phase2_checks import (
    check_sqli_boolean, check_sqli_error, check_sqli_time, sql_database_family,
)
from fixtures import FakeFetcher, ok_result

URL = "https://example.com/items"
PARAM = "id"


def _id(url):
    return (parse_qs(urlsplit(url).query).get(PARAM) or [""])[0]


# --- error based ----------------------------------------------------------- #
async def test_sqli_error_based():
    def responder(url, **k):
        if not _id(url).isdigit():
            return ok_result(url, status_code=500,
                             text="ERROR: unterminated quoted string at or near \"'\"")
        return ok_result(url, text="<p>ok</p>")
    findings = await check_sqli_error(FakeFetcher(responder), URL, PARAM)
    assert len(findings) == 1
    assert "PostgreSQL" in findings[0].evidence


# --- boolean based --------------------------------------------------------- #
def _boolean_responder(url, **k):
    raw = _id(url)
    if "1=2" in raw or "'1'='2" in raw:
        return ok_result(url, text="<p>No items found.</p>")
    return ok_result(url, text="<ul><li>Widget</li><li>Gadget</li><li>Gizmo</li></ul>")


async def test_sqli_boolean_based():
    findings = await check_sqli_boolean(FakeFetcher(_boolean_responder), URL, PARAM)
    assert len(findings) == 1
    assert "Boolean" in findings[0].title


async def test_sqli_false_positive_similar_responses():
    """A page that returns the same content regardless of input must not be
    reported as boolean SQLi."""
    findings = await check_sqli_boolean(
        FakeFetcher(lambda url, **k: ok_result(url, text="<p>Stable page.</p>")), URL, PARAM
    )
    assert findings == []


async def test_sqli_normal_input():
    """No SQL error and stable responses -> no error/boolean finding."""
    fetcher = FakeFetcher(lambda url, **k: ok_result(url, text="<p>catalogue</p>"))
    assert await check_sqli_error(fetcher, URL, PARAM) == []
    assert await check_sqli_boolean(fetcher, URL, PARAM) == []


# --- time based ------------------------------------------------------------ #
async def test_sqli_time_based():
    """Injected measure: the delay payload is ~2s slower than the control."""
    async def measure(payload):
        elapsed = 2.1 if "SLEEP(2" in payload else 0.02
        return ok_result("https://example.com/items"), elapsed

    findings = await check_sqli_time(None, URL, PARAM, measure=measure,
                                     delay_seconds=2.0, threshold=1.5)
    assert len(findings) == 1
    assert "Time-based" in findings[0].title


async def test_sqli_time_based_slow_server_not_flagged():
    """A uniformly slow server (control and delay both slow) must not trigger,
    because only the *difference* matters."""
    async def measure(payload):
        return ok_result("https://example.com/items"), 3.0  # everything is slow
    findings = await check_sqli_time(None, URL, PARAM, measure=measure,
                                     delay_seconds=2.0, threshold=1.5)
    assert findings == []


# --- database fingerprint -------------------------------------------------- #
def test_sqli_database_fingerprint():
    assert sql_database_family("You have an error in your SQL syntax; MySQL server") == "MySQL"
    assert sql_database_family("PostgreSQL ERROR: syntax error at or near") == "PostgreSQL"
    assert sql_database_family("ORA-00933: SQL command not properly ended") == "Oracle"
    assert sql_database_family("Microsoft OLE DB Provider for SQL Server") == "Microsoft SQL Server"
    assert sql_database_family("sqlite3.OperationalError: near") == "SQLite"
    assert sql_database_family("a perfectly normal page") is None
