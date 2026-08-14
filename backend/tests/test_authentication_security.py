"""Authentication & session-security tests (Phase 2)."""
from app.services.auth_checks import (
    check_logout_invalidation, check_reset_token_reuse, check_session_expiration,
    check_session_rotation, check_username_enumeration,
)
from fixtures import FakeFetcher, ok_result

LOGIN = "https://example.com/auth/login"
PROTECTED = "https://example.com/account"
LOGOUT = "https://example.com/auth/logout"
RESET = "https://example.com/auth/reset"


# --- username enumeration -------------------------------------------------- #
async def test_auth_username_enumeration():
    def responder(url, **k):
        user = (k.get("json") or {}).get("username")
        if user == "admin":
            return ok_result(url, status_code=401, text="Incorrect password for admin.")
        return ok_result(url, status_code=404, text="No such user.")
    findings = await check_username_enumeration(
        FakeFetcher(responder), LOGIN, valid_username="admin", invalid_username="ghost")
    assert len(findings) == 1
    assert findings[0].dedup_key.startswith("username_enumeration")


async def test_auth_enumeration_secure_negative():
    """Uniform generic error for both -> no enumeration."""
    def responder(url, **k):
        return ok_result(url, status_code=401, text="Invalid username or password.")
    findings = await check_username_enumeration(
        FakeFetcher(responder), LOGIN, valid_username="admin", invalid_username="ghost")
    assert findings == []


# --- session rotation / fixation ------------------------------------------- #
async def test_auth_session_rotation():
    """Session id unchanged after login -> fixation."""
    def responder(url, **k):
        return ok_result(url, text="ok", headers={"set-cookie": "sid=FIXED123; Path=/"})
    findings = await check_session_rotation(
        FakeFetcher(responder), LOGIN, login_data={"username": "admin", "password": "admin-pass"})
    assert len(findings) == 1
    assert findings[0].dedup_key.startswith("session_fixation")


async def test_auth_session_rotation_secure_negative():
    """A fresh id is issued at login -> not vulnerable."""
    seq = {"n": 0}
    def responder(url, **k):
        seq["n"] += 1
        sid = "PRE000" if seq["n"] == 1 else "POST999"
        return ok_result(url, text="ok", headers={"set-cookie": f"sid={sid}; Path=/"})
    findings = await check_session_rotation(
        FakeFetcher(responder), LOGIN, login_data={"username": "admin", "password": "admin-pass"})
    assert findings == []


# --- logout invalidation --------------------------------------------------- #
async def test_auth_logout_invalidation():
    """Protected resource still reachable after logout -> vulnerable."""
    def responder(url, **k):
        if url.endswith("/logout"):
            return ok_result(url, text="logged out")
        return ok_result(url, status_code=200, text="account page")  # always accessible
    findings = await check_logout_invalidation(
        FakeFetcher(responder), PROTECTED, LOGOUT, session_cookie="sid=abc")
    assert len(findings) == 1
    assert findings[0].dedup_key.startswith("broken_logout")


async def test_auth_logout_invalidation_secure_negative():
    state = {"active": True}
    def responder(url, **k):
        if url.endswith("/logout"):
            state["active"] = False
            return ok_result(url, text="logged out")
        if state["active"]:
            return ok_result(url, status_code=200, text="account page")
        return ok_result(url, status_code=401, text="unauthorized")
    findings = await check_logout_invalidation(
        FakeFetcher(responder), PROTECTED, LOGOUT, session_cookie="sid=abc")
    assert findings == []


# --- session expiration ---------------------------------------------------- #
async def test_auth_expired_session():
    """A stale session is still accepted -> vulnerable."""
    findings = await check_session_expiration(
        FakeFetcher(lambda url, **k: ok_result(url, status_code=200, text="account")),
        PROTECTED, expired_cookie="sid=stale-old")
    assert len(findings) == 1
    assert findings[0].dedup_key.startswith("session_expiration")


async def test_auth_expired_session_secure_negative():
    findings = await check_session_expiration(
        FakeFetcher(lambda url, **k: ok_result(url, status_code=401, text="expired")),
        PROTECTED, expired_cookie="sid=stale-old")
    assert findings == []


# --- reset token reuse ----------------------------------------------------- #
async def test_auth_reset_token_reuse():
    def responder(url, **k):
        token = (k.get("json") or {}).get("token")
        if token == "valid-reset-token":
            return ok_result(url, text='{"reset": true}', content_type="application/json")
        return ok_result(url, status_code=400, text='{"error": "invalid token"}',
                         content_type="application/json")
    findings = await check_reset_token_reuse(
        FakeFetcher(responder), RESET, token="valid-reset-token")
    assert len(findings) == 1
    assert findings[0].dedup_key.startswith("reset_token_reuse")


async def test_auth_reset_invalid_token_negative():
    def responder(url, **k):
        return ok_result(url, status_code=400, text='{"error": "invalid token"}',
                         content_type="application/json")
    findings = await check_reset_token_reuse(
        FakeFetcher(responder), RESET, token="bogus")
    assert findings == []


async def test_auth_negative_case():
    """A single-use token consumed on first use -> no reuse finding."""
    calls = {"n": 0}
    def responder(url, **k):
        calls["n"] += 1
        if calls["n"] == 1:
            return ok_result(url, text='{"reset": true}', content_type="application/json")
        return ok_result(url, status_code=400, text='{"error": "invalid token"}',
                         content_type="application/json")
    findings = await check_reset_token_reuse(
        FakeFetcher(responder), RESET, token="one-time-token")
    assert findings == []
