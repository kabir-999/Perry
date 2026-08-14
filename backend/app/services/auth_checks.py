"""
Authentication & session-security detectors (Phase 2).

Same contract as ``security_checks`` / ``phase2_checks``: async functions that
take a ``Fetcher``, send a small bounded set of requests, and return
``FindingCandidate`` objects backed by concrete evidence.

Safety: these detectors never guess real credentials, never brute-force, and
never reset arbitrary accounts. They rely on caller-supplied test identities /
tokens against an authorized target.
"""
from __future__ import annotations

import re

from app.services.finding_types import FindingCandidate
from app.services.response_analyzer import analyze, jaccard


def _cookie_value(set_cookie: str | None, name: str = "sid") -> str | None:
    if not set_cookie:
        return None
    m = re.search(rf"\b{re.escape(name)}=([^;,\s]+)", set_cookie)
    return m.group(1) if m else None


def _path(url: str) -> str:
    from urllib.parse import urlsplit
    return urlsplit(url).path or "/"


# --------------------------------------------------------------------------- #
# Username enumeration
# --------------------------------------------------------------------------- #
async def check_username_enumeration(
    fetcher, login_url: str, *,
    valid_username: str, invalid_username: str,
    password: str = "wrong-Password-000", threshold: float = 0.9,
) -> list[FindingCandidate]:
    """A valid-username/wrong-password attempt should be indistinguishable from
    an unknown-username attempt. If they differ (status or body), the app leaks
    which usernames exist."""
    r_valid = await fetcher.fetch(
        login_url, method="POST",
        json={"username": valid_username, "password": password}, use_cache=False,
    )
    r_invalid = await fetcher.fetch(
        login_url, method="POST",
        json={"username": invalid_username, "password": password}, use_cache=False,
    )
    if not (r_valid.ok and r_invalid.ok):
        return []
    sim = jaccard(analyze(r_valid).shingles, analyze(r_invalid).shingles)
    status_diff = r_valid.status_code != r_invalid.status_code
    if status_diff or sim < threshold:
        return [
            FindingCandidate(
                title="Username enumeration via login responses",
                category="authentication",
                severity="low",
                confidence="confirmed",
                url=login_url, method="POST", parameter="username",
                evidence=(
                    f"Valid user '{valid_username}' (HTTP {r_valid.status_code}) and "
                    f"unknown user '{invalid_username}' (HTTP {r_invalid.status_code}) "
                    f"produced distinguishable responses (similarity {sim:.2f})."
                ),
                request_summary=f"POST {login_url} (valid vs invalid username)",
                response_summary=f"status_diff={status_diff}, body_similarity={sim:.2f}",
                description="The login endpoint responds differently for existing vs "
                "non-existing usernames, allowing account enumeration.",
                impact="Lets an attacker build a list of valid accounts for targeted attacks.",
                remediation="Return an identical generic error and status for all failed "
                "logins; apply uniform timing.",
                dedup_key=f"username_enumeration|{_path(login_url)}",
            )
        ]
    return []


# --------------------------------------------------------------------------- #
# Session fixation (identifier not rotated on authentication)
# --------------------------------------------------------------------------- #
async def check_session_rotation(
    fetcher, login_url: str, *, login_data: dict, pre_url: str | None = None,
    cookie_name: str = "sid",
) -> list[FindingCandidate]:
    """The session identifier must change after a successful login. If the
    pre-auth id is still valid post-auth, the app is vulnerable to fixation."""
    pre = await fetcher.fetch(pre_url or login_url, use_cache=False)
    pre_sid = _cookie_value(pre.headers.get("set-cookie"), cookie_name)
    post = await fetcher.fetch(login_url, method="POST", data=login_data, use_cache=False)
    post_sid = _cookie_value(post.headers.get("set-cookie"), cookie_name)
    if pre_sid and post_sid and pre_sid == post_sid:
        return [
            FindingCandidate(
                title="Session fixation (identifier not rotated on login)",
                category="authentication",
                severity="medium",
                confidence="confirmed",
                url=login_url, method="POST", parameter=cookie_name,
                evidence=f"Session id '{pre_sid}' was unchanged before and after "
                "authentication.",
                request_summary=f"GET {pre_url or login_url} -> POST {login_url}",
                response_summary="pre-auth and post-auth session ids are identical",
                description="The application keeps the pre-authentication session "
                "identifier after login, enabling session fixation.",
                impact="An attacker who fixes a victim's session id gains their "
                "authenticated session.",
                remediation="Issue a fresh session id on every privilege change / login.",
                dedup_key=f"session_fixation|{_path(login_url)}",
            )
        ]
    return []


# --------------------------------------------------------------------------- #
# Logout invalidation / session expiration (server-side validity)
# --------------------------------------------------------------------------- #
async def _resource_status(fetcher, url, cookie):
    return await fetcher.fetch(url, headers={"Cookie": cookie}, use_cache=False)


async def check_logout_invalidation(
    fetcher, protected_url: str, logout_url: str, *, session_cookie: str,
) -> list[FindingCandidate]:
    """After logout, the same session cookie must no longer grant access."""
    before = await _resource_status(fetcher, protected_url, session_cookie)
    if not (before.ok and before.status_code == 200):
        return []  # no authenticated baseline to reason about
    await fetcher.fetch(logout_url, headers={"Cookie": session_cookie}, use_cache=False)
    after = await _resource_status(fetcher, protected_url, session_cookie)
    if after.ok and after.status_code == 200:
        return [
            FindingCandidate(
                title="Session not invalidated on logout",
                category="authentication",
                severity="medium",
                confidence="confirmed",
                url=protected_url, method="GET", parameter="",
                evidence=f"The session cookie still returned HTTP 200 from "
                f"{protected_url} after calling {logout_url}.",
                request_summary=f"GET {protected_url} -> GET {logout_url} -> GET {protected_url}",
                response_summary="protected resource still accessible post-logout",
                description="Logout does not invalidate the server-side session, so a "
                "captured session remains usable.",
                impact="Stolen or shared sessions stay valid after the user logs out.",
                remediation="Destroy the server-side session on logout and rotate the id.",
                dedup_key=f"broken_logout|{_path(protected_url)}",
            )
        ]
    return []


async def check_session_expiration(
    fetcher, protected_url: str, *, expired_cookie: str,
) -> list[FindingCandidate]:
    """A session the server should treat as expired must be rejected."""
    res = await _resource_status(fetcher, protected_url, expired_cookie)
    if res.ok and res.status_code == 200:
        return [
            FindingCandidate(
                title="Expired/stale session still accepted",
                category="authentication",
                severity="medium",
                confidence="confirmed",
                url=protected_url, method="GET", parameter="",
                evidence=f"A stale session cookie returned HTTP 200 from {protected_url}.",
                request_summary=f"GET {protected_url} with a stale session",
                response_summary="stale session accepted",
                description="The server does not enforce session expiration; old "
                "session identifiers keep working indefinitely.",
                impact="Captured sessions never expire server-side.",
                remediation="Enforce absolute and idle session timeouts server-side.",
                dedup_key=f"session_expiration|{_path(protected_url)}",
            )
        ]
    return []


# --------------------------------------------------------------------------- #
# Password-reset token reuse
# --------------------------------------------------------------------------- #
def _reset_ok(res) -> bool:
    return res.ok and res.status_code in (200, 204) and "invalid" not in res.text.lower()


async def check_reset_token_reuse(
    fetcher, reset_url: str, *, token: str, new_password: str = "New-Passw0rd!",
) -> list[FindingCandidate]:
    """A single-use reset token must be rejected on a second use."""
    first = await fetcher.fetch(
        reset_url, method="POST",
        json={"token": token, "password": new_password}, use_cache=False,
    )
    if not _reset_ok(first):
        return []  # the token was not accepted even once (e.g. invalid token)
    second = await fetcher.fetch(
        reset_url, method="POST",
        json={"token": token, "password": new_password}, use_cache=False,
    )
    if _reset_ok(second):
        return [
            FindingCandidate(
                title="Password-reset token can be reused",
                category="authentication",
                severity="high",
                confidence="confirmed",
                url=reset_url, method="POST", parameter="token",
                evidence=f"Reset token was accepted on two consecutive uses "
                f"(HTTP {first.status_code} then {second.status_code}).",
                request_summary=f"POST {reset_url} x2 with the same token",
                response_summary="token accepted more than once",
                description="Password-reset tokens are not invalidated after use, so a "
                "leaked token can be replayed.",
                impact="A captured reset link allows repeated account takeover.",
                remediation="Invalidate reset tokens on first use and expire them quickly.",
                dedup_key=f"reset_token_reuse|{_path(reset_url)}",
            )
        ]
    return []
