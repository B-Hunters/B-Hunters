"""Session management and CSRF protection.

Sessions are server-side records stored in MongoDB.  The browser only
receives an opaque, random session identifier in an ``HttpOnly`` cookie, so
revoking a session is immediate and a stolen cookie carries no
credentials.

CSRF protection uses the double-submit cookie pattern: a random token is
issued in a readable cookie and must be echoed back in the
``X-CSRF-Token`` header on every unsafe request.  Because the cookie is
``SameSite=Lax`` and the header is required, a cross-site form post cannot
succeed.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Optional

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})


@dataclass(frozen=True)
class Session:
    """A persisted user session."""

    session_id: str
    user_id: str
    username: str
    role: str
    csrf_token: str
    created_at: float
    expires_at: float
    last_seen_at: float
    ip_address: str = ""
    user_agent: str = ""

    @property
    def is_expired(self) -> bool:
        return time.time() >= self.expires_at

    def to_public_dict(self) -> dict[str, Any]:
        """Serialise the session without the session identifier itself."""
        return {
            "user_id": self.user_id,
            "username": self.username,
            "role": self.role,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "last_seen_at": self.last_seen_at,
        }


def generate_session_id() -> str:
    """Create an opaque 256-bit session identifier."""
    return secrets.token_urlsafe(32)


def generate_csrf_token() -> str:
    """Create a CSRF token."""
    return secrets.token_urlsafe(32)


def hash_session_id(session_id: str) -> str:
    """Hash a session id for storage so a database leak is not directly usable."""
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()


def verify_csrf(expected: str | None, provided: str | None) -> bool:
    """Constant-time comparison of the expected and provided CSRF tokens."""
    if not expected or not provided:
        return False
    return hmac.compare_digest(expected.encode("utf-8"), provided.encode("utf-8"))


def requires_csrf(method: str, content_type: str = "") -> bool:
    """Return ``True`` when the request needs a CSRF token."""
    if (method or "GET").upper() in SAFE_METHODS:
        return False
    return True


def build_session(
    *,
    session_id: str,
    user_id: str,
    username: str,
    role: str,
    ttl_seconds: int,
    ip_address: str = "",
    user_agent: str = "",
) -> Session:
    """Create a new :class:`Session` record."""
    now = time.time()
    return Session(
        session_id=session_id,
        user_id=user_id,
        username=username,
        role=role,
        csrf_token=generate_csrf_token(),
        created_at=now,
        expires_at=now + ttl_seconds,
        last_seen_at=now,
        ip_address=ip_address or "",
        user_agent=(user_agent or "")[:512],
    )


def set_session_cookies(
    response,
    session: Session,
    *,
    cookie_name: str = "bh_session",
    csrf_cookie_name: str = "bh_csrf",
    secure: bool = False,
    samesite: str = "Lax",
    max_age: Optional[int] = None,
) -> None:
    """Attach the session and CSRF cookies to an HTTP response."""
    age = int(max_age if max_age is not None else max(0, session.expires_at - time.time()))
    response.set_cookie(
        cookie_name,
        session.session_id,
        httponly=True,
        secure=secure,
        samesite=samesite,
        max_age=age,
        path="/",
    )
    # Readable by the frontend so it can echo the token back in a header.
    response.set_cookie(
        csrf_cookie_name,
        session.csrf_token,
        httponly=False,
        secure=secure,
        samesite=samesite,
        max_age=age,
        path="/",
    )


def clear_session_cookies(
    response,
    *,
    cookie_name: str = "bh_session",
    csrf_cookie_name: str = "bh_csrf",
    secure: bool = False,
    samesite: str = "Lax",
) -> None:
    """Remove the session and CSRF cookies."""
    response.delete_cookie(cookie_name, path="/", secure=secure, httponly=True, samesite=samesite)
    response.delete_cookie(csrf_cookie_name, path="/", secure=secure, httponly=False, samesite=samesite)


class LoginThrottle:
    """Per-username + per-IP login throttling.

    Keeps a small in-memory window of failed attempts.  This protects a
    single node; a multi-node deployment should additionally share the
    counters through MongoDB (see :meth:`LoginThrottle.persist_failure`).
    """

    def __init__(self, max_attempts: int = 5, lockout_seconds: int = 300) -> None:
        self.max_attempts = max(1, int(max_attempts))
        self.lockout_seconds = int(lockout_seconds)
        self._failures: dict[str, list[float]] = {}
        self._locked_until: dict[str, float] = {}

    @staticmethod
    def _keys(username: str, ip_address: str) -> tuple[str, str]:
        return (username or "").lower(), ip_address or ""

    def is_locked(self, username: str, ip_address: str = "") -> bool:
        now = time.time()
        for key in self._keys(username, ip_address):
            until = self._locked_until.get(key, 0.0)
            if until > now:
                return True
            if until:
                self._locked_until.pop(key, None)
        return False

    def remaining_lockout(self, username: str, ip_address: str = "") -> int:
        now = time.time()
        remaining = 0
        for key in self._keys(username, ip_address):
            remaining = max(remaining, int(self._locked_until.get(key, 0.0) - now))
        return max(0, remaining)

    def register_failure(self, username: str, ip_address: str = "") -> int:
        now = time.time()
        attempts = 0
        for key in self._keys(username, ip_address):
            bucket = [t for t in self._failures.get(key, []) if now - t < self.lockout_seconds]
            bucket.append(now)
            self._failures[key] = bucket
            attempts = max(attempts, len(bucket))
            if len(bucket) >= self.max_attempts:
                self._locked_until[key] = now + self.lockout_seconds
        return attempts

    def register_success(self, username: str, ip_address: str = "") -> None:
        for key in self._keys(username, ip_address):
            self._failures.pop(key, None)
            self._locked_until.pop(key, None)

    def reset(self) -> None:
        self._failures.clear()
        self._locked_until.clear()


def session_to_dict(session: Session) -> Mapping[str, Any]:
    """Storage representation of a session."""
    return {
        "session_id_hash": hash_session_id(session.session_id),
        "user_id": session.user_id,
        "username": session.username,
        "role": session.role,
        "csrf_token": session.csrf_token,
        "created_at": session.created_at,
        "expires_at": session.expires_at,
        "last_seen_at": session.last_seen_at,
        "ip_address": session.ip_address,
        "user_agent": session.user_agent,
    }
