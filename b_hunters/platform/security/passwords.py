"""Password hashing and credential helpers.

Argon2id is used because it is the current OWASP recommendation for
password storage and is memory-hard, which limits offline guessing on a
leaked hash database.
"""

from __future__ import annotations

import hmac
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=64 * 1024,
    parallelism=2,
    hash_len=32,
    salt_len=16,
)

#: Dummy hash used to equalise timing when a user does not exist.
_DUMMY_HASH = _hasher.hash("b-hunters-timing-equaliser")


def hash_password(password: str) -> str:
    """Hash a plaintext password with Argon2id."""
    if not password:
        raise ValueError("password must not be empty")
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    """Verify *password* against *password_hash*.

    Returns ``False`` rather than raising for unknown or malformed hashes so
    that callers cannot distinguish the failure modes.
    """
    if not password_hash:
        # Still burn a hash so that "no such user" and "wrong password" take
        # a comparable amount of time.
        try:
            _hasher.verify(_DUMMY_HASH, password or "")
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            pass
        return False
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    """Return ``True`` when *password_hash* uses outdated parameters."""
    try:
        return _hasher.check_needs_rehash(password_hash)
    except (InvalidHashError, ValueError):
        return True


def validate_password_strength(password: str, *, min_length: int = 12) -> list[str]:
    """Return a list of human readable problems with *password*."""
    problems: list[str] = []
    if not password or len(password) < min_length:
        problems.append(f"password must be at least {min_length} characters long")
    if password and len(password) > 256:
        problems.append("password must be at most 256 characters long")
    classes = sum(
        [
            any(c.islower() for c in password or ""),
            any(c.isupper() for c in password or ""),
            any(c.isdigit() for c in password or ""),
            any(not c.isalnum() for c in password or ""),
        ]
    )
    if password and classes < 3:
        problems.append("password must mix at least three of: lowercase, uppercase, digits, symbols")
    return problems


def constant_time_equals(left: str, right: str) -> bool:
    """Timing-safe string comparison."""
    return hmac.compare_digest((left or "").encode("utf-8"), (right or "").encode("utf-8"))


def generate_token(nbytes: int = 32) -> str:
    """Generate a URL-safe random token."""
    return secrets.token_urlsafe(nbytes)
