"""The browser: the scope-routed browser and the login recorder."""

from .login import LoginError, record_login, store_session
from .scope import ScopeBrowser, ScopeViolationError

__all__ = [
    "LoginError",
    "ScopeBrowser",
    "ScopeViolationError",
    "record_login",
    "store_session",
]
