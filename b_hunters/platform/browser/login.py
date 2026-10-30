"""The login recorder.

A scan can log in: it fills the target's login form, keeps the session
and uses it for the rest of the scan.  That is what makes the
vulnerabilities behind a login reachable at all — the WebGoat lessons,
the Juice Shop basket, an admin panel — and they are the majority of
what an application actually exposes.

The recorder runs in the runner, not in the API: it needs the browser
and the credentials, and the API does not decrypt.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Optional

from ..db.identities import IdentityRepository
from ..security.scope import ScopeEnforcer, build_policy_from_scan
from .scope import ScopeBrowser, page_text, wait_for_any

log = logging.getLogger(__name__)


class LoginError(Exception):
    """The login did not produce a session."""


def _totp(secret: str) -> str:
    """The one-time password of a secret, when the identity has one."""
    if not secret:
        return ""
    try:
        import pyotp

        return pyotp.TOTP(secret).now()
    except Exception as exc:  # pragma: no cover - a malformed secret
        log.warning("could not generate a one-time password: %s", exc)
        return ""


async def record_login(
    *,
    identity: dict[str, Any],
    secrets: dict[str, Any],
    authorized_hosts: Optional[list[str]] = None,
    timeout_seconds: int = 90,
) -> dict[str, Any]:
    """Log in and keep the session.

    Returns the state of the attempt: ``verified`` when the session
    works, ``failed`` when it does not, and the reason either way.  The
    session itself is returned so that the caller can store it; it is
    never logged.
    """
    login_url = str(identity.get("login_url", "") or "")
    verify_url = str(identity.get("verify_url", "") or "")
    success_url = str(identity.get("success_url", "") or "")
    if not login_url:
        return {"status": "failed", "reason": "the identity has no login url", "storage_state": None}

    hosts = list(authorized_hosts or [])
    if not hosts:
        from urllib.parse import urlsplit

        hosts = [urlsplit(login_url).hostname or ""]
    policy = build_policy_from_scan(
        authorized_hosts=[host for host in hosts if host],
        excluded_paths=[],
        allow_private_network=True,
        allow_http=True,
        allow_state_changing=False,
    )
    enforcer = ScopeEnforcer(policy)

    username = str(identity.get("username", "") or "")
    password = str(secrets.get("password", "") or "")
    username_field = str(identity.get("username_field", "") or "username")
    password_field = str(identity.get("password_field", "") or "password")
    totp_secret = str(secrets.get("totp_secret", "") or "")

    browser = ScopeBrowser(policy=policy, enforcer=enforcer)
    try:
        await browser.start()
        page = await browser.context.new_page()

        # The login itself is a POST, which the scope refuses by
        # default.  It is the one request that has to be allowed, and
        # only to the login page.
        await _allow_login(browser, login_url)

        await page.goto(login_url, wait_until="domcontentloaded", timeout=timeout_seconds * 1000)

        await _fill(page, username_field, username)
        await _fill(page, password_field, password)
        code_field = await _find_field(page, ("otp", "totp", "code", "mfa", "2fa"))
        if code_field and totp_secret:
            await _fill(page, code_field, _totp(totp_secret))

        await page.keyboard.press("Enter")
        await wait_for_any(
            page,
            tuple(url for url in (success_url, verify_url) if url),
            timeout_ms=timeout_seconds * 1000,
        )

        storage_state = await browser.context.storage_state()
        verified, reason = await _verify(browser, page, verify_url, identity)
        if not verified:
            return {"status": "failed", "reason": reason, "storage_state": storage_state}
        return {
            "status": "verified",
            "reason": "",
            "storage_state": storage_state,
            "verified_at": time.time(),
        }
    except Exception as exc:
        log.warning("the login of %s failed: %s", identity.get("name", ""), exc)
        return {
            "status": "failed",
            "reason": f"{type(exc).__name__}: {exc}",
            "storage_state": None,
        }
    finally:
        await browser.stop()


async def _allow_login(browser: ScopeBrowser, login_url: str) -> None:
    """Let the login form be submitted.

    The scope refuses a POST by default, and the login is a POST.  It
    is allowed to one url — the login page — and to nothing else.
    """
    original = browser.allows

    def allows(url: str, method: str = "GET") -> tuple[bool, str]:
        if method.upper() not in browser.policy.safe_methods and url == login_url:
            return True, ""
        return original(url, method)

    browser.allows = allows  # type: ignore[method-assign]


async def _fill(page: Any, field: str, value: str) -> None:
    """Fill one field of a form, when there is one."""
    if not field or not value:
        return
    selectors = (
        f"input[name='{field}']",
        f"input[id='{field}']",
        f"input[placeholder*='{field}' i]",
        f"input[type='{field}']",
    )
    for selector in selectors:
        try:
            element = await page.query_selector(selector)
        except Exception:
            element = None
        if element is None:
            continue
        try:
            await element.fill(value)
            return
        except Exception as exc:
            log.debug("could not fill the field %s: %s", field, exc)
            continue


async def _find_field(page: Any, names: tuple[str, ...]) -> str:
    """The name of a field, when the form has one."""
    for name in names:
        try:
            element = await page.query_selector(f"input[name*='{name}' i]")
        except Exception:
            element = None
        if element is not None:
            try:
                return await element.get_attribute("name") or name
            except Exception:
                return name
    return ""


async def _verify(
    browser: ScopeBrowser,
    page: Any,
    verify_url: str,
    identity: dict[str, Any],
) -> tuple[bool, str]:
    """Check that the session works.

    A login page that is reachable without a session proves nothing, so
    the check is made against a page that *requires* the session.  When
    the identity names none, the check falls back to the content of the
    page the login led to.
    """
    if not verify_url:
        text = await page_text(page)
        selector = str(identity.get("success_selector", "") or "")
        if selector:
            return (True, "") if text else (False, "the page after the login is empty")
        return (True, "") if text else (False, "the page after the login is empty")

    try:
        await page.goto(verify_url, wait_until="domcontentloaded", timeout=30000)
    except Exception as exc:
        return False, f"the protected page could not be loaded: {exc}"

    if page.url != verify_url:
        # The application redirected away from the protected page: the
        # session did not take.
        return False, f"the protected page redirected to {page.url}"

    selector = str(identity.get("verify_selector", "") or "")
    expected = str(identity.get("verify_text", "") or "")
    if selector:
        try:
            element = await page.query_selector(selector)
        except Exception:
            element = None
        if element is None:
            return False, f"the protected page has no {selector}"
        return True, ""
    if expected:
        text = await page_text(page)
        if expected.lower() not in text.lower():
            return False, f"the protected page does not show {expected!r}"
        return True, ""
    return True, ""


def store_session(
    repository: IdentityRepository,
    identity_id: str,
    result: dict[str, Any],
) -> bool:
    """Store the session of a login attempt."""
    state = result.get("storage_state")
    if not state:
        return False
    return repository.set_session(
        identity_id,
        storage_state=state,
        expires_at=result.get("verified_at"),
    )
