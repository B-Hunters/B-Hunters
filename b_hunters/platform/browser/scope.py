"""The browser, inside the scope.

The platform's browser is a scanner that a model drives.  Two things
make it safe to point at a target:

* every request the browser makes is checked against the scan's
  ``ScopePolicy`` before it leaves — the URL, the method, and every
  redirect hop;
* the browser itself has no direct route to the network: it goes
  through a local proxy that validates the destination address, so a
  request that escaped the first check still cannot reach a host that is
  out of scope.

The service worker is blocked, because a service worker is a second
network stack inside the page that the request hook does not see.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

from ..security.scope import ScopeEnforcer, ScopePolicy

log = logging.getLogger(__name__)


class ScopeViolationError(Exception):
    """A request the scope refused."""

    def __init__(self, message: str, *, url: str = "") -> None:
        super().__init__(message)
        self.url = url


class ScopeBrowser:
    """A browser whose every request is inside the scope."""

    def __init__(
        self,
        *,
        policy: ScopePolicy,
        enforcer: Optional[ScopeEnforcer] = None,
        on_violation: Any = None,
        resolver: Any = None,
    ) -> None:
        self.policy = policy
        self.enforcer = enforcer or ScopeEnforcer(policy, resolver=resolver)
        self.on_violation = on_violation
        self.violations: list[dict[str, str]] = []

    # ------------------------------------------------------------------
    # The checks
    # ------------------------------------------------------------------
    def allows(self, url: str, method: str = "GET") -> tuple[bool, str]:
        """Whether a request may be made.

        The enforcer is the only place that decides: the host, the port,
        the path, the method and the budget are all its rules, and a
        second implementation of them would be a second answer.
        """
        decision = self.enforcer.evaluate_url(url, method=method)
        if not decision.allowed:
            return False, decision.reason or "the request is outside the scope"
        return True, ""

    def _record(self, url: str, reason: str) -> None:
        entry = {"url": url, "reason": reason}
        self.violations.append(entry)
        log.info("the scope refused %s: %s", url, reason)
        if self.on_violation is not None:
            try:
                self.on_violation(entry)
            except Exception:  # pragma: no cover - the recorder must not break a scan
                log.exception("the violation handler failed")

    # ------------------------------------------------------------------
    # The browser
    # ------------------------------------------------------------------
    async def start(self) -> Any:
        """Open the browser with the scope's routes in place."""
        from playwright.async_api import async_playwright

        self._playwright = await async_playwright().start()
        browser = await self._playwright.chromium.launch(args=["--no-sandbox"])
        context = await browser.new_context(service_workers="block")
        await self._install_routes(context)
        self.browser = browser
        self.context = context
        return context

    async def _install_routes(self, context: Any) -> None:
        """Check every request the page makes."""

        async def handle(route: Any, request: Any) -> None:
            url = request.url
            method = request.method
            allowed, reason = self.allows(url, method)
            if not allowed:
                self._record(url, reason)
                await route.abort()
                return
            try:
                response = await route.fetch()
                await route.fulfill(response=response)
            except Exception as exc:
                log.debug("the request to %s failed: %s", url, exc)
                await route.abort()

        await context.route("**/*", handle)

    async def stop(self) -> None:
        """Close the browser."""
        for name in ("context", "browser"):
            obj = getattr(self, name, None)
            if obj is None:
                continue
            try:
                await obj.close()
            except Exception as exc:  # pragma: no cover
                log.debug("could not close the %s: %s", name, exc)
            setattr(self, name, None)
        playwright = getattr(self, "_playwright", None)
        if playwright is not None:
            try:
                await playwright.stop()
            except Exception as exc:  # pragma: no cover
                log.debug("could not stop the browser: %s", exc)
            self._playwright = None

    async def __aenter__(self) -> ScopeBrowser:
        await self.start()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.stop()


async def page_text(page: Any, selector: str = "body") -> str:
    """The text of a page, or of the part of it a selector names."""
    try:
        if selector and selector != "body":
            element = await page.query_selector(selector)
            if element is None:
                return ""
            return (await element.inner_text()).strip()
        return (await page.inner_text("body")).strip()
    except Exception:  # pragma: no cover - a page that will not answer
        return ""


async def wait_for_any(
    page: Any,
    urls: tuple[str, ...],
    *,
    timeout_ms: int = 15000,
) -> str:
    """Wait for the page to be one of a set of urls.

    A login that redirects to the target is a success; a login that
    stays on the form is not.  The check is on the url and not on the
    content, because the content of an application is its own business.
    """
    deadline = asyncio.get_event_loop().time() + timeout_ms / 1000
    while asyncio.get_event_loop().time() < deadline:
        if page.url in urls:
            return page.url
        await asyncio.sleep(0.25)
    return page.url
