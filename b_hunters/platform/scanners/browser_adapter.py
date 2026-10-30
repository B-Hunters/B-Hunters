"""The browser crawler.

The HTTP crawler sees the server's answers.  The browser crawler sees
what the *page* asks for: the routes a single-page application defines
in JavaScript, the endpoints it fetches, the hash routes it navigates
to.  An application whose API is only reachable from its own front end
is invisible to a crawler that only follows links.

The crawler drives the same scope-routed browser the agents use, so
every request it makes is checked against the scan's scope before it
leaves, and the service worker is blocked — a service worker is a second
network stack inside the page that the request hook does not see.

Only metadata is recorded.  A body is read to find the references and
is never stored.
"""

from __future__ import annotations

import logging
from collections import deque
from typing import Any
from urllib.parse import urljoin, urlsplit

from ..assets import is_external, normalise_url
from .base import ScanRequest, ScanResult

log = logging.getLogger(__name__)

#: The most URLs the crawler records.
ASSET_LIMIT = 500

#: How deep it follows.
MAX_DEPTH = 3

#: The schemes that are not a URL to fetch.
NON_HTTP_SCHEMES = ("javascript:", "mailto:", "tel:", "data:", "about:", "blob:")


async def browser_crawl_executor(request: ScanRequest) -> ScanResult:
    """Crawl the target with a browser and record every URL it saw.

    It follows the links the page carries, the endpoints the page asks
    for over XHR or fetch, and the hash routes it navigates to.  A
    reference to another host is recorded as an external reference and
    is never fetched.
    """
    from ..browser.scope import ScopeBrowser

    authorized = _authorized_hosts(request)
    assets: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    seen: set[str] = set()
    queue: deque[tuple[str, int]] = deque()

    for raw in _seeds(request, authorized):
        url = normalise_url(raw)
        if not url or url in seen:
            continue
        seen.add(url)
        queue.append((raw, 0))

    browser = None
    try:
        policy = getattr(request.scope, "policy", None)
        if policy is None:
            from ..security.scope import build_policy_from_scan

            policy = build_policy_from_scan(
                authorized_hosts=authorized,
                allow_private_network=True,
                allow_http=True,
            )
        browser = ScopeBrowser(policy=policy)
        await browser.start()
        page = await browser.page()

        while queue:
            if len(assets) >= ASSET_LIMIT:
                break
            raw, depth = queue.popleft()
            url = normalise_url(raw)
            item = assets.setdefault(url, _item(url, depth=depth))
            if is_external(url, authorized):
                item["scope"] = "external"

            try:
                await page.goto(raw, wait_until="domcontentloaded", timeout=15000)
            except Exception as exc:
                errors.append(f"{url}: {type(exc).__name__}")
                continue

            for reference in await _references(page, raw):
                child = normalise_url(reference)
                if not child or child in seen:
                    continue
                seen.add(child)
                if depth + 1 <= MAX_DEPTH:
                    queue.append((child, depth + 1))
    except Exception as exc:
        log.warning("the browser crawl failed: %s", exc)
        errors.append(f"{type(exc).__name__}: {exc}")
    finally:
        if browser is not None:
            await browser.stop()

    return ScanResult(
        scanner="browser_crawl",
        ok=not errors,
        error="; ".join(errors[:5]),
        kind="url",
        items=list(assets.values()),
        metadata={
            "assets": len(assets),
            "external": sum(1 for item in assets.values() if item["scope"] == "external"),
            "targets_checked": len(request.targets),
            "max_depth": MAX_DEPTH,
        },
    )


async def _references(page: Any, base: str) -> list[str]:
    """The URLs the page asked for.

    Three kinds: the links it carries, the endpoints it fetches over
    XHR or fetch, and the hash routes it navigates to.  The first two
    are read from the page's own state; the third is read from the
    links, because a hash route is a link whose fragment is the route.
    """
    found: list[str] = []

    for selector in ("a[href]", "script[src]", "link[href]", "img[src]", "iframe[src]"):
        try:
            elements = await page.query_selector_all(selector)
        except Exception as exc:
            log.debug("could not read the %s elements: %s", selector, exc)
            continue
        for element in elements:
            try:
                value = await element.get_attribute("href") or await element.get_attribute("src")
            except Exception as exc:
                log.debug("could not read the attribute of a %s element: %s", selector, exc)
                value = None
            if value:
                found.append(_absolute(base, value))

    # The endpoints the page asked for.  The performance entries name
    # the resource that was fetched, which is the XHR and fetch
    # traffic the DOM does not show.
    try:
        entries = await page.evaluate("() => performance.getEntriesByType('resource').map(e => e.name)")
    except Exception:
        entries = []
    for entry in entries or []:
        if isinstance(entry, str) and entry:
            found.append(entry)

    return found


def _absolute(base: str, value: str) -> str:
    """The absolute url of a reference."""
    text = (value or "").strip()
    if not text or text.lower().startswith(NON_HTTP_SCHEMES):
        return ""
    if text.startswith("#"):
        # A hash route: the route is the fragment of the page itself.
        parts = urlsplit(base)
        return f"{parts.scheme}://{parts.netloc}{parts.path}#{text[1:]}"
    return urljoin(base, text)


def _authorized_hosts(request: ScanRequest) -> list[str]:
    """The hosts the crawler treats as first-party.

    The scope policy names them.  A scope that names none - a test
    double - leaves the scan's own targets as the authorised surface.
    """
    policy = getattr(request.scope, "policy", None)
    hosts = [
        str(host).strip().lower()
        for host in (getattr(policy, "authorized_hosts", ()) or ())
        if str(host).strip()
    ]
    if hosts:
        return hosts
    for target in request.targets:
        host = urlsplit(target if "://" in target else f"https://{target}").hostname or ""
        if host and host.lower() not in hosts:
            hosts.append(host.lower())
    return hosts


def _seeds(request: ScanRequest, authorized: list[str]) -> list[str]:
    """The URLs the crawl starts from.

    The scan targets are the seeds.  A URL among the operator's own
    seeds joins them when it is in scope.
    """
    seeds: list[str] = []
    for target in request.targets:
        text = (target or "").strip()
        if not text:
            continue
        seeds.append(text if "://" in text else f"https://{text}")
    for seed in request.seeds:
        text = (seed or "").strip()
        if not text.startswith(("http://", "https://")):
            continue
        if is_external(normalise_url(text), authorized):
            continue
        seeds.append(text)
    return seeds


def _item(url: str, *, depth: int = 0) -> dict[str, Any]:
    """One entry of the inventory."""
    parts = urlsplit(url)
    return {
        "url": url,
        "kind": "url",
        "host": parts.hostname or "",
        "path": parts.path or "/",
        "depth": depth,
        "scope": "internal",
        "discovered_by": "browser_crawl",
    }
