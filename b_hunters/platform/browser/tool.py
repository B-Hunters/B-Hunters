"""The browser the agents drive.

The browser is the one part of the platform that a model drives, and it
can reach anything the page can.  Three rules keep it useful and safe:

* **There is no ``storage_state`` action and no JavaScript evaluation.**
  The model cannot read the session out of the browser, and it cannot
  run code in the page.  A tool that can do either is a tool that can
  carry the session away.
* **Every action is audited** and a screenshot becomes an artifact, so
  the operator can see what the model saw.
* **``session_status`` returns a boolean and a short summary, never
  cookies.**

Every request the browser makes is checked against the scan's scope
before it leaves — that is the `ScopeBrowser`'s job, and this tool does
not second-guess it.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from ..tools.gateway import ToolContext, ToolError

#: The actions the tool offers.
BROWSER_ACTIONS = (
    "goto",
    "click",
    "fill",
    "press",
    "wait",
    "extract_text",
    "extract_html",
    "screenshot",
    "session_status",
)

#: The patterns whose values are removed from what the tool returns.
#:
#: A page can show anything, and a model reads what the tool returns.
#: A session cookie in a page body is the one thing that must not come
#: back out.
_SECRET_PATTERNS = (
    re.compile(r"(session|token|jwt|auth|api[_-]?key|password|secret)\s*[=:]\s*[^\s,;'\"&]+", re.I),
    re.compile(r"(?:session|token|jwt|auth|api[_-]?key|password|secret)[^\s]*=[^;\s]+", re.I),
    re.compile(r"\b[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
)

#: What a redacted value is replaced with.
REDACTED = "[redacted]"


def redact(payload: Any) -> Any:
    """Remove the secrets from what the tool returns."""
    if isinstance(payload, str):
        text = payload
        for pattern in _SECRET_PATTERNS:
            text = pattern.sub(REDACTED, text)
        return text
    if isinstance(payload, dict):
        return {key: redact(value) for key, value in payload.items()}
    if isinstance(payload, list):
        return [redact(item) for item in payload]
    return payload


def _browser(context: ToolContext) -> Any:
    browser = context.metadata.get("browser")
    if browser is None:
        raise ToolError("no browser is available in this context")
    return browser


async def browser_tool(
    action: str,
    url: str = "",
    selector: str = "",
    value: str = "",
    key: str = "",
    timeout_ms: int = 15000,
    *,
    context: ToolContext,
) -> dict[str, Any]:
    """Drive the browser.

    The actions are ``goto``, ``click``, ``fill``, ``press``, ``wait``,
    ``extract_text``, ``extract_html``, ``screenshot`` and
    ``session_status``.

    There is no action that reads the session and no action that runs
    JavaScript in the page: the model uses the browser to look at the
    application, not to take it over.
    """
    if action not in BROWSER_ACTIONS:
        raise ToolError(
            f"unknown browser action '{action}'; the actions are {', '.join(BROWSER_ACTIONS)}"
        )

    if action == "session_status":
        return await _session_status(context)

    browser = _browser(context)
    page = await browser.page()

    if action == "goto":
        if not url:
            raise ToolError("the goto action needs a url")
        response = await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        return {
            "action": action,
            "url": page.url,
            "status": getattr(response, "status", None),
            "title": await _title(page),
        }

    if action == "click":
        element = await _element(page, selector)
        if element is None:
            raise ToolError(f"the page has no element matching '{selector}'")
        await element.click(timeout=timeout_ms)
        return {"action": action, "url": page.url, "title": await _title(page)}

    if action == "fill":
        element = await _element(page, selector)
        if element is None:
            raise ToolError(f"the page has no element matching '{selector}'")
        await element.fill(value)
        return {"action": action, "filled": selector}

    if action == "press":
        await page.keyboard.press(key or "Enter")
        return {"action": action, "key": key or "Enter", "url": page.url}

    if action == "wait":
        await page.wait_for_timeout(min(int(timeout_ms), 30000))
        return {"action": action, "url": page.url, "title": await _title(page)}

    if action == "extract_text":
        text = await _text(page, selector)
        return {"action": action, "text": redact(text)}

    if action == "extract_html":
        html = ""
        if selector:
            element = await _element(page, selector)
            if element is not None:
                html = await element.inner_html()
        else:
            html = await page.content()
        return {"action": action, "html": redact(html[:200_000])}

    # screenshot
    path = await browser.screenshot(page)
    handle = f"screenshot-{len(context.artifacts)}"
    context.artifacts.append(handle)
    context.evidence[handle] = path
    return {"action": action, "artifact": handle, "path": path}


async def _session_status(context: ToolContext) -> dict[str, Any]:
    """Whether there is a session, and a summary of it.

    Never the cookies: the model does not need them, and a model that
    can read them can carry them away.
    """
    browser = context.metadata.get("browser")
    if browser is None:
        return {
            "authenticated": False,
            "summary": "no browser is open, so there is no session",
        }
    try:
        cookies = await browser.cookies()
    except Exception:
        cookies = []
    names = sorted({str(cookie.get("name", "")) for cookie in cookies if cookie.get("name")})
    if not names:
        return {"authenticated": False, "summary": "the browser holds no session"}
    return {
        "authenticated": True,
        "summary": f"the browser holds {len(names)} cookie(s): {', '.join(names)}",
        "cookie_names": names,
    }


async def _element(page: Any, selector: str) -> Optional[Any]:
    if not selector:
        return None
    try:
        return await page.query_selector(selector)
    except Exception:
        return None


async def _text(page: Any, selector: str) -> str:
    try:
        if selector:
            element = await page.query_selector(selector)
            if element is None:
                return ""
            return (await element.inner_text()).strip()
        return (await page.inner_text("body")).strip()
    except Exception:
        return ""


async def _title(page: Any) -> str:
    try:
        return (await page.title()) or ""
    except Exception:
        return ""


BROWSER_TOOL_SCHEMA = {
    "type": "object",
    "properties": {
        "action": {
            "type": "string",
            "enum": list(BROWSER_ACTIONS),
            "description": "What the browser should do.",
        },
        "url": {"type": "string", "default": ""},
        "selector": {"type": "string", "default": ""},
        "value": {"type": "string", "default": ""},
        "key": {"type": "string", "default": ""},
        "timeout_ms": {"type": "integer", "default": 15000},
    },
    "required": ["action"],
    "additionalProperties": False,
}
