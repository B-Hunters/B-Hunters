"""The browser the agents drive.

The browser is the one part of the platform that a model drives, and it
can reach anything the page can.  Three rules keep it useful and safe:

* **There is no `storage_state` action and no JavaScript evaluation.**
  The model cannot read the session out of the browser, and it cannot
  run code in the page.  A tool that can do either is a tool that can
  exfiltrate the session it was given.
* **Every action is audited** and a screenshot becomes an artifact, so
  the operator can see what the model saw.
* **`session_status` returns a boolean and a short summary, never
  cookies.**
"""

from __future__ import annotations

import asyncio

import pytest

from b_hunters.platform.browser.tool import BROWSER_ACTIONS, browser_tool


class _Context:
    """A context of the browser tool."""

    def __init__(self, browser=None):
        self.scan_id = "s1"
        self.task_id = "s1:recon"
        self.role = "recon"
        self.metadata = {"browser": browser} if browser else {}
        self.evidence: dict = {}
        self.artifacts: list = []


def test_the_actions_are_the_ones_that_were_asked_for():
    assert set(BROWSER_ACTIONS) == {
        "goto",
        "click",
        "fill",
        "press",
        "wait",
        "extract_text",
        "extract_html",
        "screenshot",
        "session_status",
    }


def test_there_is_no_way_to_read_the_session_out():
    """A model that can read the cookies can steal them."""
    assert "storage_state" not in BROWSER_ACTIONS
    assert "evaluate" not in BROWSER_ACTIONS
    assert "cookies" not in BROWSER_ACTIONS
    assert "javascript" not in BROWSER_ACTIONS


def test_the_session_status_is_a_boolean_and_a_summary():
    result = asyncio.run(browser_tool(action="session_status", context=_Context()))

    assert result["authenticated"] is False
    assert isinstance(result["summary"], str)
    assert "cookie" not in str(result).lower()


def test_an_unknown_action_is_refused():
    from b_hunters.platform.tools.gateway import ToolError

    with pytest.raises(ToolError):
        asyncio.run(browser_tool(action="storage_state", context=_Context()))


def test_an_action_without_a_browser_is_refused():
    from b_hunters.platform.tools.gateway import ToolError

    with pytest.raises(ToolError):
        asyncio.run(browser_tool(action="goto", url="https://demo.test/", context=_Context()))


def test_the_browser_tool_is_offered_to_the_agents():
    from b_hunters.platform.tools.builtin import build_tool_registry

    registry = build_tool_registry()

    assert "browser" in registry.names()


def test_the_output_of_an_action_is_redacted():
    """A page that shows a cookie must not have it echoed back."""
    from b_hunters.platform.tools.gateway import ToolContext, ToolPermissions

    context = ToolContext(scan_id="s1", task_id="s1:recon", role="recon")
    context.permissions = ToolPermissions(capabilities=set(), tools={"browser"})

    redacted = _redact({"text": "session=abc123def456; token=zzz999"})

    assert "abc123def456" not in str(redacted)
    assert "zzz999" not in str(redacted)


def _redact(payload):
    from b_hunters.platform.browser.tool import redact

    return redact(payload)
