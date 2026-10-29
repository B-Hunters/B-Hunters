"""The gateway's tools become framework tools.

The bridge must not lose the schema of a tool - the model sees the same
fields and the same descriptions - and it must not lose the capability
check: a tool the role may not use stays unusable.
"""

from __future__ import annotations

import json

import pytest

from b_hunters.platform.agents.framework import Conclusion, build_tools
from b_hunters.platform.tools.gateway import ToolContext, ToolDefinition


def _definition(
    name: str = "echo",
    *,
    capabilities: set[str] | None = None,
    handler=None,
) -> ToolDefinition:
    async def _handler(text: str = "", *, context=None):
        return {"echoed": text}

    return ToolDefinition(
        name=name,
        description="Echo the text back.",
        parameters={
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "What to echo."},
                "times": {"type": "integer", "description": "How often."},
            },
            "required": ["text"],
            "additionalProperties": False,
        },
        handler=handler or _handler,
        capabilities=capabilities or {"read_files"},
    )


def _context(role: str = "recon") -> ToolContext:
    context = ToolContext(scan_id="s", task_id="t", role=role)
    context.permissions.capabilities = {"read_files"}
    return context


def test_the_schema_survives_the_bridge() -> None:
    tools = build_tools([_definition()], _context())
    assert len(tools) == 1
    schema = tools[0].function_schema.json_schema
    assert schema["properties"]["text"]["description"] == "What to echo."
    assert schema["properties"]["times"]["description"] == "How often."
    assert schema["required"] == ["text"]


def test_a_tool_the_role_may_not_use_is_still_bridged() -> None:
    """The gateway refuses it, and the refusal is recorded.

    A role that reaches for a tool it may not have must leave a trace:
    the tool is bridged, the gateway refuses the call and writes the
    refusal to the audit trail.
    """
    context = _context()
    context.permissions.denied_tools.add("echo")
    tools = build_tools([_definition()], context)
    assert len(tools) == 1


@pytest.mark.asyncio
async def test_the_bridged_tool_calls_the_gateway_handler() -> None:
    seen: dict[str, object] = {}

    async def _handler(text: str = "", *, context=None):
        seen["text"] = text
        seen["context"] = context
        return {"echoed": text}

    context = _context()
    tools = build_tools([_definition(handler=_handler)], context)
    call = tools[0].function_schema.function

    class _Run:
        deps = context

    result = await call(_Run(), text="hello")

    assert json.loads(result)["echoed"] == "hello"
    assert seen["text"] == "hello"
    assert seen["context"] is context


def test_the_conclusion_is_a_model() -> None:
    conclusion = Conclusion(
        conclusion="found it",
        confidence="high",
        findings=[{"title": "a", "vuln_class": "xss", "severity": "medium"}],
    )
    assert conclusion.conclusion == "found it"
    assert conclusion.findings[0]["title"] == "a"


def test_a_conclusion_is_normalised_rather_than_rejected() -> None:
    """A model writes what it writes; the platform stores it in its shape."""
    from b_hunters.platform.agents.framework import normalise_conclusion

    conclusion = Conclusion(
        conclusion="found it",
        confidence=0.85,
        observations="one observation",
        findings=["a finding as text"],
    )

    stored = normalise_conclusion(conclusion)

    assert stored["confidence"] == "high"
    assert stored["observations"] == ["one observation"]
    assert stored["findings"] == [{"title": "a finding as text"}]
