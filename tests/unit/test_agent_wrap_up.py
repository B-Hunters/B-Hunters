"""A role that keeps calling tools is told to conclude - and it does.

The budget limits the requests, so the nudge that asks the role to
conclude has to arrive with the last request that is still allowed.  When
the two counts drifted apart, the run was cut off before the role could
answer, and every finding it had collected was lost.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from b_hunters.platform.agents.provider import ChatMessage, Completion, Provider, ProviderConfig, ToolCall
from b_hunters.platform.agents.roles import builtin_roles
from b_hunters.platform.agents.runtime import AgentRuntime, AgentRuntimeConfig
from b_hunters.platform.tools.gateway import ToolGateway, ToolRegistry


class _StubProvider(Provider):
    """Calls a tool forever, until it is told to conclude."""

    def __init__(self) -> None:
        super().__init__(ProviderConfig(base_url="https://mock.test/v1", model="mock"))
        self.sent: list[list[dict[str, Any]]] = []
        #: The tools every request was offered.
        self.tools_offered: list[set[str]] = []

    async def complete(self, messages, **kwargs):  # type: ignore[override]
        self.sent.append(list(messages))
        offered = {
            getattr(tool, "name", None) or (tool.get("function") or {}).get("name")
            for tool in (kwargs.get("tools") or ())
        }
        self.tools_offered.append(offered)
        told_to_conclude = any("final JSON answer" in str(message.get("content", "")) for message in messages)
        # A model that is offered nothing but the answer gives the answer.
        if told_to_conclude or "http_request" not in offered:
            return Completion(
                message=ChatMessage(
                    role="assistant",
                    content=json.dumps({"conclusion": "the role concluded", "confidence": "high"}),
                ),
                model="mock",
            )
        return Completion(
            message=ChatMessage(
                role="assistant",
                content="",
                tool_calls=[ToolCall(id="call-1", name="http_request", arguments={})],
            ),
            model="mock",
        )

    async def supports_native_tools(self) -> bool:  # type: ignore[override]
        return True


def _gateway() -> ToolGateway:
    registry = ToolRegistry()

    async def do_request(**kwargs: Any) -> str:
        return "body"

    registry.register(
        "http_request",
        "Send an HTTP request.",
        {"type": "object", "properties": {}},
        do_request,
        capabilities={"network"},
    )
    return ToolGateway(registry)


@pytest.mark.asyncio
async def test_a_role_that_never_stops_is_told_to_conclude_and_concludes() -> None:
    provider = _StubProvider()
    runtime = AgentRuntime(
        provider=provider,
        gateway=_gateway(),
        role=builtin_roles()["recon"],
        config=AgentRuntimeConfig(max_rounds=4, max_tool_calls=20),
    )

    run = await runtime.run(scan_id="scan", task_id="task", objective="look at the target")

    assert run.status == "succeeded", run.error
    assert run.conclusion == "the role concluded"
    # The instruction to conclude has to reach the model.
    assert any(
        "final JSON answer" in str(message.get("content", ""))
        for request in provider.sent
        for message in request
    )


@pytest.mark.asyncio
async def test_the_conclusion_comes_before_the_budget_is_spent() -> None:
    """The instruction has to arrive while a request is still allowed."""
    provider = _StubProvider()
    runtime = AgentRuntime(
        provider=provider,
        gateway=_gateway(),
        role=builtin_roles()["recon"],
        config=AgentRuntimeConfig(max_rounds=4, max_tool_calls=20),
    )

    await runtime.run(scan_id="scan", task_id="task", objective="look at the target")

    assert len(provider.sent) <= 4, "the role was cut off before it could conclude"


@pytest.mark.asyncio
async def test_the_last_request_offers_no_tools() -> None:
    """A role that calls a tool again on the last request still answers.

    The budget ends with a request the role may still make.  On that one
    it is offered nothing but the answer, so it cannot spend another
    round and lose everything it found.
    """
    provider = _StubProvider()
    runtime = AgentRuntime(
        provider=provider,
        gateway=_gateway(),
        role=builtin_roles()["recon"],
        config=AgentRuntimeConfig(max_rounds=3, max_tool_calls=20),
    )

    run = await runtime.run(scan_id="scan", task_id="task", objective="look at the target")

    assert run.status == "succeeded", run.error
    assert "http_request" not in provider.tools_offered[-1], "the last request still offered the tools"


@pytest.mark.asyncio
async def test_the_last_request_still_offers_the_answer() -> None:
    """Withholding the tools must not withhold the answer.

    The role delivers its conclusion through the tool the framework reads
    the answer from.  When that tool was withheld together with the
    others, the role had no way to deliver its conclusion at all: it ran
    out of rounds with everything it had found still in its head.
    """
    provider = _StubProvider()
    runtime = AgentRuntime(
        provider=provider,
        gateway=_gateway(),
        role=builtin_roles()["recon"],
        config=AgentRuntimeConfig(max_rounds=3, max_tool_calls=20),
    )

    await runtime.run(scan_id="scan", task_id="task", objective="look at the target")

    offered = provider.tools_offered[-1]
    assert "http_request" not in offered, "the last request still offered the tools"
    assert offered, "the last request offered no way to answer at all"
    assert any("final" in name for name in offered), f"the answer tool is missing: {offered}"
