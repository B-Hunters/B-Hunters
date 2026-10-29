"""Tests for the budget the agent loop works within.

An agent that explores without ever concluding is not a useful agent: it
spends the whole budget on tool calls and returns nothing.  The runtime
therefore tells the model to wrap up before the budget runs out.
"""

from __future__ import annotations

from typing import Any

import pytest

from b_hunters.platform.agents.provider import (
    ChatMessage,
    Completion,
    Provider,
    ProviderConfig,
    ToolCall,
)
from b_hunters.platform.agents.roles import builtin_roles
from b_hunters.platform.agents.runtime import AgentRuntime, AgentRuntimeConfig
from b_hunters.platform.tools.gateway import (
    CAPABILITY_NETWORK,
    ToolGateway,
    ToolRegistry,
)


class ToolCallingProvider(Provider):
    """A provider that keeps asking for a tool."""

    def __init__(self) -> None:
        super().__init__(ProviderConfig(base_url="https://mock.test/v1", model="mock"))
        self.sent: list[list[dict[str, Any]]] = []

    async def complete(self, messages, **kwargs):  # type: ignore[override]
        self.sent.append(list(messages))
        return Completion(
            message=ChatMessage(
                role="assistant",
                content="",
                tool_calls=[ToolCall(id="call-1", name="http_request", arguments={}, origin="native")],
            ),
            model="mock",
            prompt_tokens=1,
            completion_tokens=1,
            total_tokens=1,
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
        capabilities={CAPABILITY_NETWORK},
    )
    return ToolGateway(registry)


@pytest.mark.asyncio
async def test_the_agent_is_told_to_wrap_up_before_its_budget_runs_out() -> None:
    """The last round carries an instruction to conclude."""
    provider = ToolCallingProvider()
    runtime = AgentRuntime(
        provider=provider,
        gateway=_gateway(),
        role=builtin_roles()["recon"],
        config=AgentRuntimeConfig(max_rounds=3, max_tool_calls=40),
    )

    await runtime.run(scan_id="scan", task_id="task", objective="look at the target")

    wrap_ups = [
        message
        for message in provider.sent[-1]
        if message.get("role") == "user" and "final JSON answer" in str(message.get("content", ""))
    ]
    assert wrap_ups, "the agent was never told to produce its final answer"


@pytest.mark.asyncio
async def test_the_wrap_up_comes_before_the_round_budget_is_spent() -> None:
    """The instruction is there while there is still a round left to use."""
    provider = ToolCallingProvider()
    runtime = AgentRuntime(
        provider=provider,
        gateway=_gateway(),
        role=builtin_roles()["recon"],
        config=AgentRuntimeConfig(max_rounds=3, max_tool_calls=40),
    )

    await runtime.run(scan_id="scan", task_id="task", objective="look at the target")

    # The instruction must reach the model: it is appended to the
    # transcript, and the request that follows carries it.
    assert any(
        message.get("role") == "user" and "final JSON answer" in str(message.get("content", ""))
        for request in provider.sent[1:]
        for message in request
    )
