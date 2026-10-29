"""Tests for the shape of the messages the agent runtime sends.

A provider that answered with native tool calls expects the result of
each call to come back as a ``tool`` message carrying the identifier of
the call it answers, directly behind the assistant message that made the
call.  A provider in compatibility mode saw a plain message and expects
a plain answer instead.  Mixing the two shapes is rejected by strict
endpoints, so both are pinned here.
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


class RecordingProvider(Provider):
    """A provider that records the messages it is asked to complete."""

    def __init__(self, *, native: bool, calls: list[ToolCall]) -> None:
        super().__init__(ProviderConfig(base_url="https://mock.test/v1", model="mock"))
        self.native = native
        self.calls = calls
        self.sent: list[list[dict[str, Any]]] = []

    async def complete(self, messages, **kwargs):  # type: ignore[override]
        self.sent.append(list(messages))
        if len(self.sent) == 1:
            return Completion(
                message=ChatMessage(
                    role="assistant",
                    content="",
                    tool_calls=list(self.calls),
                ),
                model="mock",
                prompt_tokens=1,
                completion_tokens=1,
                total_tokens=2,
            )
        return Completion(
            message=ChatMessage(role="assistant", content='{"conclusion": "done"}'),
            model="mock",
            prompt_tokens=1,
            completion_tokens=1,
            total_tokens=2,
        )

    async def supports_native_tools(self) -> bool:  # type: ignore[override]
        return self.native


def _gateway() -> ToolGateway:
    registry = ToolRegistry()

    async def do_request(**kwargs: Any) -> str:
        return "the response body"

    registry.register(
        "http_request",
        "Send an HTTP request.",
        {"type": "object", "properties": {}},
        do_request,
        capabilities={CAPABILITY_NETWORK},
    )
    return ToolGateway(registry)


def _role(name: str):
    role = builtin_roles().get(name)
    assert role is not None, f"no role named {name}"
    return role


async def _run(provider: Provider) -> list[dict[str, Any]]:
    runtime = AgentRuntime(
        provider=provider,
        gateway=_gateway(),
        role=_role("recon"),
        config=AgentRuntimeConfig(max_rounds=3, max_tool_calls=4),
    )
    await runtime.run(scan_id="scan", task_id="task", objective="look at the target")
    return provider.sent[-1]


@pytest.mark.asyncio
async def test_a_native_tool_result_is_a_tool_message_with_the_call_identifier() -> None:
    """A native call is answered with a "tool" message, not a "user" one."""
    provider = RecordingProvider(
        native=True,
        calls=[ToolCall(id="call-42", name="http_request", arguments={}, origin="native")],
    )

    messages = await _run(provider)

    tool_messages = [m for m in messages if m.get("role") == "tool"]
    assert len(tool_messages) == 1
    assert tool_messages[0]["tool_call_id"] == "call-42"

    # The result sits directly behind the assistant message that made the
    # call, which is what the endpoint checks.
    index = messages.index(tool_messages[0])
    assert messages[index - 1]["role"] == "assistant"
    assert messages[index - 1]["tool_calls"][0]["id"] == "call-42"


@pytest.mark.asyncio
async def test_a_compat_tool_result_stays_a_user_message() -> None:
    """In compatibility mode the model saw a plain message, so it gets one."""
    provider = RecordingProvider(
        native=False,
        calls=[ToolCall(id="call-1", name="http_request", arguments={}, origin="compat")],
    )

    messages = await _run(provider)

    assert not [m for m in messages if m.get("role") == "tool"]
    assert any(m.get("role") == "user" and "http_request" in str(m.get("content", "")) for m in messages)
