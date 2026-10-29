"""Tests for what an agent run leaves behind.

Two things matter for the console: that a malformed provider response
does not take a run down, and that the conclusion of a role reaches the
message stream, so the console can say what each role did.
"""

from __future__ import annotations

from typing import Any

import pytest

from b_hunters.platform.agents.provider import (
    ChatMessage,
    Completion,
    Provider,
    ProviderConfig,
    ProviderInvalidResponse,
    ToolCall,
)
from b_hunters.platform.agents.roles import builtin_roles
from b_hunters.platform.agents.runtime import AgentRuntime, AgentRuntimeConfig
from b_hunters.platform.agents.schemas import MessageKind
from b_hunters.platform.tools.gateway import (
    CAPABILITY_NETWORK,
    ToolGateway,
    ToolRegistry,
)


class ToolCallingProvider(Provider):
    """A provider that answers with one tool call and then concludes."""

    def __init__(self) -> None:
        super().__init__(ProviderConfig(base_url="https://mock.test/v1", model="mock"))
        self.sent: list[list[dict[str, Any]]] = []

    async def complete(self, messages, **kwargs):  # type: ignore[override]
        self.sent.append(list(messages))
        if len(self.sent) == 1:
            return Completion(
                message=ChatMessage(
                    role="assistant",
                    content="",
                    tool_calls=[ToolCall(id="call-1", name="http_request", arguments={})],
                ),
                model="mock",
                prompt_tokens=1,
                completion_tokens=1,
                total_tokens=2,
            )

        # The conclusion is asked for as a tool call: the framework reads
        # the answer from the call and checks it against the schema.
        def _name(tool: Any) -> str:
            if isinstance(tool, dict):
                return str(tool.get("function", {}).get("name", ""))
            return str(getattr(tool, "name", ""))

        output_tool = next(
            (
                name
                for name in (_name(tool) for tool in (kwargs.get("tools") or ()))
                if name != "http_request"
            ),
            "final_result",
        )
        return Completion(
            message=ChatMessage(
                role="assistant",
                content="",
                tool_calls=[
                    ToolCall(
                        id="call-2",
                        name=output_tool,
                        arguments={
                            "conclusion": "the target answers on every port",
                            "confidence": "high",
                        },
                    )
                ],
            ),
            model="mock",
            prompt_tokens=1,
            completion_tokens=1,
            total_tokens=2,
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


# ----------------------------------------------------------------------
# A malformed provider response
# ----------------------------------------------------------------------
class TestMalformedResponses:
    def test_a_tool_call_without_a_function_is_skipped(self) -> None:
        provider = Provider(ProviderConfig(base_url="https://mock.test/v1", model="mock"))

        completion = provider._parse(
            {
                "choices": [
                    {
                        "message": {
                            "content": "",
                            "tool_calls": [{"id": "call-1", "type": "function", "function": "http_request"}],
                        }
                    }
                ],
                "usage": {},
            },
            latency_ms=1,
            raw_body={},
        )

        # The odd entry is dropped, the rest of the response is usable.
        assert completion.message.tool_calls == []

    def test_a_tool_calls_field_that_is_not_a_list_is_ignored(self) -> None:
        provider = Provider(ProviderConfig(base_url="https://mock.test/v1", model="mock"))

        completion = provider._parse(
            {"choices": [{"message": {"content": "hello", "tool_calls": "not a list"}}]},
            latency_ms=1,
            raw_body={},
        )

        assert completion.message.content == "hello"
        assert completion.message.tool_calls == []

    def test_an_unexpected_shape_says_so(self, monkeypatch) -> None:
        """A shape the parser does not know must not fail obscurely."""
        provider = Provider(ProviderConfig(base_url="https://mock.test/v1", model="mock"))

        def explode(*args: Any, **kwargs: Any):
            raise AttributeError("'str' object has no attribute 'get'")

        monkeypatch.setattr(provider, "_parse_completion", explode)

        with pytest.raises(ProviderInvalidResponse) as excinfo:
            provider._parse({"choices": [{"message": {}}]}, latency_ms=1, raw_body={})

        assert "unexpected shape" in str(excinfo.value)


# ----------------------------------------------------------------------
# The conclusion reaches the message stream
# ----------------------------------------------------------------------
class TestConclusionMessage:
    @pytest.mark.asyncio
    async def test_the_conclusion_is_emitted_as_a_task_result(self) -> None:
        messages = []
        runtime = AgentRuntime(
            provider=ToolCallingProvider(),
            gateway=_gateway(),
            role=builtin_roles()["recon"],
            config=AgentRuntimeConfig(max_rounds=3, max_tool_calls=10),
            on_message=messages.append,
        )

        run = await runtime.run(scan_id="scan", task_id="task", objective="look at the target")

        assert run.status == "succeeded"
        results = [m for m in messages if m.kind == MessageKind.TASK_RESULT]
        assert len(results) == 1
        assert results[0].hypothesis == "the target answers on every port"
        assert "1 tool call" in results[0].rationale
