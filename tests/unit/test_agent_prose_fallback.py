"""A role that answers in prose still delivers its conclusion.

A model that does not fill in the answer tool - because it ran out of
rounds, or because it wrote prose where the tool call was expected -
has still done the work.  Throwing the answer away because it came in
the wrong shape loses every finding the role produced.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from b_hunters.platform.agents.framework import conclusion_from_text, normalise_conclusion
from b_hunters.platform.agents.provider import ChatMessage, Completion, Provider, ProviderConfig, ToolCall
from b_hunters.platform.agents.roles import builtin_roles
from b_hunters.platform.agents.runtime import AgentRuntime, AgentRuntimeConfig
from b_hunters.platform.tools.gateway import ToolGateway, ToolRegistry


def test_prose_is_read_as_a_conclusion() -> None:
    conclusion = normalise_conclusion(conclusion_from_text("The actuator is exposed without a login."))

    assert conclusion["conclusion"] == "The actuator is exposed without a login."
    assert conclusion["observations"], "the prose was not kept as an observation"


def test_json_written_as_text_is_read_as_the_answer() -> None:
    text = "Here is my answer:\n" + json.dumps(
        {"conclusion": "two findings", "confidence": "high", "findings": [{"title": "an issue"}]}
    )

    conclusion = normalise_conclusion(conclusion_from_text(text))

    assert conclusion["conclusion"] == "two findings"
    assert conclusion["confidence"] == "high"
    assert conclusion["findings"] == [{"title": "an issue"}]


def test_nothing_is_nothing() -> None:
    conclusion = normalise_conclusion(conclusion_from_text("   "))

    assert conclusion["conclusion"] == ""


class _ProseProvider(Provider):
    """A model that calls tools and then answers in prose."""

    def __init__(self) -> None:
        super().__init__(ProviderConfig(base_url="https://mock.test/v1", model="mock"))
        self.calls = 0

    async def complete(self, messages, **kwargs):  # type: ignore[override]
        self.calls += 1
        offered = {
            getattr(tool, "name", None) or (tool.get("function") or {}).get("name")
            for tool in (kwargs.get("tools") or ())
        }
        if "http_request" in offered:
            return Completion(
                message=ChatMessage(
                    role="assistant",
                    content="",
                    tool_calls=[ToolCall(id="call-1", name="http_request", arguments={})],
                ),
                model="mock",
            )
        # The last request: the model writes its answer instead of
        # filling in the answer tool.
        return Completion(
            message=ChatMessage(
                role="assistant",
                content="I found an exposed actuator endpoint on the target.",
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
async def test_a_role_that_answers_in_prose_still_concludes() -> None:
    provider = _ProseProvider()
    runtime = AgentRuntime(
        provider=provider,
        gateway=_gateway(),
        role=builtin_roles()["recon"],
        config=AgentRuntimeConfig(max_rounds=3, max_tool_calls=20),
    )

    run = await runtime.run(scan_id="scan", task_id="task", objective="look at the target")

    assert run.status == "succeeded", run.error
    assert "exposed actuator" in run.conclusion


class _BrokenProvider(_ProseProvider):
    """A model that writes something and then the provider breaks."""

    async def complete(self, messages, **kwargs):  # type: ignore[override]
        self.calls += 1
        if self.calls > 1:
            raise RuntimeError("the provider is on fire")
        return await super().complete(messages, **kwargs)


@pytest.mark.asyncio
async def test_a_broken_run_is_not_rescued_by_the_prose() -> None:
    """A run that broke is a failure.  The prose the model wrote before
    it broke is not a conclusion."""
    provider = _BrokenProvider()
    runtime = AgentRuntime(
        provider=provider,
        gateway=_gateway(),
        role=builtin_roles()["recon"],
        config=AgentRuntimeConfig(max_rounds=3, max_tool_calls=20),
    )

    run = await runtime.run(scan_id="scan", task_id="task", objective="look at the target")

    assert run.status != "succeeded", "a broken run was reported as a success"
    assert not run.conclusion
