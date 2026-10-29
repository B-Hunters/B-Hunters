"""A role that cannot judge findings is told so - once.

The hypothesis roles reached for `record_verdict` anyway - it is the
obvious name for "say what you think of this finding" - and every
attempt was refused by the gateway, because only the adjudicator (and
the optional verifier) may judge a finding.  The refusals cost rounds
that the roles needed for their own work, so the prompt now says
plainly who records the verdicts.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from b_hunters.platform.agents.provider import ChatMessage, Completion, Provider, ProviderConfig
from b_hunters.platform.agents.roles import builtin_roles
from b_hunters.platform.agents.runtime import AgentRuntime, AgentRuntimeConfig
from b_hunters.platform.tools.gateway import ToolGateway, ToolRegistry


class _StubProvider(Provider):
    """Answers at once and keeps the prompts it was given."""

    def __init__(self) -> None:
        super().__init__(ProviderConfig(base_url="https://mock.test/v1", model="mock"))
        self.prompts: list[str] = []

    async def complete(self, messages, **kwargs):  # type: ignore[override]
        self.prompts.append("\n".join(str(message.get("content", "")) for message in messages))
        return Completion(
            message=ChatMessage(
                role="assistant",
                content=json.dumps({"conclusion": "the role concluded", "confidence": "high"}),
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
async def test_a_role_that_may_not_judge_findings_is_told_who_does() -> None:
    provider = _StubProvider()
    runtime = AgentRuntime(
        provider=provider,
        gateway=_gateway(),
        role=builtin_roles()["vuln_config"],
        config=AgentRuntimeConfig(max_rounds=2, max_tool_calls=10),
    )

    await runtime.run(scan_id="scan", task_id="task", objective="check the configuration")

    assert provider.prompts, "the role was never given a prompt"
    assert "Do not call `record_verdict`" in provider.prompts[0]


@pytest.mark.asyncio
async def test_the_adjudicator_is_not_told_not_to_judge() -> None:
    """The adjudicator records the verdicts; it must not be told to keep
    its hands off them."""
    provider = _StubProvider()
    runtime = AgentRuntime(
        provider=provider,
        gateway=_gateway(),
        role=builtin_roles()["adjudicator"],
        config=AgentRuntimeConfig(max_rounds=2, max_tool_calls=10),
    )

    await runtime.run(scan_id="scan", task_id="task", objective="judge the findings")

    assert provider.prompts
    assert "Do not call `record_verdict`" not in provider.prompts[0]
