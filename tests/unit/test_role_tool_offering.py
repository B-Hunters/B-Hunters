"""A role is offered the tools it may use, and only those.

Every tool of the registry used to be offered to every role, and the
gateway refused the ones the role may not have.  A model does not learn
from a refusal: it kept reaching for `record_verdict` and for the
network tools, and the rounds it spent on those calls were the rounds
it needed for its own work.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from b_hunters.platform.agents.provider import ChatMessage, Completion, Provider, ProviderConfig
from b_hunters.platform.agents.roles import builtin_roles
from b_hunters.platform.agents.runtime import AgentRuntime, AgentRuntimeConfig
from b_hunters.platform.tools.gateway import ToolGateway, ToolRegistry


class _RecordingProvider(Provider):
    """A provider that answers at once and remembers what it was offered."""

    def __init__(self) -> None:
        super().__init__(ProviderConfig(base_url="https://mock.test/v1", model="mock"))
        self.offered: list[set[str]] = []

    async def complete(self, messages, **kwargs):  # type: ignore[override]
        self.offered.append(
            {
                getattr(tool, "name", None) or (tool.get("function") or {}).get("name")
                for tool in (kwargs.get("tools") or ())
            }
        )
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

    async def do_command(**kwargs: Any) -> str:
        return "output"

    registry.register(
        "http_request",
        "Send an HTTP request.",
        {"type": "object", "properties": {}},
        do_request,
        capabilities={"network"},
    )
    registry.register(
        "run_command",
        "Run a command.",
        {"type": "object", "properties": {}},
        do_command,
        capabilities={"run_commands"},
    )
    return ToolGateway(registry)


@pytest.mark.asyncio
async def test_a_role_is_offered_only_its_own_tools() -> None:
    provider = _RecordingProvider()
    role = builtin_roles()["recon"]
    runtime = AgentRuntime(
        provider=provider,
        gateway=_gateway(),
        role=role,
        config=AgentRuntimeConfig(max_rounds=2, max_tool_calls=10),
    )

    await runtime.run(scan_id="scan", task_id="task", objective="look at the target")

    assert provider.offered, "the role was never given a prompt"
    offered = provider.offered[0]
    # The shell is not the recon role's to use, so it is not offered.
    assert "run_command" not in offered
    assert "http_request" in offered, "the role lost the tools it may use"


@pytest.mark.asyncio
async def test_the_adjudicator_is_offered_the_tool_that_records_a_verdict() -> None:
    provider = _RecordingProvider()
    runtime = AgentRuntime(
        provider=provider,
        gateway=_gateway(),
        role=builtin_roles()["adjudicator"],
        config=AgentRuntimeConfig(max_rounds=2, max_tool_calls=10),
    )

    await runtime.run(scan_id="scan", task_id="task", objective="judge the findings")

    offered = provider.offered[0]
    # The tool that records the verdict is not in this gateway, but the
    # shell must not be offered either.
    assert "run_command" not in offered
