"""End-to-end scan lifecycle tests.

These drive a whole scan with a mocked OpenAI-compatible provider, so the
agent runtime, the tool gateway, the orchestrator, the persistence layer
and the event stream are all exercised together without needing a real
model or a real target.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from b_hunters.platform.agents.orchestrator import ScanContext, ScanOrchestrator, ScanProfile
from b_hunters.platform.agents.provider import Provider, ProviderConfig
from b_hunters.platform.scanners.registry import build_default_registry
from b_hunters.platform.tools.builtin import build_tool_registry

pytestmark = pytest.mark.integration


# ----------------------------------------------------------------------
# A scripted provider
# ----------------------------------------------------------------------
class ScriptedProvider(Provider):
    """A provider that replays a fixed list of chat completions."""

    def __init__(self, script: list[dict[str, Any]], **kwargs: Any) -> None:
        config = ProviderConfig(
            base_url="https://mock.test/v1",
            model="mock-model",
            api_key="mock",
            **kwargs,
        )
        super().__init__(config)
        self.script = list(script)
        self.calls: list[list[dict[str, Any]]] = []

    async def complete(self, messages, **kwargs):  # type: ignore[override]
        from b_hunters.platform.agents.provider import ChatMessage, Completion, ToolCall

        self.calls.append(list(messages))
        step = self.script.pop(0) if self.script else {"content": "done"}
        tool_calls = [
            ToolCall(
                id=call["id"],
                name=call["name"],
                arguments=call.get("arguments", {}),
                origin="native",
            )
            for call in step.get("tool_calls", [])
        ]
        return Completion(
            message=ChatMessage(role="assistant", content=step.get("content", ""), tool_calls=tool_calls),
            model="mock-model",
            prompt_tokens=10,
            completion_tokens=5,
            total_tokens=15,
        )

    async def supports_native_tools(self) -> bool:  # type: ignore[override]
        return True


def _conclusion(conclusion: str, **extra: Any) -> dict[str, Any]:
    payload = {
        "conclusion": conclusion,
        "confidence": "medium",
        "observations": ["observed something"],
        "uncertainty": "",
        "next_step": "",
        "findings": [],
    }
    payload.update(extra)
    return {"content": json.dumps(payload)}


@pytest.fixture
def orchestrator_parts(services, tmp_path):
    """Build an orchestrator with a scripted provider."""
    registry = build_default_registry()
    tool_registry = build_tool_registry()
    provider = ScriptedProvider([])

    def factory(provider_name: str = "") -> Provider:
        return provider

    orchestrator = ScanOrchestrator(
        database=services.db,
        settings=services.settings,
        provider_factory=factory,
        tool_registry=tool_registry,
        scanner_registry=registry,
    )
    orchestrator.settings.agent_workspace_root = str(tmp_path)
    return orchestrator, provider, services


def _context(services, **overrides) -> ScanContext:
    payload = {
        "scan_id": "",
        "name": "e2e scan",
        "targets": ["https://demo.test/"],
        "authorized_hosts": ["demo.test"],
        "profile": ScanProfile.default(),
        "safe_mode": True,
        "max_duration_seconds": 120,
        "workspace_root": "/tmp/b-hunters-e2e",
    }
    payload.update(overrides)
    return ScanContext(**payload)


@pytest.mark.asyncio
async def test_a_scan_runs_and_produces_findings(orchestrator_parts) -> None:
    orchestrator, provider, services = orchestrator_parts
    scan = services.scans.create(
        {
            "name": "e2e scan",
            "status": "queued",
            "created_by": "test",
            "definition": {"targets": ["https://demo.test/"]},
            "scope": {"authorized_hosts": ["demo.test"]},
        }
    )
    provider.script = [
        _conclusion(
            "The JavaScript bundle exposes an undocumented admin route",
            findings=[
                {
                    "title": "Undocumented admin route",
                    "vuln_class": "api_discovery",
                    "severity": "medium",
                    "host": "demo.test",
                    "path": "/admin/secret",
                    "summary": "/admin/secret is not in the specification",
                    "confidence": 0.7,
                }
            ],
        )
    ]

    context = _context(services, scan_id=scan.scan_id)
    context.profile.agent_roles = ["recon"]
    result = await orchestrator.run(context)

    assert result["status"] == "completed"
    record = services.scans.get(scan.scan_id)
    assert record.status == "completed"

    findings = services.findings.list(scan.scan_id)
    assert len(findings) == 1
    assert findings[0]["vuln_class"] == "api_discovery"
    assert findings[0]["detected_by"] == ["recon"]

    events = services.events.list_after(scan.scan_id)
    kinds = {event["kind"] for event in events}
    assert "scan.started" in kinds
    assert "scan.completed" in kinds
    assert "agent.completed" in kinds


@pytest.mark.asyncio
async def test_a_scan_is_persisted_with_its_tasks_and_agents(orchestrator_parts) -> None:
    orchestrator, provider, services = orchestrator_parts
    scan = services.scans.create(
        {
            "name": "e2e task scan",
            "status": "queued",
            "created_by": "test",
            "definition": {},
            "scope": {"authorized_hosts": ["demo.test"]},
        }
    )
    provider.script = [_conclusion("nothing notable")]
    context = _context(services, scan_id=scan.scan_id)
    context.profile.agent_roles = ["recon", "verifier"]
    await orchestrator.run(context)

    tasks = services.tasks.list_for_scan(scan.scan_id)
    roles = {task["agent_role"] for task in tasks}
    assert "recon" in roles
    assert "verifier" in roles

    # The verifier must depend on the hypothesis agents.
    verifier = next(task for task in tasks if task["agent_role"] == "verifier")
    assert verifier["depends_on"]

    agents = services.agents.list_for_scan(scan.scan_id)
    assert any(agent["role"] == "recon" for agent in agents)


@pytest.mark.asyncio
async def test_a_provider_failure_fails_the_agent_but_not_the_scan(orchestrator_parts) -> None:
    orchestrator, provider, services = orchestrator_parts
    scan = services.scans.create(
        {
            "name": "e2e failure",
            "status": "queued",
            "created_by": "test",
            "definition": {},
            "scope": {"authorized_hosts": ["demo.test"]},
        }
    )

    async def failing_complete(*args, **kwargs):
        from b_hunters.platform.agents.provider import ProviderError

        raise ProviderError("the model endpoint returned 500", retryable=False)

    provider.complete = failing_complete  # type: ignore[assignment]

    context = _context(services, scan_id=scan.scan_id)
    context.profile.agent_roles = ["recon"]
    result = await orchestrator.run(context)

    assert result["status"] == "completed"
    tasks = services.tasks.list_for_scan(scan.scan_id)
    assert any(task["status"] == "failed" for task in tasks)
    events = services.events.list_after(scan.scan_id)
    assert any(event["kind"] == "agent.message" for event in events)


@pytest.mark.asyncio
async def test_cancelling_a_scan_stops_it(orchestrator_parts) -> None:
    orchestrator, provider, services = orchestrator_parts
    scan = services.scans.create(
        {
            "name": "e2e cancel",
            "status": "queued",
            "created_by": "test",
            "definition": {},
            "scope": {"authorized_hosts": ["demo.test"]},
        }
    )
    provider.script = [_conclusion("should not matter")]
    orchestrator.cancel(scan.scan_id)
    context = _context(services, scan_id=scan.scan_id)
    result = await orchestrator.run(context)
    assert result["status"] == "cancelled"
    assert services.scans.get(scan.scan_id).status == "cancelled"


@pytest.mark.asyncio
async def test_tool_calls_are_recorded_and_bounded(orchestrator_parts) -> None:
    orchestrator, provider, services = orchestrator_parts
    scan = services.scans.create(
        {
            "name": "e2e tools",
            "status": "queued",
            "created_by": "test",
            "definition": {},
            "scope": {"authorized_hosts": ["demo.test"]},
        }
    )
    provider.script = [
        {
            "content": "",
            "tool_calls": [
                {
                    "id": "c1",
                    "name": "list_findings",
                    "arguments": {"limit": 10},
                }
            ],
        },
        _conclusion("the findings list was empty"),
    ]

    context = _context(services, scan_id=scan.scan_id)
    context.profile.agent_roles = ["recon"]
    await orchestrator.run(context)

    calls = services.tool_calls.list_for_scan(scan.scan_id)
    assert len(calls) >= 1
    assert calls[0]["tool"] == "list_findings"
    assert calls[0]["status"] == "ok"


@pytest.mark.asyncio
async def test_an_agent_cannot_use_a_tool_outside_its_permissions(orchestrator_parts) -> None:
    orchestrator, provider, services = orchestrator_parts
    scan = services.scans.create(
        {
            "name": "e2e permissions",
            "status": "queued",
            "created_by": "test",
            "definition": {},
            "scope": {"authorized_hosts": ["demo.test"]},
        }
    )
    # The recon role has no shell capability.
    provider.script = [
        {
            "content": "",
            "tool_calls": [{"id": "c1", "name": "run_command", "arguments": {"command": "id"}}],
        },
        _conclusion("the shell was refused as expected"),
    ]

    context = _context(services, scan_id=scan.scan_id)
    context.profile.agent_roles = ["recon"]
    await orchestrator.run(context)

    calls = services.tool_calls.list_for_scan(scan.scan_id)
    shell_calls = [call for call in calls if call["tool"] == "run_command"]
    assert shell_calls
    assert shell_calls[0]["status"] == "error"
    # The refusal must name the tool and explain why it was refused.
    assert "run_command" in shell_calls[0]["error"]


@pytest.mark.asyncio
async def test_a_scan_cannot_reach_an_out_of_scope_host(orchestrator_parts) -> None:
    orchestrator, provider, services = orchestrator_parts
    scan = services.scans.create(
        {
            "name": "e2e scope",
            "status": "queued",
            "created_by": "test",
            "definition": {},
            "scope": {"authorized_hosts": ["demo.test"]},
        }
    )
    provider.script = [
        {
            "content": "",
            "tool_calls": [
                {
                    "id": "c1",
                    "name": "http_request",
                    "arguments": {"url": "https://evil.test/steal"},
                }
            ],
        },
        _conclusion("the out of scope request was refused"),
    ]

    context = _context(services, scan_id=scan.scan_id)
    context.profile.agent_roles = ["recon"]
    await orchestrator.run(context)

    calls = services.tool_calls.list_for_scan(scan.scan_id)
    request_calls = [call for call in calls if call["tool"] == "http_request"]
    assert request_calls
    assert request_calls[0]["status"] == "error"
    assert "scope" in request_calls[0]["error"].lower()


@pytest.mark.asyncio
async def test_the_orchestrator_plan_has_dependencies(orchestrator_parts) -> None:
    orchestrator, _provider, _services = orchestrator_parts
    context = (
        _context(services=orchestrator.db and None or None)
        if False
        else _context(orchestrator.db, scan_id="plan-scan")
    )
    context.profile.agent_roles = ["recon", "vuln_xss", "verifier", "adjudicator"]
    plan = orchestrator.build_plan(context)
    by_role = {task.role: task for task in plan}
    assert "verifier" in by_role
    assert "adjudicator" in by_role
    assert by_role["verifier"].depends_on
    assert by_role["adjudicator"].depends_on
