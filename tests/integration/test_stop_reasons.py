"""Why an agent stopped, and the deadline that stops it.

The scan cap is an enforced deadline.  A role that did not start because
the deadline passed is recorded as ``wall_clock``, and a role that was
cut off mid-flight is recorded as ``wall_clock`` too - never as
``succeeded``.

Every task result carries the reason it stopped, and the reason is
never derived from an empty error string.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import replace
from typing import Any

import pytest

from b_hunters.platform.agents.orchestrator import ScanContext, ScanOrchestrator, ScanProfile
from b_hunters.platform.agents.provider import Completion, Provider, ProviderConfig
from b_hunters.platform.agents.roles import builtin_roles
from b_hunters.platform.agents.runtime import AgentRuntime, AgentRuntimeConfig
from b_hunters.platform.api.deps import Services, set_services
from b_hunters.platform.db.client import Database
from b_hunters.platform.scanners.registry import build_default_registry
from b_hunters.platform.tools.builtin import build_tool_registry
from b_hunters.platform.tools.gateway import ToolGateway, ToolRegistry

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def database(settings):
    """A database of this test's own.

    The other agents work against the same MongoDB, so the rows of this
    test live in a database of their own and only its own collections are
    cleaned.
    """
    scoped = replace(settings, mongo_db=f"{settings.mongo_db}-stopreasons")
    db = Database(scoped)
    if not db.ping():
        pytest.skip(f"MongoDB is not reachable at {settings.mongo_uri}")
    db.ensure_indexes()
    yield db
    for name in (
        "platform_scans",
        "platform_tasks",
        "platform_agents",
        "platform_messages",
        "platform_scan_events",
        "platform_findings",
    ):
        db.collection(name).delete_many({})
    db.close()


@pytest.fixture
def services(database, settings):
    """The service container of this test's own database."""
    container = Services(database, replace(settings, mongo_db=database.settings.mongo_db))
    set_services(container)
    yield container
    set_services(None)


# ----------------------------------------------------------------------
# A scripted provider
# ----------------------------------------------------------------------
class ScriptedProvider(Provider):
    """A provider that replays a fixed list of chat completions."""

    def __init__(self, script: list[dict[str, Any]] | None = None, **kwargs: Any) -> None:
        config = ProviderConfig(
            base_url="https://mock.test/v1",
            model="mock-model",
            api_key="mock",
            **kwargs,
        )
        super().__init__(config)
        self.script = list(script or [])

    async def complete(self, messages, **kwargs):  # type: ignore[override]
        from b_hunters.platform.agents.provider import ChatMessage, ToolCall

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


class SlowProvider(ScriptedProvider):
    """A provider that never answers in time."""

    async def complete(self, messages, **kwargs):  # type: ignore[override]
        await asyncio.sleep(30)
        return await super().complete(messages, **kwargs)


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
    provider = ScriptedProvider([])

    def factory(provider_name: str = "") -> Provider:
        return provider

    orchestrator = ScanOrchestrator(
        database=services.db,
        settings=services.settings,
        provider_factory=factory,
        tool_registry=build_tool_registry(),
        scanner_registry=build_default_registry(),
    )
    orchestrator.settings.agent_workspace_root = str(tmp_path)
    return orchestrator, provider, services


def _context(services, **overrides) -> ScanContext:
    payload = {
        "scan_id": "",
        "name": "stop reason scan",
        "targets": ["https://demo.test/"],
        "authorized_hosts": ["demo.test"],
        "profile": ScanProfile.default(),
        "safe_mode": True,
        "max_duration_seconds": 120,
        "workspace_root": "/tmp/b-hunters-stopreasons",
    }
    payload.update(overrides)
    return ScanContext(**payload)


def _scan(services, name: str = "stop reason scan"):
    return services.scans.create(
        {
            "name": name,
            "status": "queued",
            "created_by": "test",
            "definition": {"targets": ["https://demo.test/"]},
            "scope": {"authorized_hosts": ["demo.test"]},
        }
    )


# ----------------------------------------------------------------------
# The deadline
# ----------------------------------------------------------------------
@pytest.mark.asyncio
async def test_a_role_that_never_started_is_recorded_as_wall_clock(orchestrator_parts) -> None:
    orchestrator, provider, services = orchestrator_parts
    scan = _scan(services)
    provider.script = [_conclusion("done")]
    context = _context(services, scan_id=scan.scan_id)
    context.profile.agent_roles = ["recon", "api"]
    context.max_duration_seconds = 30
    # The deadline has passed before the scan starts.
    services.scans.update(scan.scan_id, {"deadline_at": time.time() - 1})

    await orchestrator.run(context)

    tasks = {task["task_id"]: task for task in services.tasks.list_for_scan(scan.scan_id)}
    assert tasks
    for task in tasks.values():
        assert task["status"] == "wall_clock"
        assert task["result"]["stop_reason"] == "wall_clock"


@pytest.mark.asyncio
async def test_a_role_that_was_cut_off_is_not_reported_as_succeeded(orchestrator_parts) -> None:
    """A role that is cut off mid-flight is cut off, not successful."""
    orchestrator, _provider, services = orchestrator_parts
    scan = _scan(services, "cut off scan")

    async def slow_complete(*args, **kwargs):
        await asyncio.sleep(30)

    orchestrator.provider_factory = lambda provider_name="": _slow_provider(slow_complete)
    context = _context(services, scan_id=scan.scan_id)
    context.profile.agent_roles = ["recon"]
    # The deadline passes while the role is still working.
    services.scans.update(scan.scan_id, {"deadline_at": time.time() + 2})

    await orchestrator.run(context)

    tasks = services.tasks.list_for_scan(scan.scan_id)
    assert tasks
    for task in tasks:
        assert task["status"] == "wall_clock"
        assert task["result"]["stop_reason"] == "wall_clock"


def _slow_provider(handler) -> Provider:
    provider = ScriptedProvider([])
    provider.complete = handler  # type: ignore[assignment]
    return provider


@pytest.mark.asyncio
async def test_the_deadline_is_stored_on_the_scan(orchestrator_parts) -> None:
    orchestrator, provider, services = orchestrator_parts
    scan = _scan(services, "deadline scan")
    provider.script = [_conclusion("done")]
    context = _context(services, scan_id=scan.scan_id)
    context.profile.agent_roles = ["recon"]
    context.max_duration_seconds = 300

    await orchestrator.run(context)

    document = services.db.collection("platform_scans").find_one({"scan_id": scan.scan_id}) or {}
    assert float(document.get("deadline_at", 0)) > 0


@pytest.mark.asyncio
async def test_a_task_that_already_succeeded_keeps_its_result(orchestrator_parts) -> None:
    """A deadline that passes later does not undo the work that was done."""
    orchestrator, provider, services = orchestrator_parts
    scan = _scan(services, "resumed scan")
    provider.script = [_conclusion("done")]
    context = _context(services, scan_id=scan.scan_id)
    context.profile.agent_roles = ["recon", "api"]
    await orchestrator.run(context)

    finished = services.tasks.list_for_scan(scan.scan_id)
    assert finished
    assert all(task["status"] == "succeeded" for task in finished)

    # The scan is picked up again after its deadline has passed.
    services.scans.update(scan.scan_id, {"phase": "agents", "deadline_at": time.time() - 1})
    provider.script = [_conclusion("done again")]
    await orchestrator.run(context)

    tasks = {task["task_id"]: task for task in services.tasks.list_for_scan(scan.scan_id)}
    for task in tasks.values():
        assert task["status"] == "succeeded"
        assert task["result"]["stop_reason"] == "completed"


# ----------------------------------------------------------------------
# The stop reason
# ----------------------------------------------------------------------
@pytest.mark.asyncio
async def test_a_task_that_finished_carries_its_stop_reason(orchestrator_parts) -> None:
    orchestrator, provider, services = orchestrator_parts
    scan = _scan(services, "finished scan")
    provider.script = [_conclusion("done")]
    context = _context(services, scan_id=scan.scan_id)
    context.profile.agent_roles = ["recon"]

    await orchestrator.run(context)

    tasks = services.tasks.list_for_scan(scan.scan_id)
    assert tasks
    for task in tasks:
        assert task["status"] == "succeeded"
        assert task["result"]["stop_reason"] == "completed"


@pytest.mark.asyncio
async def test_a_failed_task_is_not_reported_as_completed(orchestrator_parts) -> None:
    orchestrator, provider, services = orchestrator_parts
    scan = _scan(services, "failed scan")

    async def failing_complete(*args, **kwargs):
        from b_hunters.platform.agents.provider import ProviderError

        raise ProviderError("the model endpoint returned 500", retryable=False)

    provider.complete = failing_complete  # type: ignore[assignment]
    context = _context(services, scan_id=scan.scan_id)
    context.profile.agent_roles = ["recon"]

    await orchestrator.run(context)

    tasks = services.tasks.list_for_scan(scan.scan_id)
    assert tasks
    for task in tasks:
        assert task["result"]["stop_reason"] == "failed"
        assert task["result"]["stop_reason"] != "completed"


@pytest.mark.asyncio
async def test_the_runtime_records_a_wall_clock_expiry() -> None:
    """The per-task wall clock is a stop reason of its own."""
    provider = SlowProvider([])
    runtime = AgentRuntime(
        provider=provider,
        gateway=ToolGateway(ToolRegistry()),
        role=builtin_roles()["recon"],
        config=AgentRuntimeConfig(max_rounds=3, max_tool_calls=10, max_wall_clock_seconds=1),
    )

    run = await runtime.run(scan_id="scan", task_id="task", objective="look at the target")

    assert run.status == "wall_clock"
    assert run.error == "the task ran out of its wall clock"
    assert run.to_dict()["stop_reason"] == "wall_clock"
