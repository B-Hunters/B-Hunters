"""A scan resumes where it stopped.

A runner that dies in the middle of a scan must not make the scan start
again: the scan records the phase it reached and the state of every
agent task, so the next runner picks the work up where the last one left
it.  A task that already succeeded is not run again - its work is done,
its findings are persisted, and running it would spend the tokens twice.
"""

from __future__ import annotations

import pytest
from test_scan_lifecycle import _conclusion, _context, orchestrator_parts  # noqa: F401

pytestmark = pytest.mark.integration


@pytest.fixture
def scan(services):
    """A scan that is already in the agent phase."""
    return services.scans.create(
        {
            "name": "resumed scan",
            "status": "running",
            "created_by": "test",
            "definition": {"targets": ["https://demo.test/"]},
            "scope": {"authorized_hosts": ["demo.test"]},
            "phase": "agents",
        }
    )


@pytest.mark.asyncio
async def test_a_succeeded_agent_task_is_not_run_again(services, orchestrator_parts):  # noqa: F811
    orchestrator, provider, services = orchestrator_parts
    scan = services.scans.create(
        {
            "name": "resumed scan",
            "status": "running",
            "created_by": "test",
            "definition": {"targets": ["https://demo.test/"]},
            "scope": {"authorized_hosts": ["demo.test"]},
            "phase": "agents",
        }
    )
    services.tasks.upsert(
        scan_id=scan.scan_id,
        task_id=f"{scan.scan_id}:recon",
        title="Recon",
        agent_role="recon",
        budget={},
        input={},
    )
    services.tasks.set_status(f"{scan.scan_id}:recon", "succeeded", result={"role": "recon"})
    provider.script = [_conclusion("done"), _conclusion("done")]
    context = _context(services, scan_id=scan.scan_id)
    context.profile.agent_roles = ["recon", "api"]
    await orchestrator.run(context)
    roles = list(provider.calls)
    assert roles  # the api role still ran
    # Only the api role called the model: the recon task was not run again.
    assert len(provider.calls) == 1
    tasks = {task["task_id"]: task for task in services.tasks.list_for_scan(scan.scan_id)}
    assert tasks[f"{scan.scan_id}:recon"]["status"] == "succeeded"
    assert tasks[f"{scan.scan_id}:api"]["status"] == "succeeded"


@pytest.mark.asyncio
async def test_a_scan_resumes_at_the_phase_it_reached(services, orchestrator_parts):  # noqa: F811
    orchestrator, provider, services = orchestrator_parts
    scan = services.scans.create(
        {
            "name": "resumed scan",
            "status": "running",
            "created_by": "test",
            "definition": {"targets": ["https://demo.test/"]},
            "scope": {"authorized_hosts": ["demo.test"]},
            "phase": "agents",
        }
    )
    provider.script = [_conclusion("done")]
    context = _context(services, scan_id=scan.scan_id)
    context.profile.agent_roles = ["recon"]
    await orchestrator.run(context)
    kinds = {event["kind"] for event in services.events.list_after(scan.scan_id)}
    assert "workers.dispatched" not in kinds
    # The scanner stage is skipped as well: the scan resumes at the
    # phase it reached, not at the beginning.
    assert "scanner.completed" not in kinds
    assert services.scans.get(scan.scan_id).phase == "completed"


@pytest.mark.asyncio
async def test_a_scan_resumed_at_the_verifying_phase_runs_the_verifier(services, orchestrator_parts):  # noqa: F811
    orchestrator, provider, services = orchestrator_parts
    scan = services.scans.create(
        {
            "name": "resumed scan",
            "status": "running",
            "created_by": "test",
            "definition": {"targets": ["https://demo.test/"]},
            "scope": {"authorized_hosts": ["demo.test"]},
            "phase": "verifying",
        }
    )
    provider.script = [_conclusion("done")]
    context = _context(services, scan_id=scan.scan_id)
    context.profile.agent_roles = ["recon", "verifier"]
    await orchestrator.run(context)
    tasks = {task["task_id"]: task for task in services.tasks.list_for_scan(scan.scan_id)}
    # The hypothesis stage is over: its task is not run again.
    assert tasks[f"{scan.scan_id}:recon"]["status"] == "pending"
    # The verifier depends on the hypothesis tasks, and the stage it
    # belongs to is over, so it is not blocked.
    assert tasks[f"{scan.scan_id}:verifier"]["status"] == "succeeded"


@pytest.mark.asyncio
async def test_the_plan_is_replaced_and_not_duplicated(services, orchestrator_parts):  # noqa: F811
    orchestrator, provider, services = orchestrator_parts
    scan = services.scans.create(
        {
            "name": "resumed scan",
            "status": "running",
            "created_by": "test",
            "definition": {"targets": ["https://demo.test/"]},
            "scope": {"authorized_hosts": ["demo.test"]},
            "phase": "agents",
        }
    )
    provider.script = [_conclusion("done"), _conclusion("done")]
    context = _context(services, scan_id=scan.scan_id)
    context.profile.agent_roles = ["recon"]
    await orchestrator.run(context)
    first = len(services.tasks.list_for_scan(scan.scan_id))

    provider.script = [_conclusion("done again")]
    await orchestrator.run(context)
    second = len(services.tasks.list_for_scan(scan.scan_id))
    # The second run replaces the plan instead of duplicating it.
    assert second == first
