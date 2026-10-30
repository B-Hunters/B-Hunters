"""A role that stops learning should stop working.

The runtime ends a task whose rounds produce nothing new.  A role that
keeps making the same call with the same answer is not learning
anything, and paying for its remaining rounds buys the scan nothing.
"""

from __future__ import annotations

import pytest

from b_hunters.platform.agents.orchestrator import ScanContext, ScanOrchestrator
from b_hunters.platform.scanners.registry import build_default_registry
from b_hunters.platform.tools.builtin import build_tool_registry
from tests.integration.test_scan_lifecycle import ScriptedProvider, _conclusion

pytestmark = pytest.mark.integration


def _scan(services, name: str) -> object:
    return services.scans.create(
        {
            "name": name,
            "status": "queued",
            "created_by": "test",
            "definition": {"targets": ["https://demo.test/"]},
            "scope": {"authorized_hosts": ["demo.test"]},
        }
    )


def _context(services, scan_id: str) -> ScanContext:
    context = ScanContext(
        scan_id=scan_id,
        name="early stop",
        targets=["https://demo.test/"],
        authorized_hosts=["demo.test"],
        workspace_root="/tmp/b-hunters-test-workspaces",
    )
    context.profile.agent_roles = ["recon"]
    return context


def _orchestrator(services, provider) -> ScanOrchestrator:
    return ScanOrchestrator(
        database=services.db,
        settings=services.settings,
        provider_factory=lambda name="": provider,
        tool_registry=build_tool_registry(),
        scanner_registry=build_default_registry(),
    )


@pytest.mark.asyncio
async def test_a_role_that_repeats_itself_stops(services) -> None:
    """The same call with the same answer is not new evidence."""
    scan = _scan(services, "early stop")
    provider = ScriptedProvider(
        [
            {
                "content": "looking again",
                "tool_calls": [{"id": "c1", "name": "list_worker_output", "arguments": {}}],
            },
            {
                "content": "looking again",
                "tool_calls": [{"id": "c2", "name": "list_worker_output", "arguments": {}}],
            },
            {
                "content": "looking again",
                "tool_calls": [{"id": "c3", "name": "list_worker_output", "arguments": {}}],
            },
            {
                "content": "looking again",
                "tool_calls": [{"id": "c4", "name": "list_worker_output", "arguments": {}}],
            },
            {
                "content": "looking again",
                "tool_calls": [{"id": "c5", "name": "list_worker_output", "arguments": {}}],
            },
            _conclusion("done"),
        ]
    )
    orchestrator = _orchestrator(services, provider)

    await orchestrator.run(_context(services, scan.scan_id))

    task = services.tasks.list_for_scan(scan.scan_id)[0]
    assert task["status"] == "no_new_evidence"
    assert "nothing new" in (task.get("error") or "")
    # It stopped before the role could spend the whole budget.
    assert task["result"]["rounds"] < 6


@pytest.mark.asyncio
async def test_a_role_that_learns_something_keeps_going(services) -> None:
    """A round that finds something is never an empty round."""
    scan = _scan(services, "early stop")
    provider = ScriptedProvider(
        [
            {"tool_calls": [{"id": "c1", "name": "list_worker_output", "arguments": {"kind": "url"}}]},
            {"tool_calls": [{"id": "c2", "name": "list_worker_output", "arguments": {"kind": "path"}}]},
            {"tool_calls": [{"id": "c3", "name": "list_worker_output", "arguments": {"kind": "url"}}]},
            _conclusion("done"),
        ]
    )
    orchestrator = _orchestrator(services, provider)

    await orchestrator.run(_context(services, scan.scan_id))

    task = services.tasks.list_for_scan(scan.scan_id)[0]
    assert task["status"] == "succeeded"
    assert task["result"]["stop_reason"] == "completed"
