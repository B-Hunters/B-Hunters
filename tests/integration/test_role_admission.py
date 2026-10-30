"""The roles a scan runs.

A reasoning model spends about 150 seconds and 150,000 tokens on one
role, so twelve roles need nine minutes of agent time on their own.  A
scan whose budget is smaller than that has to choose, and the choice
has to be visible: the roles that run are the ones that yield the most,
and the ones that do not run are recorded as cut off with the reason.
"""

from __future__ import annotations

import uuid

import pytest

from b_hunters.platform.agents.orchestrator import ROLE_PRIORITY, ScanOrchestrator

pytestmark = pytest.mark.integration


class _Task:
    """A task of the plan."""

    def __init__(self, role: str, scan_id: str):
        self.role = role
        self.task_id = f"{scan_id}:{role}"


class _Context:
    """The context the admission needs."""

    def __init__(self, scan_id: str):
        self.scan_id = scan_id
        self.name = "the scan"


def _scan_id() -> str:
    """A scan of its own: the shared test database keeps every row."""
    return f"s-{uuid.uuid4().hex[:8]}"


def test_every_role_is_admitted_when_there_is_no_limit(services):
    orchestrator = ScanOrchestrator(database=services.db, settings=services.settings)
    scan_id = _scan_id()
    tasks = [_Task(role, scan_id) for role in ROLE_PRIORITY]

    admitted = orchestrator._admit_roles(_Context(scan_id), tasks)

    assert len(admitted) == len(tasks)


def test_the_roles_that_run_are_the_ones_that_yield_the_most(services):
    settings = services.settings
    settings.agent_max_roles = 2
    try:
        orchestrator = ScanOrchestrator(database=services.db, settings=settings)
        scan_id = _scan_id()
        tasks = [_Task(role, scan_id) for role in ROLE_PRIORITY]

        admitted = orchestrator._admit_roles(_Context(scan_id), tasks)
    finally:
        settings.agent_max_roles = 0

    assert [task.role for task in admitted] == ["recon", "javascript"]


def test_the_roles_that_do_not_run_are_recorded_as_cut_off(services):
    from b_hunters.platform.db.repositories import TaskRepository

    settings = services.settings
    settings.agent_max_roles = 1
    scan_id = _scan_id()
    try:
        orchestrator = ScanOrchestrator(database=services.db, settings=settings)
        tasks = []
        for role in ROLE_PRIORITY[:3]:
            orchestrator.tasks.create(
                scan_id=scan_id,
                task_id=f"{scan_id}:{role}",
                title=role,
                kind="agent",
                agent_role=role,
            )
            tasks.append(_Task(role, scan_id))

        admitted = orchestrator._admit_roles(_Context(scan_id), tasks)

        assert len(admitted) == 1
        stored = {task["task_id"]: task for task in TaskRepository(services.db).list_for_scan(scan_id)}
        assert stored[f"{scan_id}:javascript"]["status"] == "wall_clock"
        assert "budget" in stored[f"{scan_id}:javascript"]["error"]
    finally:
        settings.agent_max_roles = 0
