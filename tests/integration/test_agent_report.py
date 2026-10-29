"""The outcome of every agent role.

The per-role table answers the question the console could not answer:
what did each role do, why did it stop and what did it find.  A role
that never started is reported as a role that never started - never as
a role that succeeded.

The stop reason is read from the task result.  Nothing is derived from
an empty error string.
"""

from __future__ import annotations

import time
from dataclasses import replace

import pytest

from b_hunters.platform.api.deps import Services, set_services
from b_hunters.platform.db.client import Database

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def database(settings):
    """A database of this test's own.

    The other agents work against the same MongoDB, so the rows of this
    test live in a database of their own and only its own collections are
    cleaned.
    """
    scoped = replace(settings, mongo_db=f"{settings.mongo_db}-agentreport")
    db = Database(scoped)
    if not db.ping():
        pytest.skip(f"MongoDB is not reachable at {settings.mongo_uri}")
    db.ensure_indexes()
    yield db
    for name in (
        "platform_scans",
        "platform_tasks",
        "platform_findings",
        "platform_scan_events",
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


def _scan(client, csrf, **overrides):
    payload = {
        "name": f"agent report scan {int(time.time() * 1000)}",
        "targets": {
            "urls": ["https://demo.test/"],
            "authorized_hosts": ["demo.test"],
            "excluded_paths": [],
        },
        "profile": "standard",
        "scanners": [],
        "agent_roles": [],
        "test_accounts": [],
    }
    payload.update(overrides)
    response = client.post("/api/v1/scans", json=payload, headers={"X-CSRF-Token": csrf})
    assert response.status_code == 201, response.text
    return response.json()["scan_id"]


def _report(client, csrf, scan_id):
    response = client.get(f"/api/v1/scans/{scan_id}/agents/report", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200, response.text
    return response.json()


def _row(payload, role):
    for row in payload["roles"]:
        if row["role"] == role:
            return row
    raise AssertionError(f"{role} is not in the agent report")


def _agent_task(services, scan_id, role, *, status="succeeded", result=None, error=""):
    """Store the task of one role, the way the orchestrator stores it."""
    task_id = f"{scan_id}:{role}"
    services.tasks.upsert(
        scan_id=scan_id,
        task_id=task_id,
        title=f"{role} task",
        kind="agent",
        agent_role=role,
    )
    services.tasks.set_status(task_id, status, error=error, result=result)
    return task_id


# ----------------------------------------------------------------------
# The table
# ----------------------------------------------------------------------
def test_the_agent_report_names_every_planned_role(client, csrf, services) -> None:
    scan_id = _scan(client, csrf)

    payload = _report(client, csrf, scan_id)

    assert payload["built_in_roles"] == 13
    assert payload["roles"]
    assert "stop_reasons" in payload
    assert payload["planned_roles"] == len(payload["roles"])


def test_a_role_that_ran_is_reported_with_its_outcome(client, csrf, services) -> None:
    scan_id = _scan(client, csrf)
    _agent_task(
        services,
        scan_id,
        "recon",
        result={
            "role": "recon",
            "status": "succeeded",
            "stop_reason": "completed",
            "conclusion": "the target runs WordPress",
            "rounds": 4,
            "tool_calls_used": 7,
            "tokens_used": 1234,
        },
    )

    payload = _report(client, csrf, scan_id)

    row = _row(payload, "recon")
    assert row["tasks"] == 1
    assert row["status"] == "succeeded"
    assert row["stop_reason"] == "completed"
    assert row["rounds"] == 4
    assert row["tool_calls"] == 7
    assert row["tokens"] == 1234
    assert row["conclusion"] == "the target runs WordPress"


def test_a_role_that_was_cut_off_is_not_reported_as_succeeded(client, csrf, services) -> None:
    scan_id = _scan(client, csrf)
    _agent_task(
        services,
        scan_id,
        "api",
        status="wall_clock",
        error="the scan ran out of its time",
        result={"role": "api", "status": "wall_clock", "stop_reason": "wall_clock"},
    )

    payload = _report(client, csrf, scan_id)

    row = _row(payload, "api")
    assert row["status"] == "wall_clock"
    assert row["stop_reason"] == "wall_clock"
    assert row["status"] != "succeeded"


def test_a_role_that_never_started_is_reported_as_not_started(client, csrf, services) -> None:
    scan_id = _scan(client, csrf)

    payload = _report(client, csrf, scan_id)

    row = _row(payload, "recon")
    assert row["tasks"] == 0
    assert row["status"] != "succeeded"
    assert row["stop_reason"] != "completed"


def test_the_stop_reasons_are_counted(client, csrf, services) -> None:
    scan_id = _scan(client, csrf)
    _agent_task(
        services,
        scan_id,
        "recon",
        result={"role": "recon", "status": "succeeded", "stop_reason": "completed"},
    )
    _agent_task(
        services,
        scan_id,
        "api",
        status="wall_clock",
        error="the scan ran out of its time",
        result={"role": "api", "status": "wall_clock", "stop_reason": "wall_clock"},
    )

    payload = _report(client, csrf, scan_id)

    assert payload["stop_reasons"]["completed"] == 1
    assert payload["stop_reasons"]["wall_clock"] == 1


def test_the_findings_of_a_role_are_counted(client, csrf, services) -> None:
    scan_id = _scan(client, csrf)
    services.findings.upsert(
        scan_id=scan_id,
        title="a missing header",
        summary="the security headers are missing",
        vuln_class="headers",
        severity="low",
        host="demo.test",
        path="/",
        detected_by=["recon"],
        detection_source="agent",
    )
    services.findings.upsert(
        scan_id=scan_id,
        title="an open redirect",
        summary="the redirect goes anywhere",
        vuln_class="redirect",
        severity="medium",
        host="demo.test",
        path="/go",
        detected_by=["recon", "api"],
        detection_source="agent",
    )

    payload = _report(client, csrf, scan_id)

    assert _row(payload, "recon")["findings_raised"] == 2
    assert _row(payload, "api")["findings_raised"] == 1


def test_a_confirmed_finding_is_counted_as_confirmed(client, csrf, services) -> None:
    scan_id = _scan(client, csrf)
    document, _ = services.findings.upsert(
        scan_id=scan_id,
        title="an open redirect",
        summary="the redirect goes anywhere",
        vuln_class="redirect",
        severity="medium",
        host="demo.test",
        path="/go",
        detected_by=["recon"],
        detection_source="agent",
    )
    services.findings.set_verification(document["finding_id"], status="confirmed")

    payload = _report(client, csrf, scan_id)

    row = _row(payload, "recon")
    assert row["findings_raised"] == 1
    assert row["findings_confirmed"] == 1


def test_an_unverified_finding_is_not_counted_as_confirmed(client, csrf, services) -> None:
    scan_id = _scan(client, csrf)
    services.findings.upsert(
        scan_id=scan_id,
        title="an open redirect",
        summary="the redirect goes anywhere",
        vuln_class="redirect",
        severity="medium",
        host="demo.test",
        path="/go",
        detected_by=["recon"],
        detection_source="agent",
    )

    payload = _report(client, csrf, scan_id)

    assert _row(payload, "recon")["findings_confirmed"] == 0


def test_the_conclusion_is_truncated(client, csrf, services) -> None:
    scan_id = _scan(client, csrf)
    _agent_task(
        services,
        scan_id,
        "recon",
        result={
            "role": "recon",
            "status": "succeeded",
            "stop_reason": "completed",
            "conclusion": "x" * 900,
        },
    )

    payload = _report(client, csrf, scan_id)

    assert len(_row(payload, "recon")["conclusion"]) == 400


# ----------------------------------------------------------------------
# The endpoint
# ----------------------------------------------------------------------
def test_the_report_of_an_unknown_scan_is_a_404(client, csrf) -> None:
    response = client.get("/api/v1/scans/does-not-exist/agents/report", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 404


def test_the_report_needs_a_session(client) -> None:
    response = client.get("/api/v1/scans/whatever/agents/report")
    assert response.status_code == 401
