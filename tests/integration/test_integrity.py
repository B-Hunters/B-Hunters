"""The error ledger and the integrity verdict.

A scan fails: a request is refused, a page is missing, a tool times
out.  Those are what a scanner produces when it works.  A failure the
platform cannot name is a different thing, and it is the only thing
that fails the verdict of a scan.

The verdict is written onto the scan when it ends and it can be read
again afterwards, recomputed from the records the scan kept.
"""

from __future__ import annotations

import time
from dataclasses import replace

import pytest

from b_hunters.platform.agents.provider import Provider, ProviderConfig, ProviderError
from b_hunters.platform.api.deps import Services, set_services
from b_hunters.platform.db.client import Database
from b_hunters.platform.errors import ledger_from_records
from b_hunters.platform.tools.builtin import build_tool_registry

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def database(settings):
    """A database of this test's own.

    The other agents work against the same MongoDB, so the rows of this
    test live in a database of their own and only its own collections are
    cleaned.
    """
    scoped = replace(settings, mongo_db=f"{settings.mongo_db}-integrity")
    db = Database(scoped)
    if not db.ping():
        pytest.skip(f"MongoDB is not reachable at {settings.mongo_uri}")
    db.ensure_indexes()
    yield db
    for name in (
        "platform_scans",
        "platform_tasks",
        "platform_tool_calls",
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


def _scan(client, csrf):
    payload = {
        "name": f"integrity scan {int(time.time() * 1000)}",
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
    response = client.post("/api/v1/scans", json=payload, headers={"X-CSRF-Token": csrf})
    assert response.status_code == 201, response.text
    return response.json()["scan_id"]


def _integrity(client, csrf, scan_id):
    response = client.get(f"/api/v1/scans/{scan_id}/integrity", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200, response.text
    return response.json()


def _failed_task(services, scan_id, role="recon", error="Connection refused"):
    task_id = f"{scan_id}:{role}"
    services.tasks.upsert(
        scan_id=scan_id,
        task_id=task_id,
        title=f"{role} task",
        kind="agent",
        agent_role=role,
    )
    services.tasks.set_status(task_id, "failed", error=error)
    return task_id


def _failed_tool_call(services, scan_id, error="HTTP 404 Not Found"):
    services.db.collection("platform_tool_calls").insert_one(
        {
            "scan_id": scan_id,
            "task_id": f"{scan_id}:recon",
            "agent_role": "recon",
            "tool": "http_request",
            "call_id": "call-1",
            "status": "error",
            "error": error,
            "at": time.time(),
        }
    )


# ----------------------------------------------------------------------
# The verdict
# ----------------------------------------------------------------------
def test_a_scan_without_a_failure_passes(client, csrf, services) -> None:
    scan_id = _scan(client, csrf)

    payload = _integrity(client, csrf, scan_id)

    assert payload["verdict"] == "pass"
    assert payload["unexplained"] == 0
    assert payload["total"] == 0


def test_an_explained_failure_does_not_fail_the_verdict(client, csrf, services) -> None:
    scan_id = _scan(client, csrf)
    _failed_tool_call(services, scan_id, error="HTTP 404 Not Found")
    _failed_task(services, scan_id, error="Connection refused")

    payload = _integrity(client, csrf, scan_id)

    assert payload["verdict"] == "pass"
    assert payload["by_class"]["http_status"] == 1
    assert payload["by_class"]["connection"] == 1


def test_a_failure_without_an_explanation_fails_the_verdict(client, csrf, services) -> None:
    scan_id = _scan(client, csrf)
    _failed_task(services, scan_id, error="RuntimeError: object has no attribute 'x'")

    payload = _integrity(client, csrf, scan_id)

    assert payload["verdict"] == "fail"
    assert payload["crash"] == 1


def test_an_unnamed_failure_fails_the_verdict(client, csrf, services) -> None:
    scan_id = _scan(client, csrf)
    _failed_task(services, scan_id, error="")

    payload = _integrity(client, csrf, scan_id)

    assert payload["verdict"] == "fail"
    assert payload["unexplained"] == 1


def test_a_scanner_error_is_in_the_ledger(client, csrf, services) -> None:
    scan_id = _scan(client, csrf)
    services.events.append(
        scan_id=scan_id,
        kind="scanner.error",
        payload={"scanner": "asset_crawl", "error": "the request timed out"},
    )

    payload = _integrity(client, csrf, scan_id)

    assert payload["by_class"]["timeout"] == 1
    assert payload["verdict"] == "pass"


def test_a_worker_error_is_in_the_ledger(client, csrf, services) -> None:
    scan_id = _scan(client, csrf)
    services.events.append(
        scan_id=scan_id,
        kind="worker.error",
        payload={"target": "demo.test", "error": "the host could not be resolved"},
    )

    payload = _integrity(client, csrf, scan_id)

    assert payload["by_class"]["dns"] == 1


def test_the_entries_say_where_the_failure_came_from(client, csrf, services) -> None:
    scan_id = _scan(client, csrf)
    _failed_tool_call(services, scan_id, error="HTTP 404 Not Found")
    _failed_task(services, scan_id, error="Connection refused")

    payload = _integrity(client, csrf, scan_id)

    sources = {entry["source"] for entry in payload["entries"]}
    assert sources == {"tool_call", "task"}


# ----------------------------------------------------------------------
# The verdict the scan recorded
# ----------------------------------------------------------------------
def test_the_verdict_is_written_onto_the_scan(client, csrf, services) -> None:
    from b_hunters.platform.agents.orchestrator import ScanOrchestrator

    scan_id = _scan(client, csrf)
    _failed_task(services, scan_id, error="Connection refused")
    orchestrator = ScanOrchestrator(database=services.db, settings=services.settings)

    orchestrator._write_integrity(scan_id)

    document = services.db.collection("platform_scans").find_one({"scan_id": scan_id}) or {}
    integrity = document.get("integrity") or {}
    assert integrity["verdict"] == "pass"
    assert integrity["by_class"]["connection"] == 1


def test_the_verdict_that_was_recorded_is_served_with_the_new_one(client, csrf, services) -> None:
    scan_id = _scan(client, csrf)
    services.scans.update(
        scan_id,
        {"integrity": {"verdict": "pass", "unexplained": 0, "by_class": {}, "total": 0}},
    )
    _failed_task(services, scan_id, error="RuntimeError: boom")

    payload = _integrity(client, csrf, scan_id)

    assert payload["stored"]["verdict"] == "pass"
    assert payload["verdict"] == "fail"


def test_the_integrity_of_an_unknown_scan_is_a_404(client, csrf) -> None:
    response = client.get("/api/v1/scans/does-not-exist/integrity", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 404


def test_the_integrity_needs_a_session(client) -> None:
    response = client.get("/api/v1/scans/whatever/integrity")
    assert response.status_code == 401


# ----------------------------------------------------------------------
# The verdict of a scan that ran
# ----------------------------------------------------------------------
class FailingProvider(Provider):
    """A provider whose endpoint answers with an error."""

    async def complete(self, messages, **kwargs):  # type: ignore[override]
        raise ProviderError("the model endpoint returned 500", retryable=False)

    async def supports_native_tools(self) -> bool:  # type: ignore[override]
        return True


@pytest.mark.asyncio
async def test_a_scan_that_ended_records_its_verdict(services, tmp_path) -> None:
    """The verdict of a scan is written when the scan ends."""
    from b_hunters.platform.agents.orchestrator import ScanContext, ScanOrchestrator, ScanProfile

    scan = services.scans.create(
        {
            "name": "integrity scan",
            "status": "queued",
            "created_by": "test",
            "definition": {"targets": ["https://demo.test/"]},
            "scope": {"authorized_hosts": ["demo.test"]},
        }
    )
    orchestrator = ScanOrchestrator(
        database=services.db,
        settings=services.settings,
        provider_factory=lambda name="": FailingProvider(
            ProviderConfig(base_url="https://mock.test/v1", model="mock", api_key="mock")
        ),
        tool_registry=build_tool_registry(),
    )
    orchestrator.settings.agent_workspace_root = str(tmp_path)
    context = ScanContext(
        scan_id=scan.scan_id,
        name="integrity scan",
        targets=["https://demo.test/"],
        authorized_hosts=["demo.test"],
        profile=ScanProfile.default(),
        max_duration_seconds=60,
    )
    context.profile.agent_roles = ["recon"]

    await orchestrator.run(context)

    document = services.db.collection("platform_scans").find_one({"scan_id": scan.scan_id}) or {}
    integrity = document.get("integrity") or {}
    assert integrity
    # The provider answered with a 500: the failure has a name.
    assert integrity["verdict"] == "pass"
    assert integrity["by_class"]["http_status"] == 1


@pytest.mark.asyncio
async def test_the_verdict_of_a_scan_that_ran_matches_the_ledger_again(services, tmp_path) -> None:
    """What the scan recorded is what the ledger says when it is read again."""
    from b_hunters.platform.agents.orchestrator import ScanContext, ScanOrchestrator, ScanProfile

    scan = services.scans.create(
        {
            "name": "integrity scan",
            "status": "queued",
            "created_by": "test",
            "definition": {"targets": ["https://demo.test/"]},
            "scope": {"authorized_hosts": ["demo.test"]},
        }
    )
    orchestrator = ScanOrchestrator(
        database=services.db,
        settings=services.settings,
        provider_factory=lambda name="": FailingProvider(
            ProviderConfig(base_url="https://mock.test/v1", model="mock", api_key="mock")
        ),
        tool_registry=build_tool_registry(),
    )
    orchestrator.settings.agent_workspace_root = str(tmp_path)
    context = ScanContext(
        scan_id=scan.scan_id,
        name="integrity scan",
        targets=["https://demo.test/"],
        authorized_hosts=["demo.test"],
        profile=ScanProfile.default(),
        max_duration_seconds=60,
    )
    context.profile.agent_roles = ["recon"]

    await orchestrator.run(context)

    stored = services.db.collection("platform_scans").find_one({"scan_id": scan.scan_id}) or {}
    recomputed = ledger_from_records(
        tool_calls=services.tool_calls.list_for_scan(scan.scan_id, limit=5000),
        events=services.events.list_after(scan.scan_id, 0, limit=2000),
        tasks=services.tasks.list_for_scan(scan.scan_id),
    ).verdict()
    assert (stored.get("integrity") or {})["by_class"] == recomputed["by_class"]
