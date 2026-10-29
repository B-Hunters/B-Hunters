"""Which tools took part in a scan.

The table answers the question the console could not answer before:
did every tool report?  A tool that ran and found nothing is not the
same as a tool that never ran, and the reason says which is which.

The reasons are facts the scan recorded while it ran - they are not
guessed when the table is read.
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
    scoped = replace(settings, mongo_db=f"{settings.mongo_db}-participation")
    db = Database(scoped)
    if not db.ping():
        pytest.skip(f"MongoDB is not reachable at {settings.mongo_uri}")
    db.ensure_indexes()
    yield db
    for name in (
        "platform_worker_runs",
        "platform_worker_output",
        "platform_scans",
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


def _scan(client, csrf, **overrides):
    payload = {
        "name": f"participation scan {int(time.time() * 1000)}",
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


def _participation(client, csrf, scan_id):
    response = client.get(f"/api/v1/scans/{scan_id}/participation", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200, response.text
    return response.json()


def _worker(payload, identity):
    for row in payload["workers"]:
        if row["worker"] == identity:
            return row
    raise AssertionError(f"{identity} is not in the participation table")


# ----------------------------------------------------------------------
# The table
# ----------------------------------------------------------------------
def test_the_participation_table_accounts_for_every_worker(client, csrf, services) -> None:
    scan_id = _scan(client, csrf)

    payload = _participation(client, csrf, scan_id)

    assert len(payload["workers"]) == 17
    assert payload["coverage"]["workers"]["total"] == 17
    assert payload["native_adapters"]


def test_a_worker_that_never_ran_is_reported_as_not_connected(client, csrf, services) -> None:
    scan_id = _scan(client, csrf)

    payload = _participation(client, csrf, scan_id)

    row = _worker(payload, "B-Hunters-Nuclei")
    assert row["reason"] == "not connected"
    assert row["participated"] is False
    assert row["connected_at_scan_start"] is False


def test_a_worker_that_was_online_but_never_dispatched_is_reported(client, csrf, services) -> None:
    scan_id = _scan(client, csrf)
    services.worker_runs.snapshot_connection(scan_id, ["B-Hunters-Nuclei"])

    payload = _participation(client, csrf, scan_id)

    row = _worker(payload, "B-Hunters-Nuclei")
    assert row["reason"] == "never dispatched"
    assert row["participated"] is False
    assert row["connected_at_scan_start"] is True


def test_a_worker_that_ran_and_found_nothing_is_not_reported_as_absent(client, csrf, services) -> None:
    scan_id = _scan(client, csrf)
    services.worker_runs.record(scan_id=scan_id, worker="B-Hunters-Nuclei", tasks=2, connected=True)

    payload = _participation(client, csrf, scan_id)

    row = _worker(payload, "B-Hunters-Nuclei")
    assert row["reason"] == "ran, found nothing"
    assert row["participated"] is True
    assert row["tasks"] == 2


def test_a_worker_that_errored_is_reported_as_errored(client, csrf, services) -> None:
    scan_id = _scan(client, csrf)
    services.worker_runs.record(
        scan_id=scan_id,
        worker="B-Hunters-Nuclei",
        tasks=2,
        findings=1,
        crashed_tasks=1,
        connected=True,
    )

    payload = _participation(client, csrf, scan_id)

    row = _worker(payload, "B-Hunters-Nuclei")
    assert row["reason"] == "errored"
    assert row["crashed_tasks"] == 1
    assert row["participated"] is True


def test_a_worker_that_found_something_is_reported_as_ran(client, csrf, services) -> None:
    scan_id = _scan(client, csrf)
    services.worker_runs.record(
        scan_id=scan_id, worker="B-Hunters-Nuclei", tasks=1, findings=3, connected=True
    )

    payload = _participation(client, csrf, scan_id)

    row = _worker(payload, "B-Hunters-Nuclei")
    assert row["reason"] == "ran"
    assert row["findings"] == 3


def test_the_version_of_a_worker_is_the_expected_one(client, csrf, services) -> None:
    """The workers do not report a version, so the label says so."""
    scan_id = _scan(client, csrf)

    payload = _participation(client, csrf, scan_id)

    row = _worker(payload, "B-Hunters-Nuclei")
    assert row["expected_version"] == "1.1.16"
    assert payload["health"]["version_label"] == "expected"
    assert payload["health"]["expected_versions"]["B-Hunters-Nuclei"] == "1.1.16"


def test_the_health_line_names_the_workers_that_were_online(client, csrf, services) -> None:
    scan_id = _scan(client, csrf)
    services.worker_runs.snapshot_connection(scan_id, ["B-Hunters-Katana"])

    payload = _participation(client, csrf, scan_id)

    assert payload["health"]["online_at_scan_start"] == ["B-Hunters-Katana"]
    assert "B-Hunters-Nuclei" in payload["health"]["not_connected"]


# ----------------------------------------------------------------------
# The native adapters
# ----------------------------------------------------------------------
def test_the_native_adapters_are_listed_with_their_status(client, csrf, services) -> None:
    scan_id = _scan(client, csrf)

    payload = _participation(client, csrf, scan_id)

    names = [row["name"] for row in payload["native_adapters"]]
    assert "asset_crawl" in names
    assert "service_fingerprint" in names
    for row in payload["native_adapters"]:
        assert row["version"]


def test_an_adapter_that_ran_is_reported_as_succeeded(client, csrf, services) -> None:
    scan_id = _scan(client, csrf)
    services.events.append(
        scan_id=scan_id,
        kind="scanner.completed",
        payload={"scanner": "asset_crawl", "ok": True, "error": "", "items": 12},
    )

    payload = _participation(client, csrf, scan_id)

    row = next(item for item in payload["native_adapters"] if item["name"] == "asset_crawl")
    assert row["status"] == "succeeded"
    assert row["items"] == 12
    assert row["participated"] is True


def test_an_adapter_that_was_not_selected_is_reported_as_such(client, csrf, services) -> None:
    scan_id = _scan(client, csrf)
    services.scans.update(
        scan_id,
        {
            "definition": {
                "targets": ["https://demo.test/"],
                "profile": {"name": "standard", "scanners": ["asset_crawl"]},
            }
        },
    )

    payload = _participation(client, csrf, scan_id)

    for row in payload["native_adapters"]:
        if row["name"] == "asset_crawl":
            assert row["status"] == "not run"
            continue
        assert row["status"] == "not selected"
        assert row["participated"] is False


# ----------------------------------------------------------------------
# The coverage line
# ----------------------------------------------------------------------
def test_the_coverage_line_counts_both_sections(client, csrf, services) -> None:
    scan_id = _scan(client, csrf)
    services.worker_runs.record(
        scan_id=scan_id, worker="B-Hunters-Nuclei", tasks=1, findings=1, connected=True
    )
    services.events.append(
        scan_id=scan_id,
        kind="scanner.completed",
        payload={"scanner": "asset_crawl", "ok": True, "error": "", "items": 3},
    )

    payload = _participation(client, csrf, scan_id)

    coverage = payload["coverage"]
    assert coverage["workers"]["participated"] == 1
    assert coverage["workers"]["not_connected"] == 16
    assert coverage["native_adapters"]["participated"] == 1
    assert "17 workers" in coverage["line"]
    assert "participated" in coverage["line"]


# ----------------------------------------------------------------------
# The endpoint
# ----------------------------------------------------------------------
def test_the_participation_of_an_unknown_scan_is_a_404(client, csrf) -> None:
    response = client.get("/api/v1/scans/does-not-exist/participation", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 404


def test_the_participation_needs_a_session(client) -> None:
    response = client.get("/api/v1/scans/whatever/participation")
    assert response.status_code == 401
