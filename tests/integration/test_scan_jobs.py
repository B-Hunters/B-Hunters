"""The API enqueues a scan instead of running it in its own process.

The API must not start a scan itself: a scan that the API runs dies with
the API.  The API writes a job document and returns; the runner process
picks the job up.  These tests pin that behaviour and the operator
controls that go with it: a scan that is stopped while it is still queued
must never run.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _clean(services):
    """Start every test with an empty queue."""
    services.db.collection("platform_jobs").delete_many({})
    yield


def _create_scan(client, csrf):
    response = client.post(
        "/api/v1/scans",
        json={
            "name": "queued scan",
            "targets": {
                "urls": ["https://demo.test/"],
                "authorized_hosts": ["demo.test"],
                "excluded_paths": [],
            },
            "profile": "standard",
            "scanners": ["security_headers"],
            "agent_roles": ["recon"],
            "test_accounts": [],
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 201, response.text
    return response.json()["scan_id"]


def test_starting_a_scan_enqueues_a_job(client, csrf, services):
    scan_id = _create_scan(client, csrf)
    response = client.post(f"/api/v1/scans/{scan_id}/start", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "queued"
    assert payload["scan_id"] == scan_id
    job = services.jobs.get(payload["job_id"])
    assert job["kind"] == "scan"
    assert job["payload"]["scan_id"] == scan_id
    assert job["status"] == "queued"
    assert services.scans.get(scan_id).status == "queued"


def test_starting_a_scan_creates_exactly_one_job(client, csrf, services):
    scan_id = _create_scan(client, csrf)
    client.post(f"/api/v1/scans/{scan_id}/start", headers={"X-CSRF-Token": csrf})
    jobs = [
        job
        for job in services.jobs.list()
        if job["kind"] == "scan" and job["payload"].get("scan_id") == scan_id
    ]
    assert len(jobs) == 1


def test_starting_a_scan_records_the_queue_event(client, csrf, services):
    scan_id = _create_scan(client, csrf)
    client.post(f"/api/v1/scans/{scan_id}/start", headers={"X-CSRF-Token": csrf})
    kinds = [event["kind"] for event in services.events.list_after(scan_id)]
    assert "scan.queued" in kinds


def test_starting_the_same_scan_twice_is_refused(client, csrf, services):
    scan_id = _create_scan(client, csrf)
    client.post(f"/api/v1/scans/{scan_id}/start", headers={"X-CSRF-Token": csrf})
    response = client.post(f"/api/v1/scans/{scan_id}/start", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 409
    assert "job in flight" in response.json()["detail"]


def test_stopping_a_queued_scan_cancels_its_job(client, csrf, services):
    scan_id = _create_scan(client, csrf)
    started = client.post(f"/api/v1/scans/{scan_id}/start", headers={"X-CSRF-Token": csrf}).json()
    response = client.post(f"/api/v1/scans/{scan_id}/stop", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200
    assert services.jobs.get(started["job_id"])["status"] == "cancelled"
    assert services.scans.get(scan_id).status in {"stopping", "cancelled"}
