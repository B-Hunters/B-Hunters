"""The durable job queue: claim, lease, retry, release and cancel."""

from __future__ import annotations

import time
from dataclasses import replace

import pytest

from b_hunters.platform.db.client import Database
from b_hunters.platform.db.jobs import JobRepository


@pytest.fixture(scope="module")
def database(settings):
    """A database of its own for the queue tests.

    The job queue is shared with the API tests, which empty it between
    their own tests.  The queue tests get a database of their own so
    that they neither depend on nor disturb the rest of the suite.
    """
    db = Database(replace(settings, mongo_db=f"{settings.mongo_db}-queue"))
    if not db.ping():
        pytest.skip(f"MongoDB is not reachable at {settings.mongo_uri}")
    db.ensure_indexes()
    yield db
    db.collection("platform_jobs").delete_many({})
    db.close()


@pytest.fixture(autouse=True)
def _clean(database):
    database.collection("platform_jobs").delete_many({})
    yield


def test_a_queued_job_is_claimed_exactly_once(database):
    repo = JobRepository(database)
    job = repo.enqueue(kind="scan", payload={"scan_id": "s1"})
    first = repo.claim(owner="runner-a")
    second = repo.claim(owner="runner-b")
    assert first["job_id"] == job["job_id"]
    assert first["status"] == "leased"
    assert first["lease_owner"] == "runner-a"
    assert second is None


def test_claim_orders_by_priority_then_age(database):
    repo = JobRepository(database)
    repo.enqueue(kind="scan", payload={"scan_id": "low"})
    repo.enqueue(kind="scan", payload={"scan_id": "high"}, priority=10)
    assert repo.claim(owner="r")["payload"]["scan_id"] == "high"


def test_an_expired_lease_is_claimed_again(database):
    repo = JobRepository(database)
    repo.enqueue(kind="scan", payload={"scan_id": "s1"})
    repo.claim(owner="dead-runner", lease_seconds=0)
    time.sleep(0.05)
    assert repo.claim(owner="live-runner")["lease_owner"] == "live-runner"


def test_a_heartbeat_extends_the_lease(database):
    repo = JobRepository(database)
    repo.enqueue(kind="scan", payload={"scan_id": "s1"})
    job = repo.claim(owner="runner-a", lease_seconds=1)
    time.sleep(0.05)
    assert repo.heartbeat(job["job_id"], owner="runner-a", lease_seconds=60)
    assert repo.claim(owner="runner-b") is None


def test_a_heartbeat_from_another_owner_is_refused(database):
    repo = JobRepository(database)
    repo.enqueue(kind="scan", payload={"scan_id": "s1"})
    job = repo.claim(owner="runner-a")
    assert not repo.heartbeat(job["job_id"], owner="runner-b")


def test_a_failing_job_is_retried_until_the_attempt_limit(database):
    repo = JobRepository(database)
    repo.enqueue(kind="scan", payload={"scan_id": "s1"}, max_attempts=2)
    first = repo.claim(owner="runner-a")
    repo.fail(first["job_id"], owner="runner-a", error="boom")
    second = repo.claim(owner="runner-a")
    assert second["job_id"] == first["job_id"]
    assert second["attempts"] == 2
    repo.fail(second["job_id"], owner="runner-a", error="boom again")
    assert repo.get(first["job_id"])["status"] == "failed"
    assert repo.claim(owner="runner-a") is None


def test_release_returns_the_job_to_the_queue(database):
    repo = JobRepository(database)
    repo.enqueue(kind="scan", payload={"scan_id": "s1"})
    job = repo.claim(owner="runner-a")
    repo.release(job["job_id"], owner="runner-a", delay_seconds=0)
    assert repo.get(job["job_id"])["status"] == "queued"
    assert repo.claim(owner="runner-b")["job_id"] == job["job_id"]


def test_a_cancelled_job_is_never_claimed(database):
    repo = JobRepository(database)
    job = repo.enqueue(kind="scan", payload={"scan_id": "s1"})
    repo.cancel(job["job_id"])
    assert repo.claim(owner="runner-a") is None


def test_find_live_returns_the_job_of_a_scan(database):
    repo = JobRepository(database)
    repo.enqueue(kind="scan", payload={"scan_id": "s1"})
    repo.enqueue(kind="scan", payload={"scan_id": "s2"})
    assert repo.find_live("s1")["payload"]["scan_id"] == "s1"
    assert repo.find_live("s3") is None
