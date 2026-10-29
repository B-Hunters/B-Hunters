"""One scan per target at a time.

The scanner workers are a scarce resource: two scans of the same host
would compete for the same containers.  The runner therefore takes a
lock on the target before it runs a job and gives it back afterwards.
A job whose target is locked by somebody else goes back to the queue
instead of failing: it waits for the target instead of competing for it.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import replace

import pytest
from test_runner import RecordingExecutor

from b_hunters.platform.api.deps import Services
from b_hunters.platform.db.client import Database
from b_hunters.platform.db.jobs import TargetLockRepository
from b_hunters.platform.runner import Runner, RunnerConfig

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def database(settings):
    """A database of its own for the lock tests.

    The job queue is shared with the API tests, which leave jobs in it.
    The lock tests need a queue of their own, or they would claim (and
    run) a job that belongs to another test.
    """
    db = Database(replace(settings, mongo_db=f"{settings.mongo_db}-locks"))
    if not db.ping():
        pytest.skip(f"MongoDB is not reachable at {settings.mongo_uri}")
    db.ensure_indexes()
    yield db
    db.collection("platform_jobs").delete_many({})
    db.collection("platform_target_locks").delete_many({})
    db.close()


@pytest.fixture(scope="module")
def services(database, settings):
    """A service container on the database of the module."""
    yield Services(database, settings)


@pytest.fixture(autouse=True)
def _clean(database):
    """Start every test with an empty queue and an empty set of locks."""
    database.collection("platform_jobs").delete_many({})
    database.collection("platform_target_locks").delete_many({})
    yield


def test_a_lock_is_exclusive(database):
    locks = TargetLockRepository(database)
    assert locks.acquire(target_key="demo.test", owner="runner-a")
    assert not locks.acquire(target_key="demo.test", owner="runner-b")
    assert locks.holder("demo.test")["owner"] == "runner-a"


def test_release_frees_the_lock(database):
    locks = TargetLockRepository(database)
    locks.acquire(target_key="demo.test", owner="runner-a")
    assert locks.release(target_key="demo.test", owner="runner-a")
    assert locks.acquire(target_key="demo.test", owner="runner-b")


def test_a_lock_expires(database):
    locks = TargetLockRepository(database)
    locks.acquire(target_key="demo.test", owner="runner-a", ttl_seconds=0)
    time.sleep(0.05)
    assert locks.acquire(target_key="demo.test", owner="runner-b")


def test_the_runner_defers_a_scan_of_a_locked_target(services):
    services.locks.acquire(target_key="demo.test", owner="other-runner")
    job = services.jobs.enqueue(kind="scan", payload={"scan_id": "s1", "target_key": "demo.test"})
    executor = RecordingExecutor()
    runner = Runner(services, RunnerConfig(owner="runner-a"), executor)
    asyncio.run(runner.run_once())
    assert executor.calls == []
    assert services.jobs.get(job["job_id"])["status"] == "queued"


def test_a_job_without_a_target_key_runs_without_a_lock(services):
    job = services.jobs.enqueue(kind="scan", payload={"scan_id": "s1"})
    executor = RecordingExecutor()
    runner = Runner(services, RunnerConfig(owner="runner-a"), executor)
    result = asyncio.run(runner.run_once())
    assert result["status"] == "completed"
    assert len(executor.calls) == 1
    assert services.jobs.get(job["job_id"])["status"] == "succeeded"


def test_the_runner_takes_and_releases_the_target_lock(services):
    job = services.jobs.enqueue(kind="scan", payload={"scan_id": "s1", "target_key": "demo.test"})
    executor = RecordingExecutor()
    runner = Runner(services, RunnerConfig(owner="runner-a"), executor)
    asyncio.run(runner.run_once())
    assert len(executor.calls) == 1
    assert services.jobs.get(job["job_id"])["status"] == "succeeded"
    # The lock is given back, so the next scan of the target may run.
    assert services.locks.holder("demo.test") is None


def test_the_lock_is_released_when_the_job_fails(services):
    services.jobs.enqueue(kind="scan", payload={"scan_id": "s1", "target_key": "demo.test"})
    executor = RecordingExecutor(fail_times=1)
    runner = Runner(services, RunnerConfig(owner="runner-a"), executor)
    asyncio.run(runner.run_once())
    assert services.locks.holder("demo.test") is None
