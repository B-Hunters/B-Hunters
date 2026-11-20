"""The runner process: claim a job, run it, heartbeat the lease and retry."""

from __future__ import annotations

import asyncio
import time
from dataclasses import replace

import pytest

from b_hunters.platform.api.deps import Services
from b_hunters.platform.db.client import Database
from b_hunters.platform.runner import Runner, RunnerConfig


class RecordingExecutor:
    """An executor that records the jobs it was given."""

    def __init__(self, *, fail_times: int = 0, delay: float = 0.0):
        self.calls: list[dict] = []
        self.fail_times = fail_times
        self.delay = delay

    async def execute(self, job):
        self.calls.append(job)
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.fail_times > 0:
            self.fail_times -= 1
            raise RuntimeError("executor failed")
        return {"status": "completed"}


@pytest.fixture(scope="module")
def services(settings):
    """A service container on a database of its own.

    The job queue is shared with the API tests, which empty it between
    their own tests.  The runner tests get a database of their own so
    that they neither depend on nor disturb the rest of the suite.
    """
    db = Database(replace(settings, mongo_db=f"{settings.mongo_db}-queue"))
    if not db.ping():
        pytest.skip(f"MongoDB is not reachable at {settings.mongo_uri}")
    db.ensure_indexes()
    container = Services(db, settings)
    yield container
    db.collection("platform_jobs").delete_many({})
    db.close()


@pytest.fixture(autouse=True)
def _clean(services):
    """Start every test with an empty queue."""
    services.db.collection("platform_jobs").delete_many({})
    yield


def test_the_runner_claims_and_completes_a_job(services):
    jobs = services.jobs
    jobs.enqueue(kind="scan", payload={"scan_id": "s1"})
    executor = RecordingExecutor()
    runner = Runner(services, RunnerConfig(owner="runner-a"), executor)
    result = asyncio.run(runner.run_once())
    assert result["status"] == "completed"
    assert jobs.list()[0]["status"] == "succeeded"


def test_a_failing_job_is_retried_and_then_fails(services):
    jobs = services.jobs
    jobs.enqueue(kind="scan", payload={"scan_id": "s1"}, max_attempts=2)
    executor = RecordingExecutor(fail_times=2)
    runner = Runner(services, RunnerConfig(owner="runner-a"), executor)
    asyncio.run(runner.run_once())
    assert jobs.list()[0]["status"] == "queued"
    asyncio.run(runner.run_once())
    assert jobs.list()[0]["status"] == "failed"
    assert "executor failed" in jobs.list()[0]["error"]


def test_the_runner_heartbeats_the_lease(services):
    jobs = services.jobs
    jobs.enqueue(kind="scan", payload={"scan_id": "s1"})
    runner = Runner(
        services,
        RunnerConfig(owner="runner-a", heartbeat_seconds=0.05),
        RecordingExecutor(delay=0.2),
    )
    asyncio.run(runner.run_once())
    job = jobs.list()[0]
    assert job["heartbeat_at"] >= job["created_at"]


def test_a_job_whose_lease_expired_is_claimed_again(services):
    jobs = services.jobs
    jobs.enqueue(kind="scan", payload={"scan_id": "s1"})
    jobs.claim(owner="dead-runner", lease_seconds=0)
    time.sleep(0.05)
    runner = Runner(services, RunnerConfig(owner="live-runner"), RecordingExecutor())
    asyncio.run(runner.run_once())
    assert jobs.list()[0]["status"] == "succeeded"


def test_two_runners_never_claim_the_same_job(services):
    jobs = services.jobs
    for index in range(5):
        jobs.enqueue(kind="scan", payload={"scan_id": f"s{index}"})
    first = Runner(services, RunnerConfig(owner="runner-a"), RecordingExecutor())
    second = Runner(services, RunnerConfig(owner="runner-b"), RecordingExecutor())

    async def run_both():
        await asyncio.gather(first.run_once(), second.run_once())

    asyncio.run(run_both())
    # Only the jobs that were actually claimed carry an owner; the rest
    # are still queued.  The two runners must have taken two different
    # jobs, and no job twice.
    claimed = [job["lease_owner"] for job in jobs.list() if job["lease_owner"]]
    assert len(claimed) == 2
    assert len(set(claimed)) == 2


def test_drain_stops_the_runner(services):
    services.jobs.enqueue(kind="scan", payload={"scan_id": "s1"})
    runner = Runner(services, RunnerConfig(owner="runner-a"), RecordingExecutor())
    runner.drain()
    asyncio.run(runner.run_once())
    assert services.jobs.list()[0]["status"] == "queued"


def test_a_scan_that_was_stopped_and_never_finished_is_cancelled(services):
    """A runner that dies mid-scan leaves the scan saying "stopping".

    The job is over, so no runner will pick the scan up again, and
    nothing else will ever move it: the console cannot tell it from a
    scan that is still going.
    """
    from b_hunters.platform.scan_factory import create_scan_from_template

    scan = create_scan_from_template(
        services,
        template={
            "targets": {"urls": ["https://demo.test/"], "authorized_hosts": ["demo.test"]},
            "profile": "standard",
            "test_environment": True,
        },
        name="the scan that was stopped",
    )
    services.scans.set_status(scan.scan_id, "stopping")
    # The job of the scan is over: it was cancelled, so no runner will
    # take it again.
    job = services.jobs.enqueue(kind="scan", payload={"scan_id": scan.scan_id})
    services.jobs.cancel(job["job_id"])

    runner = Runner(services, RunnerConfig(owner="runner-a"), RecordingExecutor())
    finished = runner.reconcile_stopped_scans()

    assert scan.scan_id in finished
    assert services.scans.get(scan.scan_id).status == "cancelled"


def test_a_scan_with_a_live_job_is_left_to_the_runner_that_owns_it(services):
    from b_hunters.platform.scan_factory import create_scan_from_template

    scan = create_scan_from_template(
        services,
        template={
            "targets": {"urls": ["https://demo.test/"], "authorized_hosts": ["demo.test"]},
            "profile": "standard",
            "test_environment": True,
        },
        name="the scan that is still going",
    )
    services.scans.set_status(scan.scan_id, "stopping")
    services.jobs.enqueue(kind="scan", payload={"scan_id": scan.scan_id})

    runner = Runner(services, RunnerConfig(owner="runner-a"), RecordingExecutor())
    finished = runner.reconcile_stopped_scans()

    assert finished == []
    assert services.scans.get(scan.scan_id).status == "stopping"
