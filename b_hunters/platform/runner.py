"""The runner: the process that executes the queued jobs.

The API does not run scans itself: it enqueues a job and returns.  The
runner is the process that picks the job up, runs it and records the
outcome, so a scan survives a restart of the API and of the runner
itself.

The runner claims a job with an atomic update, leases it, and renews the
lease (the heartbeat) while the job runs.  A runner that dies leaves the
lease behind; when it expires, the job is claimed again and the scan is
not lost.

The runner also holds the lock of the target it works on: only one scan
of a host runs at a time, because the scanner workers are a scarce
resource.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import socket
import time
from dataclasses import dataclass
from typing import Any, Optional, Protocol

from .agents.factory import build_orchestrator, build_scan_context
from .api.deps import Services

log = logging.getLogger(__name__)

#: The kinds of job the runner claims.
RUNNER_JOB_KINDS = ("scan", "benchmark")

#: How long a job waits for a target that is locked by somebody else.
LOCK_RETRY_SECONDS = 30

#: The counter key that tells the runner to drain.
DRAIN_COUNTER_KEY = "runner:drain"

#: How old a runner heartbeat may be before the runner counts as stale.
HEARTBEAT_MAX_AGE_SECONDS = 90.0


@dataclass(frozen=True)
class RunnerConfig:
    """How the runner behaves."""

    #: How many jobs the runner works on at the same time.
    concurrency: int = 1
    #: How long a claimed job stays leased before another runner may take it.
    lease_seconds: int = 60
    #: How often the lease of the job in flight is renewed.
    heartbeat_seconds: int = 10
    #: How long the runner waits for a new job when the queue is empty.
    poll_seconds: float = 2.0
    #: How long a draining runner waits for the job it is working on.
    shutdown_grace_seconds: int = 300
    #: The identity of this runner.  It defaults to the host and the pid,
    #: so two runners on the same host never share a lease.
    owner: str = ""

    def __post_init__(self) -> None:
        if not self.owner:
            object.__setattr__(self, "owner", f"{socket.gethostname()}-{os.getpid()}")


class JobExecutor(Protocol):
    """What the runner needs from the thing that runs a job."""

    async def execute(self, job: dict[str, Any]) -> dict[str, Any]:
        """Run one job and return its result."""
        ...


class ScanJobExecutor:
    """Runs a scan job with the orchestrator."""

    def __init__(self, services: Services) -> None:
        self.services = services

    async def execute(self, job: dict[str, Any]) -> dict[str, Any]:
        """Run the job and return its result."""
        kind = str(job.get("kind", ""))
        if kind == "identity_login":
            return await self._login(job)
        if kind != "scan":
            return {"status": "skipped", "kind": kind}
        payload = job.get("payload") or {}
        scan_id = str(payload.get("scan_id", ""))
        scan = self.services.scans.get(scan_id)
        if scan is None:
            raise RuntimeError("the scan does not exist")
        context = build_scan_context(scan, self.services.settings)
        orchestrator = build_orchestrator(self.services)
        return await orchestrator.run(context)

    async def _login(self, job: dict[str, Any]) -> dict[str, Any]:
        """Log in as an identity and keep the session.

        The credentials are decrypted here, in the runner: the API
        never decrypts, and the session it produces is stored back on
        the identity, encrypted.
        """
        from .browser.login import record_login, store_session

        payload = job.get("payload") or {}
        identity_id = str(payload.get("identity_id", ""))
        repository = self.services.identities
        identity = repository.get(identity_id)
        if identity is None:
            raise RuntimeError("the identity does not exist")

        secrets = repository.secrets_for(identity_id)
        result = await record_login(
            identity=identity,
            secrets=secrets,
            authorized_hosts=list(payload.get("authorized_hosts", []) or []),
        )
        if result.get("status") == "verified":
            store_session(repository, identity_id, result)
        self.services.audit.record(
            action="identity.login",
            actor="runner",
            target_type="identity",
            target_id=identity_id,
            detail={"status": result.get("status", ""), "reason": result.get("reason", "")},
        )
        return {
            "status": result.get("status", "failed"),
            "reason": result.get("reason", ""),
            "identity_id": identity_id,
        }


class Runner:
    """Claims jobs from the queue and runs them."""

    def __init__(
        self,
        services: Services,
        config: RunnerConfig,
        executor: JobExecutor | None = None,
    ) -> None:
        self.services = services
        self.config = config
        self.executor: JobExecutor = executor or ScanJobExecutor(services)
        self._drained = False
        self._current_job_id = ""

    # ------------------------------------------------------------------
    # Running a job
    # ------------------------------------------------------------------
    async def run_once(self) -> Optional[dict[str, Any]]:
        """Claim one job, run it and record the outcome.

        The runner takes the lock of the target before it runs a job, so
        that only one scan of a host runs at a time.  A job whose target
        is locked by somebody else is put back on the queue: it waits
        for the target instead of competing for it.

        Returns the result of the job, the job document when the job
        failed, or ``None`` when there was nothing to do.
        """
        if self._drained:
            return None
        jobs = self.services.jobs
        job = jobs.claim(
            owner=self.config.owner,
            lease_seconds=self.config.lease_seconds,
            kinds=RUNNER_JOB_KINDS,
        )
        if job is None:
            self.record_heartbeat()
            return None

        job_id = str(job.get("job_id", ""))
        target_key = str((job.get("payload") or {}).get("target_key", "") or "")
        self._current_job_id = job_id
        self.record_heartbeat()
        heartbeat = asyncio.create_task(self._heartbeat_loop(job_id))
        locked = False
        try:
            if target_key:
                locked = self.services.locks.acquire(
                    target_key=target_key,
                    owner=self.config.owner,
                    ttl_seconds=self._lock_ttl_seconds(),
                )
                if not locked:
                    # The target is busy: the job goes back to the queue
                    # and waits for the lock instead of failing.
                    log.info("the target %s is locked; the job %s waits", target_key, job_id)
                    jobs.release(job_id, owner=self.config.owner, delay_seconds=LOCK_RETRY_SECONDS)
                    return None
            result = await self.executor.execute(job)
        except Exception as exc:
            log.warning("job %s failed: %s", job_id, exc)
            jobs.fail(job_id, owner=self.config.owner, error=str(exc), retry=True)
            return job
        else:
            jobs.complete(job_id, owner=self.config.owner, result=result)
            return result
        finally:
            heartbeat.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await heartbeat
            if locked:
                self.services.locks.release(target_key=target_key, owner=self.config.owner)
            self._current_job_id = ""

    def _lock_ttl_seconds(self) -> int:
        """How long the lock of a target is held while a scan runs."""
        lease = int(getattr(self.services.settings, "runner_lease_seconds", 60) or 60)
        return max(1, lease * 5)

    async def _heartbeat_loop(self, job_id: str) -> None:
        """Renew the lease of the job in flight until the runner stops."""
        interval = max(0.01, float(self.config.heartbeat_seconds))
        while True:
            await asyncio.sleep(interval)
            try:
                self.services.jobs.heartbeat(
                    job_id,
                    owner=self.config.owner,
                    lease_seconds=self.config.lease_seconds,
                )
            except Exception:  # pragma: no cover - the heartbeat must not kill the job
                log.exception("the heartbeat of job %s failed", job_id)

    # ------------------------------------------------------------------
    # The runner loop
    # ------------------------------------------------------------------
    async def run_forever(self) -> None:
        """Run jobs until the runner is drained."""
        while not self._drained:
            if self._drain_requested():
                log.info("the runner was asked to drain; it will not claim new jobs")
                self.drain()
            result = await self.run_once()
            if result is None:
                await asyncio.sleep(self.config.poll_seconds)

    def drain(self) -> None:
        """Stop claiming new jobs.  The job in flight is allowed to finish."""
        self._drained = True

    def _drain_requested(self) -> bool:
        """Return ``True`` when an operator asked the runner to drain."""
        document = self.services.db.collection("platform_counters").find_one({"key": DRAIN_COUNTER_KEY})
        return bool(document and document.get("value"))

    # ------------------------------------------------------------------
    # Presence
    # ------------------------------------------------------------------
    def record_heartbeat(self) -> None:
        """Record that this runner is alive and what it is working on."""
        self.services.db.collection("platform_runner_heartbeats").update_one(
            {"runner_id": self.config.owner},
            {
                "$set": {
                    "runner_id": self.config.owner,
                    "last_seen_at": time.time(),
                    "current_job_id": self._current_job_id,
                    "version": 1,
                }
            },
            upsert=True,
        )
