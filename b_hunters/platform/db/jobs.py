"""The durable job queue and the per-target locks.

The API does not run scans in its own process: it writes a job document
and a separate runner process picks it up.  A job therefore survives a
restart of the API, and the runner that owns a job can be killed without
losing the work: the job carries a *lease*, and a job whose lease
expired is claimed again by whoever notices it first.

The claim is a single atomic ``find_one_and_update``, so two runners
never work on the same job.

The second half of this module is the target lock.  Two scans of the same
host compete for the same scanner worker containers, so only one scan per
target may run at a time.  The lock is a document with an expiry: a
runner that dies without releasing it does not block the target forever.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import Any, Optional

from pymongo import ASCENDING, DESCENDING, ReturnDocument
from pymongo.errors import DuplicateKeyError

from .client import Database
from .repositories import new_id, utcnow

log = logging.getLogger(__name__)

#: The states a job can be in.
JOB_STATUSES = (
    "queued",
    "leased",
    "running",
    "succeeded",
    "failed",
    "cancelled",
)

#: The states a job can be in while it still matters to an operator.
LIVE_JOB_STATUSES = ("queued", "leased", "running")

#: The states that mean the job is over.
FINISHED_JOB_STATUSES = ("succeeded", "failed", "cancelled")

#: How often the claim loop tries again when a claimed job was over its
#: attempt limit (the job is marked failed and another one is claimed).
MAX_CLAIM_ATTEMPTS = 10


class JobRepository:
    """A durable queue of jobs with leases."""

    def __init__(self, db: Database) -> None:
        self._db = db

    @property
    def _col(self):
        return self._db.collection("platform_jobs")

    # ------------------------------------------------------------------
    # Queue
    # ------------------------------------------------------------------
    def enqueue(
        self,
        *,
        kind: str,
        payload: dict[str, Any],
        priority: int = 0,
        available_at: float | None = None,
        max_attempts: int = 3,
    ) -> dict[str, Any]:
        """Put a job on the queue and return the stored document."""
        now = utcnow()
        document: dict[str, Any] = {
            "job_id": new_id(),
            "kind": kind,
            "status": "queued",
            "priority": int(priority),
            "available_at": float(available_at) if available_at is not None else now,
            "lease_owner": "",
            "lease_expires_at": 0.0,
            "heartbeat_at": None,
            "attempts": 0,
            "max_attempts": int(max_attempts),
            "payload": dict(payload or {}),
            "result": None,
            "error": "",
            "created_at": now,
            "updated_at": now,
        }
        self._col.insert_one(document)
        return document

    def claim(
        self,
        *,
        owner: str,
        lease_seconds: int = 60,
        kinds: Sequence[str] = (),
    ) -> Optional[dict[str, Any]]:
        """Claim the next job for ``owner`` and lease it.

        A job is claimable when it is queued and due, or when it was
        leased by a runner that died (its lease expired).  The claim is
        atomic: two runners never get the same job.
        """
        now = utcnow()
        query: dict[str, Any] = {
            "$or": [
                {"status": "queued", "available_at": {"$lte": now}},
                {"status": {"$in": ["leased", "running"]}, "lease_expires_at": {"$lte": now}},
            ]
        }
        if kinds:
            query["kind"] = {"$in": list(kinds)}

        for _ in range(MAX_CLAIM_ATTEMPTS):
            document = self._col.find_one_and_update(
                query,
                {
                    "$set": {
                        "status": "leased",
                        "lease_owner": owner,
                        "lease_expires_at": now + lease_seconds,
                        "heartbeat_at": now,
                        "updated_at": now,
                    },
                    "$inc": {"attempts": 1},
                },
                sort=[("priority", DESCENDING), ("created_at", ASCENDING)],
                return_document=ReturnDocument.AFTER,
            )
            if document is None:
                return None
            if int(document.get("attempts", 0)) > int(document.get("max_attempts", 3)):
                # The job is over its attempt limit: it is not worth
                # running again, so it is closed and another job is
                # claimed instead.
                self._col.update_one(
                    {"job_id": document["job_id"]},
                    {
                        "$set": {
                            "status": "failed",
                            "error": "the job exceeded its attempt limit",
                            "finished_at": utcnow(),
                            "updated_at": utcnow(),
                        }
                    },
                )
                continue
            return document
        return None

    def heartbeat(self, job_id: str, *, owner: str, lease_seconds: int = 60) -> bool:
        """Renew the lease of a job.  Only its owner may do so."""
        now = utcnow()
        result = self._col.update_one(
            {"job_id": job_id, "lease_owner": owner},
            {
                "$set": {
                    "heartbeat_at": now,
                    "lease_expires_at": now + lease_seconds,
                    "updated_at": now,
                }
            },
        )
        return result.matched_count > 0

    def complete(
        self,
        job_id: str,
        *,
        owner: str,
        result: dict[str, Any] | None = None,
    ) -> bool:
        """Mark a job as done.  Only its owner may do so."""
        now = utcnow()
        updated = self._col.update_one(
            {"job_id": job_id, "lease_owner": owner},
            {
                "$set": {
                    "status": "succeeded",
                    "result": dict(result or {}),
                    "finished_at": now,
                    "updated_at": now,
                }
            },
        )
        return updated.matched_count > 0

    def fail(self, job_id: str, *, owner: str, error: str, retry: bool = True) -> bool:
        """Record a failure.  The job is queued again while it has attempts left."""
        document = self._col.find_one({"job_id": job_id, "lease_owner": owner})
        if document is None:
            return False
        now = utcnow()
        attempts = int(document.get("attempts", 0))
        max_attempts = int(document.get("max_attempts", 3))
        if retry and attempts < max_attempts:
            update = {
                "$set": {
                    "status": "queued",
                    "lease_owner": "",
                    "lease_expires_at": 0.0,
                    "available_at": now,
                    "error": error,
                    "updated_at": now,
                }
            }
        else:
            update = {
                "$set": {
                    "status": "failed",
                    "error": error,
                    "finished_at": now,
                    "updated_at": now,
                }
            }
        updated = self._col.update_one({"job_id": job_id, "lease_owner": owner}, update)
        return updated.matched_count > 0

    def release(self, job_id: str, *, owner: str, delay_seconds: float = 0.0) -> bool:
        """Give a claimed job back to the queue."""
        now = utcnow()
        updated = self._col.update_one(
            {"job_id": job_id, "lease_owner": owner},
            {
                "$set": {
                    "status": "queued",
                    "lease_owner": "",
                    "lease_expires_at": 0.0,
                    "available_at": now + delay_seconds,
                    "updated_at": now,
                }
            },
        )
        return updated.matched_count > 0

    def cancel(self, job_id: str) -> bool:
        """Cancel a job that has not finished yet."""
        now = utcnow()
        updated = self._col.update_one(
            {"job_id": job_id, "status": {"$nin": list(FINISHED_JOB_STATUSES)}},
            {
                "$set": {
                    "status": "cancelled",
                    "finished_at": now,
                    "updated_at": now,
                }
            },
        )
        return updated.matched_count > 0

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------
    def get(self, job_id: str) -> Optional[dict[str, Any]]:
        """Return one job document."""
        return self._col.find_one({"job_id": job_id})

    def find_live(self, scan_id: str) -> Optional[dict[str, Any]]:
        """Return the queued, leased or running job of a scan."""
        return self._col.find_one(
            {"payload.scan_id": scan_id, "status": {"$in": list(LIVE_JOB_STATUSES)}},
            sort=[("created_at", DESCENDING)],
        )

    def list(self, *, status: str = "", kind: str = "", limit: int = 50) -> list[dict[str, Any]]:
        """List the jobs, newest first."""
        query: dict[str, Any] = {}
        if status:
            query["status"] = status
        if kind:
            query["kind"] = kind
        return list(self._col.find(query).sort("created_at", DESCENDING).limit(limit))


class TargetLockRepository:
    """One scan per target at a time.

    The scanner workers are a scarce resource: two scans of the same
    host would compete for the same containers.  The lock is a document
    with an expiry, so a runner that dies without releasing it does not
    block the target forever.
    """

    def __init__(self, db: Database) -> None:
        self._db = db

    @property
    def _col(self):
        return self._db.collection("platform_target_locks")

    def acquire(self, *, target_key: str, owner: str, ttl_seconds: int = 900) -> bool:
        """Take the lock of a target.  Returns ``False`` when it is held."""
        now = utcnow()
        try:
            self._col.find_one_and_update(
                {
                    "target_key": target_key,
                    "$or": [{"expires_at": {"$lte": now}}, {"owner": owner}],
                },
                {
                    "$set": {
                        "owner": owner,
                        "expires_at": now + ttl_seconds,
                        "acquired_at": now,
                    },
                    "$setOnInsert": {"target_key": target_key, "job_id": ""},
                },
                upsert=True,
                return_document=ReturnDocument.AFTER,
            )
            return True
        except DuplicateKeyError:
            # The unique index on ``target_key`` refused the insert: the
            # target is locked by somebody else.
            return False

    def release(self, *, target_key: str, owner: str) -> bool:
        """Give the lock back.  Only the holder may do so."""
        result = self._col.delete_one({"target_key": target_key, "owner": owner})
        return result.deleted_count > 0

    def holder(self, target_key: str) -> Optional[dict[str, Any]]:
        """Return the lock document of a target, or ``None`` when it is free."""
        document = self._col.find_one({"target_key": target_key})
        if document is None:
            return None
        if float(document.get("expires_at", 0)) <= utcnow():
            return None
        return document
