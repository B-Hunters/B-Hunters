"""The schedules: scans that run without a human.

A schedule says how often a scan template runs.  The runner's scheduler
loop claims a due schedule and enqueues the scan, so the scan goes
through the same queue, the same runner and the same lease as a scan an
operator started by hand.

The claim is atomic: ``find_one_and_update`` over the schedules whose
next run has come, which advances the next run in the same operation.
Two runners cannot claim the same schedule, and a runner that dies
mid-claim does not lose the schedule — the claim either happened or it
did not.
"""

from __future__ import annotations

import time
from typing import Any, Optional

from croniter import croniter

#: The collections this repository owns are registered by the platform's
#: database module; the name is repeated here so the repository can be
#: used on its own.
COLLECTION = "platform_schedules"


class ScheduleError(ValueError):
    """A schedule that cannot be run."""


def next_run(cron: str, after: float | None = None) -> float:
    """The next moment a cron expression fires after a timestamp.

    Raises ``ValueError`` for an expression the parser does not accept.
    """
    if not croniter.is_valid(cron):
        raise ValueError(f"'{cron}' is not a valid cron expression")
    base = time.time() if after is None else float(after)
    return float(croniter(cron, base).get_next(float))


class ScheduleRepository:
    """The schedules of a deployment."""

    def __init__(self, db: Any) -> None:
        self._db = db

    @property
    def _col(self):
        return self._db.collection(COLLECTION)

    def create(
        self,
        *,
        name: str,
        template: dict[str, Any],
        cron: str,
        timezone: str = "UTC",
        enabled: bool = True,
    ) -> dict[str, Any]:
        """Create a schedule.

        The cron expression is validated here: a schedule that cannot
        be parsed would otherwise sit in the database until the scheduler
        met it and failed.
        """
        now = time.time()
        document = {
            "schedule_id": f"sched-{int(now * 1000)}-{abs(hash(name)) % 100000}",
            "name": name,
            "template": template or {},
            "cron": cron,
            "timezone": timezone,
            "enabled": bool(enabled),
            "next_run_at": next_run(cron, now),
            "last_run_at": None,
            "last_scan_id": "",
            "created_at": now,
            "updated_at": now,
        }
        self._col.insert_one(document)
        return document

    def get(self, schedule_id: str) -> Optional[dict[str, Any]]:
        """One schedule, or ``None``."""
        return self._col.find_one({"schedule_id": schedule_id})

    def list(self, *, enabled_only: bool = False) -> list[dict[str, Any]]:
        """Every schedule, the enabled ones first."""
        query = {"enabled": True} if enabled_only else {}
        return list(self._col.find(query).sort("next_run_at", 1))

    def update(self, schedule_id: str, changes: dict[str, Any]) -> bool:
        """Change a schedule.  A new cron expression moves its next run."""
        payload = dict(changes or {})
        if "cron" in payload:
            payload["next_run_at"] = next_run(payload["cron"], time.time())
        payload["updated_at"] = time.time()
        result = self._col.update_one({"schedule_id": schedule_id}, {"$set": payload})
        return result.matched_count > 0

    def delete(self, schedule_id: str) -> bool:
        """Remove a schedule."""
        return self._col.delete_one({"schedule_id": schedule_id}).deleted_count > 0

    def claim_due(self, now: float | None = None) -> Optional[dict[str, Any]]:
        """Claim the schedule whose next run has come.

        The claim is a compare-and-swap: the schedule is only advanced
        when its ``next_run_at`` is still the one that was read, so two
        runners racing for the same schedule produce exactly one claim
        and the other one tries the next schedule.
        """
        moment = time.time() if now is None else float(now)
        for _ in range(10):
            candidate = self._col.find_one(
                {"enabled": True, "next_run_at": {"$lte": moment}},
                sort=[("next_run_at", 1)],
            )
            if candidate is None:
                return None
            following = next_run(candidate["cron"], moment)
            result = self._col.update_one(
                {
                    "schedule_id": candidate["schedule_id"],
                    "next_run_at": candidate["next_run_at"],
                    "enabled": True,
                },
                {
                    "$set": {
                        "next_run_at": following,
                        "claimed_at": moment,
                        "updated_at": moment,
                    }
                },
            )
            if result.modified_count == 1:
                return {**candidate, "next_run_at": following}
        return None

    def record_run(self, schedule_id: str, scan_id: str) -> bool:
        """Record that a schedule produced a scan."""
        result = self._col.update_one(
            {"schedule_id": schedule_id},
            {"$set": {"last_run_at": time.time(), "last_scan_id": scan_id, "updated_at": time.time()}},
        )
        return result.matched_count > 0
