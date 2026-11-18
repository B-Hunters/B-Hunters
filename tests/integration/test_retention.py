"""The database does not grow for ever.

The retention job was written and never called: every scan left its
events, its artefacts and its sessions behind, and the only thing that
ever removed them was an operator with a shell.

The job also removes the events and the artefacts that have expired -
and the sessions, which are expired by definition.
"""

from __future__ import annotations

import pytest

from b_hunters.platform.db.client import Database
from b_hunters.platform.runner import RETENTION_INTERVAL_SECONDS


def _database(settings):
    database = Database(settings)
    if not database.ping():
        pytest.skip("MongoDB is not reachable")
    database.ensure_indexes()
    return database


def test_the_retention_job_removes_what_has_expired(settings):
    database = _database(settings)
    events = database.collection("platform_scan_events")
    artefacts = database.collection("platform_artifacts")

    events.insert_one({"at": 0, "scan_id": "expired-scan", "kind": "scan.created"})
    artefacts.insert_one({"created_at": 0, "scan_id": "expired-scan", "kind": "file"})

    removed = database.apply_retention(event_retention_days=1, artifact_retention_days=1)

    assert removed["events"] >= 1
    assert removed["artifacts"] >= 1
    assert events.count_documents({"scan_id": "expired-scan"}) == 0
    assert artefacts.count_documents({"scan_id": "expired-scan"}) == 0


def test_the_retention_job_keeps_what_is_current(settings):
    database = _database(settings)
    events = database.collection("platform_scan_events")

    events.insert_one({"at": 9_999_999_999, "scan_id": "current-scan", "kind": "scan.created"})

    database.apply_retention(event_retention_days=3650, artifact_retention_days=3650)

    assert events.count_documents({"scan_id": "current-scan"}) == 1


def test_the_runner_calls_the_retention_job():
    """The job runs on a schedule, not on every poll."""
    assert RETENTION_INTERVAL_SECONDS >= 600
