"""The schedules: a scan that runs without a human."""

from __future__ import annotations

import time

import pytest

from b_hunters.platform.schedules import ScheduleRepository, next_run


@pytest.fixture
def repo(database):
    database.collection("platform_schedules").delete_many({})
    return ScheduleRepository(database)


def test_a_schedule_is_created_with_its_next_run(repo):
    schedule = repo.create(name="nightly", template={"targets": {}}, cron="0 3 * * *")
    assert schedule["name"] == "nightly"
    assert schedule["enabled"] is True
    assert schedule["next_run_at"] > time.time()


def test_an_invalid_cron_expression_is_refused(repo):
    with pytest.raises(ValueError):
        repo.create(name="bad", template={}, cron="not a cron expression")


def test_a_due_schedule_is_claimed_exactly_once(repo):
    repo.create(name="nightly", template={}, cron="0 3 * * *")
    first = repo.claim_due(now=time.time() + 86400)
    second = repo.claim_due(now=time.time() + 86400)
    assert first is not None
    assert second is None


def test_a_claim_advances_the_next_run(repo):
    repo.create(name="nightly", template={}, cron="0 3 * * *")
    claimed = repo.claim_due(now=time.time() + 86400)
    assert claimed["next_run_at"] > time.time() + 86400


def test_a_disabled_schedule_is_not_claimed(repo):
    repo.create(name="nightly", template={}, cron="0 3 * * *", enabled=False)
    assert repo.claim_due(now=time.time() + 86400) is None


def test_a_schedule_that_is_not_due_is_not_claimed(repo):
    repo.create(name="nightly", template={}, cron="0 3 * * *")
    assert repo.claim_due(now=time.time() - 3600) is None


def test_a_run_is_recorded(repo):
    schedule = repo.create(name="nightly", template={}, cron="0 3 * * *")
    assert repo.record_run(schedule["schedule_id"], "scan-1")
    stored = repo.get(schedule["schedule_id"])
    assert stored["last_scan_id"] == "scan-1"
    assert stored["last_run_at"] > 0


def test_a_schedule_can_be_changed_and_removed(repo):
    schedule = repo.create(name="nightly", template={}, cron="0 3 * * *")
    assert repo.update(schedule["schedule_id"], {"cron": "0 4 * * *", "enabled": False})
    stored = repo.get(schedule["schedule_id"])
    assert stored["cron"] == "0 4 * * *"
    assert stored["enabled"] is False
    assert repo.delete(schedule["schedule_id"])
    assert repo.get(schedule["schedule_id"]) is None


def test_the_next_run_of_an_expression():
    assert next_run("0 3 * * *", 0) == 3 * 3600
    assert next_run("*/15 * * * *", 0) == 900
