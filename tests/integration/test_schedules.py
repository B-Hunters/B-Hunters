"""The schedules.

A schedule is a scan that happens on its own.  The claim has to be
exact: two runners that both find a due schedule produce one scan
between them, not two.
"""

from __future__ import annotations

import time

import pytest

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _only_this_test_s_schedules(services):
    services.db.collection("platform_schedules").delete_many({})
    yield
    services.db.collection("platform_schedules").delete_many({})


def _template() -> dict:
    return {
        "name": "the nightly scan",
        "targets": {"urls": ["https://demo.test/"], "authorized_hosts": ["demo.test"]},
        "profile": "standard",
        "test_environment": True,
    }


def test_a_schedule_is_stored_with_its_next_run(services):
    schedule = services.schedules.create(name="the nightly scan", template=_template(), cron="0 3 * * *")

    assert schedule["schedule_id"]
    assert schedule["enabled"] is True
    assert schedule["next_run_at"] > time.time()


def test_a_cron_expression_that_cannot_be_parsed_is_refused(services):
    with pytest.raises(ValueError):
        services.schedules.create(name="the nightly scan", template=_template(), cron="not a cron")


def test_a_due_schedule_is_claimed_exactly_once(services):
    services.schedules.create(name="the nightly scan", template=_template(), cron="0 3 * * *")

    first = services.schedules.claim_due(now=time.time() + 86400)
    second = services.schedules.claim_due(now=time.time() + 86400)

    assert first is not None
    assert second is None


def test_a_schedule_that_is_not_due_is_not_claimed(services):
    services.schedules.create(name="the nightly scan", template=_template(), cron="0 3 * * *")

    assert services.schedules.claim_due(now=time.time()) is None


def test_a_disabled_schedule_is_not_claimed(services):
    schedule = services.schedules.create(
        name="the nightly scan", template=_template(), cron="0 3 * * *", enabled=False
    )

    assert services.schedules.claim_due(now=time.time() + 86400) is None
    assert schedule["enabled"] is False


def test_the_runner_turns_a_due_schedule_into_a_scan(services):
    from b_hunters.platform.runner import Runner, RunnerConfig

    schedule = services.schedules.create(name="the nightly scan", template=_template(), cron="0 3 * * *")
    # The schedule is due now.
    services.schedules.update(schedule["schedule_id"], {"cron": "* * * * *"})
    services.db.collection("platform_schedules").update_one(
        {"schedule_id": schedule["schedule_id"]},
        {"$set": {"next_run_at": time.time() - 10}},
    )

    runner = Runner(services, RunnerConfig(concurrency=1))
    claimed = runner.claim_due_schedules()

    assert claimed
    scan_id = claimed[0]["scan_id"]
    scan = services.scans.get(scan_id)
    assert scan is not None
    assert scan.status == "queued"
    assert services.schedules.get(schedule["schedule_id"])["last_scan_id"] == scan_id


def test_a_scheduled_scan_is_comparable_with_a_requested_one(services):
    """A scheduled scan asks the same question as a requested one.

    The comparison key is what says whether two scans may be compared,
    so two scans of the same target with the same template have to
    produce the same one.
    """
    from b_hunters.platform.scan_factory import create_scan_from_template

    first = create_scan_from_template(services, template=_template(), name="the nightly scan")
    second = create_scan_from_template(services, template=_template(), name="the nightly scan")

    assert first.comparison_key
    assert first.comparison_key == second.comparison_key
    assert first.target_key == second.target_key


def test_a_scheduled_scan_of_another_target_is_not_comparable(services):
    from b_hunters.platform.scan_factory import create_scan_from_template

    template = _template()
    template["targets"] = {
        "urls": ["https://other.test/"],
        "authorized_hosts": ["other.test"],
    }

    first = create_scan_from_template(services, template=_template(), name="the nightly scan")
    second = create_scan_from_template(services, template=template, name="the nightly scan")

    assert first.comparison_key != second.comparison_key


def test_the_schedules_are_in_the_api(client, auth_headers, services):
    services.schedules.create(name="the nightly scan", template=_template(), cron="0 3 * * *")

    response = client.get("/api/v1/schedules")

    assert response.status_code == 200, response.text
    assert response.json()["count"] == 1


def test_a_schedule_is_created_through_the_api(client, auth_headers):
    response = client.post(
        "/api/v1/schedules",
        json={
            "name": "the nightly scan",
            "template": _template(),
            "cron": "0 3 * * *",
        },
        headers=auth_headers,
    )

    assert response.status_code == 201, response.text
    assert response.json()["cron"] == "0 3 * * *"


def test_a_schedule_without_a_cron_expression_is_refused(client, auth_headers):
    response = client.post(
        "/api/v1/schedules",
        json={"name": "the nightly scan", "template": _template()},
        headers=auth_headers,
    )

    assert response.status_code == 400


def test_a_schedule_can_be_run_now(client, auth_headers, services):
    created = client.post(
        "/api/v1/schedules",
        json={"name": "the nightly scan", "template": _template(), "cron": "0 3 * * *"},
        headers=auth_headers,
    ).json()

    response = client.post(f"/api/v1/schedules/{created['schedule_id']}/run", headers=auth_headers)

    assert response.status_code == 202, response.text
    scan_id = response.json()["scan_id"]
    assert services.scans.get(scan_id) is not None


def test_a_schedule_is_deleted_through_the_api(client, auth_headers, services):
    schedule = services.schedules.create(name="the nightly scan", template=_template(), cron="0 3 * * *")

    response = client.delete(f"/api/v1/schedules/{schedule['schedule_id']}", headers=auth_headers)

    assert response.status_code == 200, response.text
    assert services.schedules.get(schedule["schedule_id"]) is None
