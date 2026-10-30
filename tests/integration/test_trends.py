"""The triage trend.

The numbers are per issue, not per occurrence: the same problem found
by three scans is one problem, and counting it three times would make a
platform that finds more look worse, not better.

Four numbers answer the question an operator actually asks: how many
issues are open and how bad are they, what is the rate at which the
findings are verified, how long does it take to triage, and are more
problems appearing than being closed.
"""

from __future__ import annotations

import time
import uuid

import pytest

pytestmark = pytest.mark.integration


def _issue(services, *, severity: str = "high"):
    """An issue of its own, on a target of its own."""
    scan_id = f"s-{uuid.uuid4().hex[:8]}"
    issue, _ = services.issues.upsert_for_finding(
        scan_id=scan_id,
        fingerprint=f"fp-{uuid.uuid4().hex[:8]}",
        title="Reflected XSS in the search",
        severity=severity,
        vuln_class="xss",
    )
    # The target of the issue is the key the trend is asked about, so
    # the shared test database does not colour the numbers.
    return issue


def _trends(client, target_key: str, days: int = 30):
    response = client.get(
        "/api/v1/dashboard/trends",
        params={"target_key": target_key, "days": days},
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_the_trend_answers_the_four_questions(client, auth_headers, services):
    issue = _issue(services)

    payload = _trends(client, issue["target_key"])

    assert "open_by_severity" in payload
    assert "new_vs_fixed" in payload
    assert "verified_rate" in payload
    assert "mean_time_to_triage_seconds" in payload


def test_the_open_issues_are_counted_once_each(client, auth_headers, services):
    """One issue seen by three scans is one open issue."""
    issue = _issue(services, severity="high")
    services.issues.apply_scan_observations(
        scan_id="s-other",
        target_key=issue["target_key"],
        observed_fingerprints=[issue["fingerprint"]],
    )

    payload = _trends(client, issue["target_key"])

    high = [row for row in payload["open_by_severity"] if row.get("severity") == "high"]
    assert high
    assert high[0]["count"] == 1


def test_an_issue_that_was_fixed_is_not_open(client, auth_headers, services):
    issue = _issue(services, severity="critical")
    client.post(
        f"/api/v1/issues/{issue['issue_id']}/triage",
        json={"status": "fixed"},
        headers=auth_headers,
    )

    payload = _trends(client, issue["target_key"])

    critical = [row for row in payload["open_by_severity"] if row.get("severity") == "critical"]
    assert not critical


def test_the_new_and_fixed_counts_are_per_week(client, auth_headers, services):
    issue = _issue(services, severity="medium")

    payload = _trends(client, issue["target_key"])

    weeks = payload["new_vs_fixed"]
    assert weeks
    assert "new" in weeks[0]
    assert "fixed" in weeks[0]


def test_the_verified_rate_is_between_zero_and_one(client, auth_headers, services):
    issue = _issue(services)

    payload = _trends(client, issue["target_key"])

    assert 0.0 <= payload["verified_rate"] <= 1.0


def test_the_time_to_triage_is_measured(client, auth_headers, services):
    issue = _issue(services, severity="low")
    client.post(
        f"/api/v1/issues/{issue['issue_id']}/triage",
        json={"status": "in_progress"},
        headers=auth_headers,
    )

    payload = _trends(client, issue["target_key"])

    assert payload["mean_time_to_triage_seconds"] >= 0


def test_the_trend_looks_back_a_number_of_days(client, auth_headers, services):
    issue = _issue(services)

    payload = _trends(client, issue["target_key"], days=7)

    assert payload["days"] == 7


def test_the_trend_needs_a_login(client):
    response = client.get("/api/v1/dashboard/trends")

    assert response.status_code in (401, 403)


def test_the_window_is_bounded(client, auth_headers):
    """A window of a hundred thousand days is refused, not honoured."""
    response = client.get("/api/v1/dashboard/trends", params={"days": 100000})

    assert response.status_code == 422


def test_an_issue_older_than_the_window_is_not_in_it(client, auth_headers, services):
    issue = _issue(services, severity="high")
    services.db.collection("platform_issues").update_one(
        {"issue_id": issue["issue_id"]},
        {"$set": {"created_at": time.time() - 400 * 86400}},
    )

    payload = _trends(client, issue["target_key"], days=30)

    high = [row for row in payload["open_by_severity"] if row.get("severity") == "high"]
    assert not high
