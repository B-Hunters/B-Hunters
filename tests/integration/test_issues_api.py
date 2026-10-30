"""The triage API.

The operator works on issues, not on findings: the triage state is set
once and it holds for every scan that sees the issue again.
"""

from __future__ import annotations

import uuid

import pytest

pytestmark = pytest.mark.integration


def _issue(services) -> dict:
    scan_id = f"s-{uuid.uuid4().hex[:8]}"
    issue, _ = services.issues.upsert_for_finding(
        scan_id=scan_id,
        fingerprint=f"fp-{uuid.uuid4().hex[:6]}",
        title="Reflected XSS in the search",
        severity="high",
        vuln_class="xss",
    )
    return issue


def test_the_issues_are_listed(client, auth_headers, services):
    issue = _issue(services)

    response = client.get("/api/v1/issues")

    assert response.status_code == 200, response.text
    identifiers = {row["issue_id"] for row in response.json()["issues"]}
    assert issue["issue_id"] in identifiers


def test_the_issues_can_be_filtered_by_their_triage_state(client, auth_headers, services):
    issue = _issue(services)
    client.post(
        f"/api/v1/issues/{issue['issue_id']}/triage",
        json={"status": "risk_accepted"},
        headers=auth_headers,
    )

    response = client.get("/api/v1/issues", params={"triage_status": "risk_accepted"})

    assert response.status_code == 200, response.text
    identifiers = {row["issue_id"] for row in response.json()["issues"]}
    assert issue["issue_id"] in identifiers


def test_the_triage_of_an_issue_is_set(client, auth_headers, services):
    issue = _issue(services)

    response = client.post(
        f"/api/v1/issues/{issue['issue_id']}/triage",
        json={"status": "in_progress", "assignee": "me"},
        headers=auth_headers,
    )

    assert response.status_code == 200, response.text
    assert response.json()["triage_status"] == "in_progress"
    assert response.json()["assignee"] == "me"


def test_an_issue_can_be_marked_a_duplicate(client, auth_headers, services):
    issue = _issue(services)
    other = _issue(services)

    response = client.post(
        f"/api/v1/issues/{issue['issue_id']}/triage",
        json={"status": "duplicate", "duplicate_of": other["issue_id"]},
        headers=auth_headers,
    )

    assert response.status_code == 200, response.text
    assert response.json()["duplicate_of"] == other["issue_id"]


def test_the_triage_of_an_unknown_issue_is_a_404(client, auth_headers):
    response = client.post(
        "/api/v1/issues/no-such-issue/triage",
        json={"status": "open"},
        headers=auth_headers,
    )

    assert response.status_code == 404


def test_an_invalid_triage_state_is_a_400(client, auth_headers, services):
    issue = _issue(services)

    response = client.post(
        f"/api/v1/issues/{issue['issue_id']}/triage",
        json={"status": "not_a_state"},
        headers=auth_headers,
    )

    assert response.status_code == 400


def test_a_selection_of_issues_is_triaged_at_once(client, auth_headers, services):
    first = _issue(services)
    second = _issue(services)

    response = client.post(
        "/api/v1/issues/bulk",
        json={"issue_ids": [first["issue_id"], second["issue_id"]], "status": "in_progress"},
        headers=auth_headers,
    )

    assert response.status_code == 200, response.text
    assert response.json()["count"] == 2
    assert services.issues.get(first["issue_id"])["triage_status"] == "in_progress"
    assert services.issues.get(second["issue_id"])["triage_status"] == "in_progress"


def test_a_bulk_triage_without_a_selection_is_a_400(client, auth_headers):
    response = client.post(
        "/api/v1/issues/bulk",
        json={"issue_ids": [], "status": "open"},
        headers=auth_headers,
    )

    assert response.status_code == 400


def test_the_history_of_an_issue_lists_its_scans_and_its_changes(client, auth_headers, services):
    issue = _issue(services)
    client.post(
        f"/api/v1/issues/{issue['issue_id']}/triage",
        json={"status": "fixed"},
        headers=auth_headers,
    )

    response = client.get(f"/api/v1/issues/{issue['issue_id']}/history")

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["scans"]
    assert any(event["event"] == "triaged" for event in payload["events"])


def test_a_comment_is_added_to_an_issue(client, auth_headers, services):
    issue = _issue(services)

    response = client.post(
        f"/api/v1/issues/{issue['issue_id']}/comments",
        json={"body": "The endpoint is public; this needs no session."},
        headers=auth_headers,
    )

    assert response.status_code == 201, response.text
    assert response.json()["body"].startswith("The endpoint is public")


def test_the_comments_of_an_issue_are_listed(client, auth_headers, services):
    issue = _issue(services)
    client.post(
        f"/api/v1/issues/{issue['issue_id']}/comments",
        json={"body": "first"},
        headers=auth_headers,
    )
    client.post(
        f"/api/v1/issues/{issue['issue_id']}/comments",
        json={"body": "second"},
        headers=auth_headers,
    )

    response = client.get(f"/api/v1/issues/{issue['issue_id']}/comments")

    assert response.status_code == 200, response.text
    assert [comment["body"] for comment in response.json()["comments"]] == ["first", "second"]


def test_an_empty_comment_is_a_400(client, auth_headers, services):
    issue = _issue(services)

    response = client.post(
        f"/api/v1/issues/{issue['issue_id']}/comments",
        json={"body": "   "},
        headers=auth_headers,
    )

    assert response.status_code == 400


def test_a_comment_on_an_unknown_issue_is_a_404(client, auth_headers):
    response = client.post(
        "/api/v1/issues/no-such-issue/comments",
        json={"body": "hello"},
        headers=auth_headers,
    )

    assert response.status_code == 404


def test_a_triage_without_a_csrf_token_is_refused(client, services):
    issue = _issue(services)

    response = client.post(
        f"/api/v1/issues/{issue['issue_id']}/triage",
        json={"status": "open"},
    )

    assert response.status_code in (401, 403)
