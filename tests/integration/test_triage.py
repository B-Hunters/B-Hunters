"""Triage lives on the issue, not on the finding.

A finding belongs to the scan that found it.  An issue is the durable
thing behind it: it carries the triage state, the observation state and
the history, and it is what the operator works on.

The rule that matters most is the reopen.  An issue the operator marked
fixed, and an issue the platform closed by itself, are both open again
when a later scan sees the problem again — and the reopen is recorded,
because a state that changes silently is a state nobody can trust.
"""

from __future__ import annotations

import uuid

import pytest

pytestmark = pytest.mark.integration


def _scan_id() -> str:
    """A scan of its own: the shared test database keeps every row."""
    return f"s-{uuid.uuid4().hex[:8]}"


def _issue(services, *, fingerprint: str = "fp", target_key: str = "demo.test"):
    scan_id = _scan_id()
    issue, _ = services.issues.upsert_for_finding(
        scan_id=scan_id,
        fingerprint=fingerprint,
        title="Reflected XSS in the search",
        severity="high",
        vuln_class="xss",
    )
    # The issue belongs to the target of its scan.  A scan with no
    # target key of its own falls back to its id, and the observations
    # are applied under that same key.
    return issue, scan_id, issue["target_key"]


def test_a_recurring_finding_reopens_its_issue(services):
    issue, scan_id, target_key = _issue(services)
    services.issues.set_triage(issue["issue_id"], status="fixed")

    services.issues.apply_scan_observations(
        scan_id=scan_id,
        target_key=target_key,
        observed_fingerprints=["fp"],
    )

    refreshed = services.issues.get(issue["issue_id"])
    assert refreshed["triage_status"] == "open"
    assert refreshed["observation_status"] == "observed"


def test_an_issue_the_platform_closed_reopens_too(services):
    issue, scan_id, target_key = _issue(services)
    services.issues.set_triage(issue["issue_id"], status="auto_closed")

    services.issues.apply_scan_observations(
        scan_id=scan_id,
        target_key=target_key,
        observed_fingerprints=["fp"],
    )

    refreshed = services.issues.get(issue["issue_id"])
    assert refreshed["triage_status"] == "open"


def test_a_risk_accepted_issue_is_left_alone(services):
    """The operator said what it is; the platform does not overrule them."""
    issue, scan_id, target_key = _issue(services)
    services.issues.set_triage(issue["issue_id"], status="risk_accepted")

    services.issues.apply_scan_observations(
        scan_id=scan_id,
        target_key=target_key,
        observed_fingerprints=["fp"],
    )

    refreshed = services.issues.get(issue["issue_id"])
    assert refreshed["triage_status"] == "risk_accepted"


def test_the_reopen_is_recorded_in_the_history(services):
    issue, scan_id, target_key = _issue(services)
    services.issues.set_triage(issue["issue_id"], status="fixed")

    services.issues.apply_scan_observations(
        scan_id=scan_id,
        target_key=target_key,
        observed_fingerprints=["fp"],
    )

    events = services.issues.events_for(issue["issue_id"])
    assert any(event["event"] == "reopened" for event in events)


def test_every_triage_change_is_recorded(services):
    issue, _scan, _key = _issue(services)

    services.issues.set_triage(issue["issue_id"], status="in_progress", assignee="me")

    events = services.issues.events_for(issue["issue_id"])
    assert events
    assert events[-1]["event"] == "triaged"
    assert events[-1]["to"] == "in_progress"


def test_an_issue_can_be_marked_a_duplicate_of_another(services):
    issue, _scan, _key = _issue(services, fingerprint="fp-1")
    other, _scan2, _key2 = _issue(services, fingerprint="fp-2")

    services.issues.set_triage(issue["issue_id"], status="duplicate", duplicate_of=other["issue_id"])

    refreshed = services.issues.get(issue["issue_id"])
    assert refreshed["triage_status"] == "duplicate"
    assert refreshed["duplicate_of"] == other["issue_id"]


def test_a_triage_of_an_unknown_issue_is_reported(services):
    with pytest.raises(KeyError):
        services.issues.set_triage("no-such-issue", status="open")


def test_an_invalid_triage_status_is_refused(services):
    issue, _scan, _key = _issue(services)

    with pytest.raises(ValueError):
        services.issues.set_triage(issue["issue_id"], status="not_a_status")
