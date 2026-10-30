"""The comments on an issue.

A finding is evidence.  A comment is what the operator says about it:
why it matters, why it was dismissed, what is being done.  There is one
user, and a comment is still editable only by its author — the guarantee
is worth having because it is what makes the record trustworthy.
"""

from __future__ import annotations

import uuid

import pytest

pytestmark = pytest.mark.integration


def _issue(services):
    scan_id = f"s-{uuid.uuid4().hex[:8]}"
    issue, _ = services.issues.upsert_for_finding(
        scan_id=scan_id,
        fingerprint="fp",
        title="Reflected XSS in the search",
        severity="high",
        vuln_class="xss",
    )
    return issue


def test_a_comment_is_stored_on_its_issue(services):
    issue = _issue(services)

    comment = services.comments.add(
        issue_id=issue["issue_id"],
        scan_id="",
        finding_id="",
        author="me",
        body="The search endpoint is public; this is reachable without a session.",
    )

    assert comment["issue_id"] == issue["issue_id"]
    assert comment["author"] == "me"
    assert comment["body"].startswith("The search endpoint")


def test_the_comments_of_an_issue_are_listed_oldest_first(services):
    issue = _issue(services)
    services.comments.add(issue_id=issue["issue_id"], scan_id="", finding_id="", author="me", body="first")
    services.comments.add(issue_id=issue["issue_id"], scan_id="", finding_id="", author="me", body="second")

    comments = services.comments.list_for_issue(issue["issue_id"])

    assert [comment["body"] for comment in comments] == ["first", "second"]


def test_a_comment_of_another_issue_is_not_listed(services):
    issue = _issue(services)
    other = _issue(services)
    services.comments.add(issue_id=issue["issue_id"], scan_id="", finding_id="", author="me", body="mine")

    assert services.comments.list_for_issue(other["issue_id"]) == []


def test_the_author_may_edit_their_comment(services):
    issue = _issue(services)
    comment = services.comments.add(
        issue_id=issue["issue_id"], scan_id="", finding_id="", author="me", body="first"
    )

    edited = services.comments.edit(comment["comment_id"], author="me", body="second")

    assert edited is True
    stored = services.comments.get(comment["comment_id"])
    assert stored["body"] == "second"


def test_nobody_else_may_edit_a_comment(services):
    issue = _issue(services)
    comment = services.comments.add(
        issue_id=issue["issue_id"], scan_id="", finding_id="", author="me", body="first"
    )

    assert services.comments.edit(comment["comment_id"], author="someone-else", body="hacked") is False
    assert services.comments.get(comment["comment_id"])["body"] == "first"


def test_a_comment_can_be_deleted_by_its_author(services):
    issue = _issue(services)
    comment = services.comments.add(
        issue_id=issue["issue_id"], scan_id="", finding_id="", author="me", body="first"
    )

    assert services.comments.delete(comment["comment_id"], author="me") is True
    assert services.comments.get(comment["comment_id"]) is None


def test_a_comment_cannot_be_deleted_by_anybody_else(services):
    issue = _issue(services)
    comment = services.comments.add(
        issue_id=issue["issue_id"], scan_id="", finding_id="", author="me", body="first"
    )

    assert services.comments.delete(comment["comment_id"], author="someone-else") is False
    assert services.comments.get(comment["comment_id"]) is not None


def test_an_empty_comment_is_refused(services):
    issue = _issue(services)

    with pytest.raises(ValueError):
        services.comments.add(issue_id=issue["issue_id"], scan_id="", finding_id="", author="me", body="   ")
