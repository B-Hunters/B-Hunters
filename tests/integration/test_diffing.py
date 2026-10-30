"""The difference between two scans of the same target."""

from __future__ import annotations

import pytest

from b_hunters.platform.diffing import compare, comparison_key, is_comparable

pytestmark = pytest.mark.integration


def _scan(**overrides):
    scan = {
        "scan_id": "s1",
        "name": "scan",
        "status": "completed",
        "phase": "completed",
        "definition": {
            "targets": ["https://demo.test/"],
            "profile": {
                "name": "standard",
                "scanners": ["nuclei", "katana"],
                "agent_roles": ["recon"],
            },
            "identity_ids": [],
        },
        "scope": {"authorized_hosts": ["demo.test"], "excluded_paths": []},
    }
    scan.update(overrides)
    return scan


def _issue(fingerprint: str, **overrides):
    issue = {
        "issue_id": f"i-{fingerprint}",
        "fingerprint": fingerprint,
        "title": "Something",
        "severity": "medium",
        "vuln_class": "xss",
        "triage_status": "open",
        "observation_status": "observed",
    }
    issue.update(overrides)
    return issue


def test_two_scans_of_the_same_question_have_the_same_key():
    assert comparison_key(_scan()) == comparison_key(_scan(scan_id="s2"))


def test_a_scan_with_another_scanner_is_another_question():
    other = _scan()
    other["definition"]["profile"]["scanners"] = ["nuclei"]
    assert comparison_key(_scan()) != comparison_key(other)


def test_a_scan_with_another_scope_is_another_question():
    other = _scan()
    other["scope"]["authorized_hosts"] = ["other.test"]
    assert comparison_key(_scan()) != comparison_key(other)


def test_a_scan_that_did_not_finish_is_not_comparable():
    comparable, reason = is_comparable(_scan(phase="agents"), _scan())
    assert comparable is False
    assert reason


def test_a_scan_without_an_earlier_one_is_not_comparable():
    comparable, reason = is_comparable(_scan(), None)
    assert comparable is False
    assert "no earlier scan" in reason


def test_the_new_findings_are_the_ones_the_earlier_scan_did_not_have():
    result = compare(
        current=_scan(),
        baseline=_scan(scan_id="s0"),
        issues_current=[_issue("a"), _issue("b")],
        issues_baseline=[_issue("b")],
        comparable=True,
        reason="",
    )
    assert [issue["fingerprint"] for issue in result["new"]] == ["a"]
    assert [issue["fingerprint"] for issue in result["persistent"]] == ["b"]
    assert result["counts"]["new"] == 1


def test_a_finding_that_was_not_seen_again_is_not_observed():
    result = compare(
        current=_scan(),
        baseline=_scan(scan_id="s0"),
        issues_current=[],
        issues_baseline=[_issue("a")],
        comparable=True,
        reason="",
    )
    assert [issue["fingerprint"] for issue in result["not_observed"]] == ["a"]
    # The absence of a finding is not a fix: the group says "not
    # observed", and the issue is closed by the auto-close rule.
    assert result["counts"]["new"] == 0


def test_a_finding_that_came_back_is_reopened():
    result = compare(
        current=_scan(),
        baseline=_scan(scan_id="s0"),
        issues_current=[_issue("a")],
        issues_baseline=[_issue("a", observation_status="auto_closed")],
        comparable=True,
        reason="",
    )
    assert [issue["fingerprint"] for issue in result["reopened"]] == ["a"]


def test_scans_that_are_not_comparable_claim_nothing():
    result = compare(
        current=_scan(),
        baseline=_scan(scan_id="s0"),
        issues_current=[_issue("a")],
        issues_baseline=[],
        comparable=False,
        reason="the two scans did not ask the same question",
    )
    assert result["comparable"] is False
    assert result["new"] == []
    assert result["not_observed"] == []
    assert result["reason"] == "the two scans did not ask the same question"
