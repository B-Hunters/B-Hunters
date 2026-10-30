"""The difference between two scans of the same target.

Two scans of the same target are comparable when they asked the same
question: the same scope, the same profile, the same scanners, the same
roles and the same identity.  A scan that covered less, or ran with
other tools, did not look at the same surface, and the difference
between them is not a difference in the target.

A finding is the same finding across scans when it has the same
fingerprint: the same vulnerability class, on the same host, at the same
path, with the same parameter.  The fingerprint is deliberately blind to
the detector, so two tools that find the same thing produce one issue
rather than two.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from typing import Any, Optional


def comparison_key(scan: dict[str, Any]) -> str:
    """The hash of what a scan asked.

    Two scans with the same key asked the same question, and the
    difference between them is a difference in the target.
    """
    definition = scan.get("definition") or {}
    scope = scan.get("scope") or {}
    profile = definition.get("profile") or {}
    material = "|".join(
        [
            _target_material(scan),
            ",".join(sorted(str(host) for host in scope.get("authorized_hosts", []))),
            ",".join(sorted(str(path) for path in scope.get("excluded_paths", []))),
            str(profile.get("name", "standard")),
            ",".join(sorted(str(name) for name in profile.get("scanners", []))),
            ",".join(sorted(str(name) for name in profile.get("agent_roles", []))),
            ",".join(sorted(str(name) for name in definition.get("identity_ids", []))),
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def _target_material(scan: dict[str, Any]) -> str:
    """The target of a scan, as one string."""
    definition = scan.get("definition") or {}
    return ",".join(sorted(str(url) for url in definition.get("targets", [])))


def is_comparable(current: dict[str, Any], baseline: dict[str, Any]) -> tuple[bool, str]:
    """Whether two scans may be compared, and why not when they may not."""
    if not baseline:
        return False, "there is no earlier scan of this target"
    if comparison_key(current) != comparison_key(baseline):
        return False, "the two scans did not ask the same question"
    if str(current.get("phase", "")) != "completed" or str(baseline.get("phase", "")) != "completed":
        return False, "one of the scans did not finish"
    return True, ""


def compare(
    *,
    current: dict[str, Any],
    baseline: Optional[dict[str, Any]],
    issues_current: Sequence[dict[str, Any]],
    issues_baseline: Sequence[dict[str, Any]],
    comparable: bool,
    reason: str,
) -> dict[str, Any]:
    """Compare two scans.

    The groups are what an operator asks about after a scan: what is
    new, what is still there, what was seen before and is not seen
    now, and what came back after having gone.
    """
    if not comparable:
        return {
            "comparable": False,
            "reason": reason,
            "new": [],
            "persistent": [],
            "not_observed": [],
            "reopened": [],
            "counts": {},
        }

    current_by_fingerprint = {issue.get("fingerprint", ""): issue for issue in issues_current}
    baseline_by_fingerprint = {issue.get("fingerprint", ""): issue for issue in issues_baseline}

    new = [
        _view(issue)
        for fingerprint, issue in current_by_fingerprint.items()
        if fingerprint not in baseline_by_fingerprint
    ]
    persistent = [
        _view(issue)
        for fingerprint, issue in current_by_fingerprint.items()
        if fingerprint in baseline_by_fingerprint
    ]
    not_observed = [
        _view(issue)
        for fingerprint, issue in baseline_by_fingerprint.items()
        if fingerprint not in current_by_fingerprint
    ]
    reopened = [
        _view(issue)
        for fingerprint, issue in current_by_fingerprint.items()
        if fingerprint in baseline_by_fingerprint
        and str(baseline_by_fingerprint[fingerprint].get("observation_status", "")) == "auto_closed"
    ]

    return {
        "comparable": True,
        "reason": reason,
        "new": new,
        "persistent": persistent,
        "not_observed": not_observed,
        "reopened": reopened,
        "counts": {
            "new": len(new),
            "persistent": len(persistent),
            "not_observed": len(not_observed),
            "reopened": len(reopened),
        },
    }


def _view(issue: dict[str, Any]) -> dict[str, Any]:
    """What the report says about one issue."""
    return {
        "issue_id": issue.get("issue_id", ""),
        "fingerprint": issue.get("fingerprint", ""),
        "title": issue.get("title", ""),
        "severity": issue.get("severity", ""),
        "vuln_class": issue.get("vuln_class", ""),
        "triage_status": issue.get("triage_status", ""),
        "observation_status": issue.get("observation_status", ""),
        "first_seen_at": issue.get("first_seen_at"),
        "last_seen_at": issue.get("last_seen_at"),
    }
