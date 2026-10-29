"""The judge gets a budget that grows with the findings it must judge.

The adjudicator ran out of rounds after it had judged half of the
findings and left the rest unverified: its budget was fixed, while the
number of findings it had to judge was not known until the workers and
the hypothesis roles had run.  The findings it judges are also handed to
it in severity order - ordered by the *name* of the severity, the least
important finding came first.
"""

from __future__ import annotations

from typing import Any

import pytest

from b_hunters.platform.agents.orchestrator import ScanOrchestrator
from b_hunters.platform.agents.roles import builtin_roles
from b_hunters.platform.agents.schemas import AgentTask, Budget

pytestmark = pytest.mark.integration


def _finding(services, scan_id: str, severity: str, title: str) -> None:
    services.findings.upsert(
        scan_id=scan_id,
        title=title,
        summary=title,
        vuln_class="test_class",
        severity=severity,
        host="demo.test",
        path=f"/{title}",
        extra_key=title,
    )


def test_the_findings_are_handed_over_in_severity_order(services) -> None:
    """The judge reads the serious findings first."""
    scan = services.scans.create({"name": "ordering", "targets": ["https://demo.test/"]})
    for severity, title in (
        ("info", "an info one"),
        ("medium", "a medium one"),
        ("critical", "a critical one"),
        ("low", "a low one"),
        ("high", "a high one"),
    ):
        _finding(services, scan.scan_id, severity, title)

    findings = services.findings.list(scan.scan_id, limit=50)

    assert [finding["severity"] for finding in findings] == [
        "critical",
        "high",
        "medium",
        "low",
        "info",
    ]
    # The sort helper must not leak into the document.
    assert "_severity_rank" not in findings[0]


def test_an_unknown_severity_sorts_last(services) -> None:
    """A finding whose severity is not one of the known ones must not
    jump to the front of the list."""
    scan = services.scans.create({"name": "odd", "targets": ["https://demo.test/"]})
    _finding(services, scan.scan_id, "info", "a known one")
    # Written straight into the collection: the repository normalises an
    # unknown severity to "info" on the way in, so the guard can only be
    # reached by a document that was not written through it.
    services.db.collection("platform_findings").insert_one(
        {
            "finding_id": "odd-one",
            "scan_id": scan.scan_id,
            "fingerprint": "odd",
            "title": "a strange one",
            "severity": "not-a-severity",
            "confidence": 0.9,
        }
    )

    findings = services.findings.list(scan.scan_id, limit=50)

    assert findings[-1]["title"] == "a strange one"


def _task(role: str, budget: Budget) -> AgentTask:
    return AgentTask(
        task_id=f"scan:{role}",
        scan_id="scan",
        role=role,
        title=role,
        budget=budget,
    )


def _orchestrator(services) -> ScanOrchestrator:
    return ScanOrchestrator(database=services.db, settings=services.settings)


def test_the_judge_gets_a_budget_that_covers_the_findings(services) -> None:
    """A judge with a fixed budget leaves the findings it did not reach
    without a verdict."""
    scan = services.scans.create({"name": "budget", "targets": ["https://demo.test/"]})
    for index in range(20):
        _finding(services, scan.scan_id, "medium", f"finding {index}")

    orchestrator = _orchestrator(services)
    task = _task("adjudicator", Budget(max_tokens=400000, max_tool_calls=60, max_rounds=12))

    budget = orchestrator._budget_for_task(
        _context(services, scan.scan_id),
        builtin_roles()["adjudicator"],
        task,
    )

    assert budget.max_rounds >= 20 * 2, "the judge cannot judge every finding"
    assert budget.max_tool_calls >= 20 * 2


def test_a_role_that_judges_nothing_keeps_its_budget(services) -> None:
    """A scan with no findings waiting for a verdict must not hand the
    judge a bigger budget for nothing."""
    scan = services.scans.create({"name": "empty", "targets": ["https://demo.test/"]})
    orchestrator = _orchestrator(services)
    task = _task("adjudicator", Budget(max_tokens=400000, max_tool_calls=60, max_rounds=12))

    budget = orchestrator._budget_for_task(
        _context(services, scan.scan_id),
        builtin_roles()["adjudicator"],
        task,
    )

    assert budget.max_rounds == 12


def test_a_role_that_is_not_a_judge_keeps_its_budget(services) -> None:
    """The hypothesis roles do not judge findings; their budget is the
    one the plan gave them."""
    scan = services.scans.create({"name": "roles", "targets": ["https://demo.test/"]})
    for index in range(20):
        _finding(services, scan.scan_id, "medium", f"finding {index}")

    orchestrator = _orchestrator(services)
    task = _task("recon", Budget(max_tokens=150000, max_tool_calls=50, max_rounds=8))

    budget = orchestrator._budget_for_task(
        _context(services, scan.scan_id),
        builtin_roles()["recon"],
        task,
    )

    assert budget.max_rounds == 8
    assert budget.max_tool_calls == 50


def test_the_judge_is_capped(services) -> None:
    """A scan with a hundred findings must not hand the judge an
    unbounded budget."""
    scan = services.scans.create({"name": "many", "targets": ["https://demo.test/"]})
    for index in range(30):
        _finding(services, scan.scan_id, "medium", f"finding {index}")

    orchestrator = _orchestrator(services)
    task = _task("adjudicator", Budget(max_tokens=400000, max_tool_calls=60, max_rounds=12))

    budget = orchestrator._budget_for_task(
        _context(services, scan.scan_id),
        builtin_roles()["adjudicator"],
        task,
    )

    assert budget.max_rounds <= 60


def _context(services, scan_id: str) -> Any:
    from b_hunters.platform.agents.orchestrator import ScanContext, ScanProfile

    return ScanContext(
        scan_id=scan_id,
        name="budget scan",
        targets=["https://demo.test/"],
        authorized_hosts=["demo.test"],
        profile=ScanProfile.default(),
    )
