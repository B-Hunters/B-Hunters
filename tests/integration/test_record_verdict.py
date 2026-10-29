"""The verdict tool writes the verdict to the finding.

A verdict that only exists in the conclusion of the verification role is
prose: it never reaches the finding, and the finding stays unverified
forever.  The tool is the way out of that.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from b_hunters.platform.tools.builtin.scan import record_verdict, record_verdicts
from b_hunters.platform.tools.gateway import (
    CAPABILITY_READ,
    CAPABILITY_VERIFY,
    ToolContext,
    ToolError,
    ToolPermissions,
)

pytestmark = pytest.mark.integration


class FakeRepository:
    """A findings repository that keeps the verdicts in memory."""

    def __init__(self) -> None:
        self.items = {
            "f-1": {
                "finding_id": "f-1",
                "scan_id": "scan-1",
                "title": "A finding",
                "severity": "medium",
                "verification_status": "unverified",
            }
        }
        self.verdicts: list[tuple[str, dict]] = []

    def get(self, finding_id: str):
        return self.items.get(finding_id)

    def set_verification(
        self, finding_id, *, status, notes="", verified_by="", severity="", false_positive_reason=""
    ):
        item = self.items.get(finding_id)
        if item is None:
            return False
        item["verification_status"] = status
        if severity:
            item["severity"] = severity
        self.verdicts.append((finding_id, {"status": status, "notes": notes, "verified_by": verified_by}))
        return True


def _context(repo: FakeRepository, *, role: str = "verifier", scan_id: str = "scan-1") -> ToolContext:
    return ToolContext(
        scan_id=scan_id,
        task_id="task-1",
        role=role,
        workspace=Path("/tmp"),
        permissions=ToolPermissions(capabilities={CAPABILITY_READ, CAPABILITY_VERIFY}),
        metadata={"findings_repository": repo},
    )


def test_the_verdict_reaches_the_finding() -> None:
    repo = FakeRepository()

    result = record_verdict(
        "f-1",
        "confirmed",
        severity="high",
        notes="reproduced with a boolean payload",
        context=_context(repo),
    )

    assert result["verification_status"] == "confirmed"
    assert repo.items["f-1"]["verification_status"] == "confirmed"
    assert repo.items["f-1"]["severity"] == "high"
    assert repo.verdicts[0][1]["notes"] == "reproduced with a boolean payload"


def test_a_rejection_carries_its_reason() -> None:
    repo = FakeRepository()

    record_verdict(
        "f-1",
        "rejected",
        false_positive_reason="the endpoint requires authentication",
        context=_context(repo),
    )

    assert repo.items["f-1"]["verification_status"] == "rejected"


def test_a_finding_of_another_scan_is_refused() -> None:
    repo = FakeRepository()

    with pytest.raises(ToolError) as excinfo:
        record_verdict("f-1", "confirmed", context=_context(repo, scan_id="another-scan"))

    assert "another scan" in str(excinfo.value)
    assert repo.verdicts == []


def test_an_unknown_finding_is_refused() -> None:
    repo = FakeRepository()

    with pytest.raises(ToolError):
        record_verdict("nope", "confirmed", context=_context(repo))


def test_many_verdicts_are_recorded_in_one_call() -> None:
    """A judge with fifty findings to judge cannot record them one at a
    time within its budget."""
    repo = FakeRepository()
    repo.items["f-2"] = {
        "finding_id": "f-2",
        "scan_id": "scan-1",
        "title": "Another finding",
        "severity": "low",
        "verification_status": "unverified",
    }

    result = record_verdicts(
        [
            {"finding_id": "f-1", "verdict": "confirmed", "notes": "reproduced"},
            {"finding_id": "f-2", "verdict": "rejected", "false_positive_reason": "a false alarm"},
        ],
        context=_context(repo),
    )

    assert result["recorded"] == 2
    assert result["refused"] == 0
    assert repo.items["f-1"]["verification_status"] == "confirmed"
    assert repo.items["f-2"]["verification_status"] == "rejected"


def test_a_refused_verdict_does_not_stop_the_others() -> None:
    """One bad entry must not cost the findings that were fine."""
    repo = FakeRepository()

    result = record_verdicts(
        [
            {"finding_id": "nope", "verdict": "confirmed"},
            {"finding_id": "f-1", "verdict": "likely"},
            {"verdict": "confirmed"},
        ],
        context=_context(repo),
    )

    assert result["recorded"] == 1
    assert result["refused"] == 2
    assert repo.items["f-1"]["verification_status"] == "likely"
    # The problems are named, so the judge can correct them.
    assert any(problem["finding_id"] == "nope" for problem in result["problems"])


def test_a_verdict_for_another_scan_is_refused() -> None:
    repo = FakeRepository()

    result = record_verdicts(
        [{"finding_id": "f-1", "verdict": "confirmed"}],
        context=_context(repo, scan_id="another-scan"),
    )

    assert result["recorded"] == 0
    assert result["refused"] == 1
    assert repo.verdicts == []
