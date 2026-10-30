"""The roles that judge must get their budget.

A scan has a budget and the roles compete for it.  When twelve roles are
planned at once the budget is gone before the last of them starts, and
the roles that never ran are recorded as cut off — including the roles
that give the findings their verdict.  A scan whose adjudicator never
ran leaves every finding unverified.
"""

from __future__ import annotations

import pytest

from b_hunters.platform.agents.orchestrator import (
    JUDGING_ROLES,
    ROLE_PRIORITY,
    ScanOrchestrator,
)

pytestmark = pytest.mark.integration


def test_the_roles_start_in_the_order_of_their_yield():
    assert ROLE_PRIORITY[0] == "recon"
    assert "access_control" in ROLE_PRIORITY
    # The judging roles come after the hypothesis roles: they judge what
    # the hypothesis roles found.
    assert "verifier" not in ROLE_PRIORITY
    assert "adjudicator" not in ROLE_PRIORITY


def test_the_judging_roles_are_the_ones_that_verify():
    assert "verifier" in JUDGING_ROLES
    assert "adjudicator" in JUDGING_ROLES


def test_a_role_ranks_by_its_place_in_the_order():
    assert ScanOrchestrator._role_rank("recon") == 0
    assert ScanOrchestrator._role_rank("source_analysis") == len(ROLE_PRIORITY) - 1
    # The judging roles rank last.
    assert ScanOrchestrator._role_rank("adjudicator") == len(ROLE_PRIORITY)
    assert ScanOrchestrator._role_rank("verifier") == len(ROLE_PRIORITY)


def test_the_judging_roles_keep_a_share_of_the_budget(services):
    import time

    orchestrator = ScanOrchestrator(database=services.db, settings=services.settings)
    deadline = time.monotonic() + 100

    reserve = orchestrator._judging_reserve(
        type("C", (), {"max_duration_seconds": 100})(), deadline
    )

    assert reserve > 0
    assert reserve <= 100 * 0.5
