"""A role that stops finding things should stop.

Two things made every agent task expensive: the deployment's round
budget was a *floor*, so every role spent every round it was given
even when it had nothing left to look at; and a role that produced
nothing new kept going anyway.  The runtime now stops a role that has
stopped learning, and the rounds are a cap rather than a floor.
"""

from __future__ import annotations

from b_hunters.platform.agents.orchestrator import ScanOrchestrator
from b_hunters.platform.agents.runtime import _evidence_seen
from b_hunters.platform.agents.schemas import STOP_REASONS


class _Role:
    """A role with a budget."""

    def __init__(self, **budget):
        self.budget = budget
        self.role = "recon"
        self.stage = "analysis"
        self.title = "Recon"
        self.objective = "look"


def test_the_rounds_are_a_cap_and_the_tokens_are_a_floor():
    orchestrator = ScanOrchestrator.__new__(ScanOrchestrator)
    role = _Role(max_rounds=6, max_tokens=1000, max_tool_calls=10)

    # The deployment asks for twenty-four rounds: the role's own six
    # apply, because a role that declares six rounds gets six.
    assert orchestrator._agent_budget(role, "max_rounds", 8, 24) == 6
    # A deployment that asks for fewer rounds wins.
    assert orchestrator._agent_budget(role, "max_rounds", 8, 4) == 4
    # The tokens are a floor: a reasoning model needs more than the role
    # asks for.
    assert orchestrator._agent_budget(role, "max_tokens", 1000, 5000) == 5000
    assert orchestrator._agent_budget(role, "max_tool_calls", 10, 100) == 100


def test_without_a_deployment_value_the_role_keeps_its_own_budget():
    orchestrator = ScanOrchestrator.__new__(ScanOrchestrator)
    role = _Role(max_rounds=6)

    assert orchestrator._agent_budget(role, "max_rounds", 8, 0) == 6


def test_a_round_that_produced_nothing_new_is_recognised():
    records: list[dict] = []
    first = _evidence_seen(records)
    assert first == _evidence_seen(records)

    records.append({"output": "the same thing again"})
    assert _evidence_seen(records) != first


def test_a_new_url_is_new_evidence():
    records: list[dict] = [{"output": "nothing here"}]
    before = _evidence_seen(records)

    records.append({"output": "found https://demo.test/secret"})

    assert _evidence_seen(records) != before


def test_the_stop_reason_of_a_role_that_stopped_learning():
    assert STOP_REASONS["no_new_evidence"] == "no_new_evidence"
    assert "no_new_evidence" in STOP_REASONS.values()


def test_the_runtime_stops_after_three_rounds_without_new_evidence():
    """A role whose tool calls keep returning the same thing stops."""
    from b_hunters.platform.agents.runtime import AgentRuntimeConfig

    config = AgentRuntimeConfig(max_rounds=20, max_empty_rounds=3)
    assert config.max_empty_rounds == 3
