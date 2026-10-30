"""A role that was cut off keeps what it found.

The findings of a role travel in its final answer.  A role that runs
out of time never gives one, and everything it had found was lost with
it.  The last thing it said is read as its answer, so the findings it
names are kept and judged like any other.
"""

from __future__ import annotations

import json

from b_hunters.platform.agents.runtime import _salvage


class _Run:
    """The part of a run the salvage touches."""

    def __init__(self):
        self.findings: list = []
        self.conclusion = ""
        self.observations: list = []
        self.uncertainty = ""
        self.status = "wall_clock"


def _answer(text: str) -> str:
    """What a model writes when it answers with the findings it has."""
    return json.dumps(
        {
            "conclusion": "the application leaks its configuration",
            "confidence": "medium",
            "observations": ["the endpoint answered without a session"],
            "uncertainty": "",
            "next_step": "",
            "findings": [
                {
                    "title": "Unauthenticated configuration disclosure",
                    "vuln_class": "information_disclosure",
                    "severity": "medium",
                    "host": "demo.test",
                    "path": "/rest/admin/application-configuration",
                    "confidence": 0.8,
                }
            ],
        }
    )


def test_the_findings_of_a_cut_off_role_are_kept():
    run = _Run()

    _salvage(run, _answer("the answer"))

    assert len(run.findings) == 1
    assert run.findings[0]["title"] == "Unauthenticated configuration disclosure"
    assert run.conclusion == "the application leaks its configuration"
    assert run.observations


def test_the_status_of_a_cut_off_role_is_not_changed():
    run = _Run()

    _salvage(run, _answer("the answer"))

    assert run.status == "wall_clock"


def test_a_role_that_found_nothing_keeps_nothing():
    run = _Run()

    _salvage(run, "I am still looking at the application.")

    assert run.findings == []


def test_a_role_that_never_spoke_keeps_nothing():
    run = _Run()

    _salvage(run, "")

    assert run.findings == []
    assert run.conclusion == ""


def test_what_a_role_already_found_is_not_overwritten():
    run = _Run()
    run.findings = [{"title": "the one it already recorded"}]

    _salvage(run, _answer("the answer"))

    assert run.findings == [{"title": "the one it already recorded"}]
