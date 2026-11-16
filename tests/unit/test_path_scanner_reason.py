"""A scanner that was handed nothing is not a scanner that found nothing.

The path scanners test the URLs that carry a parameter.  The crawler
hands them what it followed, and a page usually has no parameter in it:
the scanner filters the list down to nothing and exits without testing
anything.

Reported as "ran, found nothing", that is a false clean bill of health
for work that never happened - and it is what the platform said for
every scan of the laboratory.
"""

from __future__ import annotations

import pytest

from b_hunters.platform.api.routers.assets import _reason_for
from b_hunters.platform.scanners.worker_output import PATH_SCANNERS, _status


def test_a_path_scanner_with_no_candidates_is_told_so():
    run = {
        "worker": "B-Hunters-SQLMap",
        "tasks": 2,
        "findings": 0,
        "crashed_tasks": 0,
        "candidates": 0,
    }

    assert _reason_for(run) == "ran, had nothing to test"


def test_a_path_scanner_with_candidates_is_reported_as_finding_nothing():
    run = {
        "worker": "B-Hunters-SQLMap",
        "tasks": 2,
        "findings": 0,
        "crashed_tasks": 0,
        "candidates": 14,
    }

    assert _reason_for(run) == "ran, found nothing"


def test_a_worker_that_is_not_a_path_scanner_is_unaffected():
    """Nmap does not test the candidate list, so the count is not its concern."""
    run = {
        "worker": "B-Hunters-Nmap",
        "tasks": 2,
        "findings": 0,
        "crashed_tasks": 0,
        "candidates": 0,
    }

    assert _reason_for(run) == "ran, found nothing"


def test_a_scanner_that_found_something_is_reported_as_having_run():
    run = {
        "worker": "B-Hunters-SQLMap",
        "tasks": 2,
        "findings": 1,
        "crashed_tasks": 0,
        "candidates": 0,
    }

    assert _reason_for(run) == "ran"


def test_a_scanner_that_errored_is_reported_as_having_errored():
    run = {
        "worker": "B-Hunters-SQLMap",
        "tasks": 2,
        "findings": 0,
        "crashed_tasks": 1,
        "candidates": 0,
    }

    assert _reason_for(run) == "errored"


def test_the_status_of_a_worker_row_says_the_same_thing():
    assert (
        _status(2, [], 0, worker="B-Hunters-DalFox", candidates=0)
        == "ran, had nothing to test"
    )
    assert (
        _status(2, [], 0, worker="B-Hunters-DalFox", candidates=3)
        == "ran, found nothing"
    )


def test_every_path_scanner_is_one_of_the_workers():
    """The set is not a guess: it names the workers that read the list."""
    for identity in PATH_SCANNERS:
        assert identity.startswith("B-Hunters-")
