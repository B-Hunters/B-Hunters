"""A scan runs the workers it asked for, and no others.

The Karton router hands a task to every consumer whose filters match
it.  A task for ``subdomain``/``new`` therefore reaches thirteen
workers, whatever the scan's profile named - so a recon scan ran
sqlmap, xray and ffuf as well, against the target, at the same time.

The native adapters have always respected the profile's scanner list.
This is the other half: the list travels with the task, and a worker
that is not on it ends the task without touching the target.
"""

from __future__ import annotations

import pytest

from b_hunters.bhunter import BHunters
from b_hunters.platform.agents.orchestrator import ScanContext, ScanOrchestrator
from b_hunters.platform.scanners.worker_output import (
    SCANNER_BY_WORKER,
    WORKER_BY_SCANNER,
    WORKER_IDENTITIES,
)


class _Task:
    def __init__(self, **payload):
        self.payload_persistent = payload


class _Worker(BHunters):
    """A worker that is not going to be initialised."""

    def __init__(self, identity="B-Hunters-SQLMap", **payload):
        self.identity = identity
        self.current_task = _Task(**payload)

    def process(self, task):  # pragma: no cover - never called
        raise NotImplementedError


def _context(scanners):
    return ScanContext(
        scan_id="s-1",
        name="test",
        targets=["https://demo.test/"],
        authorized_hosts=["demo.test"],
        profile=type(
            "P",
            (),
            {
                "scanners": list(scanners),
                "max_concurrency": 1,
                "agent_roles": [],
                "name": "standard",
            },
        )(),
    )


def test_every_worker_is_reachable_from_a_scanner_name():
    """A worker that no scanner name maps to would never be asked for."""
    missing = [identity for identity in WORKER_IDENTITIES if identity not in SCANNER_BY_WORKER]
    assert not missing, f"these workers cannot be enabled: {missing}"


def test_the_scanner_names_map_to_the_worker_identities():
    assert WORKER_BY_SCANNER["sqlmap"] == "B-Hunters-SQLMap"
    assert WORKER_BY_SCANNER["katana"] == "B-Hunters-Katana"
    assert WORKER_BY_SCANNER["subrecon"] == "B-Hunters-subrecon"


def test_the_profile_decides_which_workers_run():
    enabled = ScanOrchestrator._enabled_workers(_context(["katana", "nuclei", "subrecon"]))

    assert enabled == ("B-Hunters-Katana", "B-Hunters-Nuclei", "B-Hunters-subrecon")


def test_a_native_adapter_is_not_a_worker():
    """The native adapters run inside the platform; they name no worker."""
    enabled = ScanOrchestrator._enabled_workers(_context(["security_headers", "katana"]))

    assert enabled == ("B-Hunters-Katana",)


def test_a_worker_that_was_not_asked_for_does_nothing():
    worker = _Worker(
        "B-Hunters-SQLMap", enabled_workers=["B-Hunters-Katana", "B-Hunters-Nuclei"]
    )

    assert worker.is_enabled_for_scan() is False


def test_a_worker_that_was_asked_for_runs():
    worker = _Worker("B-Hunters-Katana", enabled_workers=["B-Hunters-Katana"])

    assert worker.is_enabled_for_scan() is True


def test_a_scan_that_said_nothing_runs_every_worker():
    """A scan that was not started by the platform has no list."""
    worker = _Worker("B-Hunters-SQLMap")

    assert worker.is_enabled_for_scan() is True
