"""The worker contract test.

Every worker in the organisation has to agree on the Karton message
contract.  This test reads the worker sources and fails when a worker
drifts: a payload key that nobody writes, a status reported against a key
that matches no document, a task type that nobody consumes, an identity
that another worker already uses, or a worker that never reports at all.

The worker repositories live next to the framework repository when the
organisation has been cloned as a whole.  Set ``BHUNTERS_WORKER_ROOT`` to
point at them.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from b_hunters.platform.scanners.contracts import verify_repository_set

pytestmark = pytest.mark.integration

WORKER_ROOT = Path(os.environ.get("BHUNTERS_WORKER_ROOT", "/home/sniper/pentest/repos")).resolve()


def _repositories() -> list[Path]:
    if not WORKER_ROOT.is_dir():
        return []
    return [
        directory
        for directory in sorted(WORKER_ROOT.iterdir())
        if directory.is_dir() and directory.name != "B-Hunters" and any(directory.glob("*/*.py"))
    ]


@pytest.fixture(scope="module")
def verification():
    repositories = _repositories()
    if not repositories:
        pytest.skip(f"no worker repositories were found under {WORKER_ROOT}")
    return verify_repository_set(repositories)


def test_every_worker_is_analysed(verification) -> None:
    contracts, _findings = verification
    assert len(contracts) >= 17, "the organisation has 17 worker repositories"


def test_the_worker_contracts_have_no_errors(verification) -> None:
    _contracts, findings = verification
    errors = [finding for finding in findings if finding.severity == "error"]
    assert not errors, "\n".join(str(finding) for finding in errors)


def test_the_worker_contracts_have_no_warnings(verification) -> None:
    _contracts, findings = verification
    warnings = [finding for finding in findings if finding.severity == "warning"]
    assert not warnings, "\n".join(str(finding) for finding in warnings)


def test_every_worker_reports_its_status(verification) -> None:
    """Every worker reports its progress the same way."""
    contracts, _findings = verification
    for contract in contracts:
        assert contract.reports_status, f"{contract.name} never reports its status"
        assert contract.status_keys, f"{contract.name} reports no status key"


def test_every_worker_declares_its_filters(verification) -> None:
    contracts, _findings = verification
    for contract in contracts:
        assert contract.filters, f"{contract.name} declares no task filters"
        for entry in contract.filters:
            assert "type" in entry and "stage" in entry, f"{contract.name}: {entry}"


def test_every_worker_has_a_unique_identity(verification) -> None:
    """Two workers with the same identity compete for the same queue."""
    contracts, _findings = verification
    identities = [contract.identity for contract in contracts if contract.identity]
    assert len(identities) == len(set(identities))


def test_every_worker_binds_to_a_known_task_type(verification) -> None:
    """Every filter refers to a task type that is actually produced.

    The root task is produced by the CLI, not by a worker, so the
    producer's types are part of the known set.
    """
    contracts, _findings = verification
    produced: set[str] = {"domain"}
    for contract in contracts:
        produced |= contract.task_types
    for contract in contracts:
        for entry in contract.filters:
            task_type = entry.get("type", "")
            if task_type:
                assert task_type in produced, (
                    f"{contract.name} binds to '{task_type}', which nothing produces"
                )
