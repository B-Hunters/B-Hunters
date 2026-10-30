"""The class of a finding is normalised when it is stored.

The agent roles name a class in their own words.  The finding is stored
with the canonical name and keeps the original beside it, and two
reports of the same issue in two spellings do not become two findings.
"""

from __future__ import annotations

import uuid

import pytest

from b_hunters.platform.db.repositories import FindingRepository, compute_fingerprint

pytestmark = pytest.mark.integration


def _upsert(repository, **overrides):
    payload = {
        # The shared test database keeps the findings of every run, so
        # each test needs its own scan.
        "scan_id": f"s-{uuid.uuid4().hex[:8]}",
        "title": "Something",
        "summary": "",
        "vuln_class": "CWE-1021 (Clickjacking)",
        "severity": "medium",
        "host": "demo.test",
        "path": "/app",
    }
    payload.update(overrides)
    return repository.upsert(**payload)


def test_the_stored_class_is_canonical(database):
    repository = FindingRepository(database)

    document, _ = _upsert(repository)

    assert document["vuln_class"] == "security_misconfiguration"
    assert document["vuln_class_raw"] == "CWE-1021 (Clickjacking)"


def test_two_spellings_of_one_class_both_carry_the_canonical_name(database):
    """The spelling is kept, so two weaknesses of a kind stay apart.

    Merging them would be worse than the duplicate: the header
    findings of a target once merged into one finding, and three
    misconfigurations were lost.  The canonical name is what makes the
    two comparable; the discriminator is what keeps them separate.
    """
    repository = FindingRepository(database)
    scan_id = f"s-{uuid.uuid4().hex[:8]}"

    first, _ = _upsert(repository, scan_id=scan_id, vuln_class="CWE-1021 (Clickjacking)")
    second, created = _upsert(
        repository, scan_id=scan_id, vuln_class="security_misconfiguration", detected_by=["other"]
    )

    assert created is True
    assert first["vuln_class"] == second["vuln_class"] == "security_misconfiguration"


def test_the_same_finding_twice_is_one_finding(database):
    repository = FindingRepository(database)
    scan_id = f"s-{uuid.uuid4().hex[:8]}"

    first, _ = _upsert(repository, scan_id=scan_id, vuln_class="CWE-1021 (Clickjacking)")
    second, created = _upsert(repository, scan_id=scan_id, vuln_class="CWE-1021 (Clickjacking)")

    assert created is False
    assert second["finding_id"] == first["finding_id"]


def test_two_different_issues_of_one_class_stay_apart(database):
    repository = FindingRepository(database)
    scan_id = f"s-{uuid.uuid4().hex[:8]}"

    first, _ = _upsert(repository, scan_id=scan_id, vuln_class="CWE-1021 (Clickjacking)", path="/one")
    second, created = _upsert(
        repository,
        scan_id=scan_id,
        vuln_class="CWE-693 (Protection Mechanism Failure)",
        path="/two",
    )

    assert created is True
    assert first["finding_id"] != second["finding_id"]


def test_the_fingerprint_follows_the_canonical_class(database):
    repository = FindingRepository(database)

    document, _ = _upsert(repository, vuln_class="SQL Injection")

    expected = compute_fingerprint(
        vuln_class="sql_injection",
        host="demo.test",
        path="/app",
        parameter="",
        extra="SQL Injection",
    )
    assert document["fingerprint"] == expected
