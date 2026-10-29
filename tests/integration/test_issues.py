"""Durable issues: the findings that survive from one scan to the next.

A finding belongs to the scan that found it.  An issue is the durable
thing behind it: the same fingerprint in a later scan of the same target
is the same issue, with the same triage state and the same history.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from b_hunters.platform.api.deps import Services
from b_hunters.platform.db.client import Database

#: The collections the issue tests own.  They are emptied before and after
#: every test so that a test never sees the leftovers of another one.
OWNED_COLLECTIONS = (
    "platform_issues",
    "platform_findings",
    "platform_evidence",
    "platform_scans",
)


@pytest.fixture(scope="module")
def issue_settings(settings):
    """The settings of the issue tests: a database of their own.

    The issue collection is shared with the API tests, which empty it
    between their own tests.  The issue tests get a database of their own
    so that they neither depend on nor disturb the rest of the suite.
    """
    return replace(settings, mongo_db=f"{settings.mongo_db}-issues")


@pytest.fixture(scope="module")
def services(issue_settings):
    """A service container on the database of the issue tests."""
    db = Database(issue_settings)
    if not db.ping():
        pytest.skip(f"MongoDB is not reachable at {issue_settings.mongo_uri}")
    db.ensure_indexes()
    container = Services(db, issue_settings)
    yield container
    for collection in OWNED_COLLECTIONS:
        db.collection(collection).delete_many({})
    db.close()


@pytest.fixture(autouse=True)
def _clean(services):
    """Start every test with an empty set of issues and findings."""
    for collection in OWNED_COLLECTIONS:
        services.db.collection(collection).delete_many({})
    yield


def _scan_with_key(services, name: str = "s"):
    """Create a scan that carries the target key of the issues."""
    return services.scans.create(
        {
            "name": name,
            "status": "queued",
            "created_by": "test",
            "definition": {"targets": ["https://demo.test/"]},
            "scope": {"authorized_hosts": ["demo.test"]},
            "target_key": "demo.test",
        }
    )


def test_a_finding_links_to_an_issue(services):
    scan = _scan_with_key(services)
    finding, _ = services.findings.upsert(
        scan_id=scan.scan_id,
        title="XSS",
        summary="s",
        vuln_class="xss",
        severity="high",
        host="demo.test",
        path="/x",
    )
    assert finding["issue_id"]
    issue = services.issues.get(finding["issue_id"])
    assert issue["fingerprint"] == finding["fingerprint"]
    assert issue["triage_status"] == "open"


def test_the_same_fingerprint_in_two_scans_shares_one_issue(services):
    for index in (1, 2):
        scan = _scan_with_key(services, f"s{index}")
        services.findings.upsert(
            scan_id=scan.scan_id,
            title="XSS",
            summary="s",
            vuln_class="xss",
            severity="high",
            host="demo.test",
            path="/x",
        )
    issues = services.issues.list()
    assert len(issues) == 1
    assert len(services.issues.history(issues[0]["issue_id"])) == 2


def test_an_unobserved_issue_is_not_observed_and_then_auto_closed(services):
    scan = _scan_with_key(services)
    issue, _ = services.issues.upsert_for_finding(
        scan_id=scan.scan_id, fingerprint="fp", title="XSS", severity="high", vuln_class="xss"
    )
    counts = services.issues.apply_scan_observations(
        scan_id=scan.scan_id, target_key="demo.test", observed_fingerprints=[]
    )
    assert counts["not_observed"] == 1
    assert services.issues.get(issue["issue_id"])["observation_status"] == "not_observed"
    services.issues.apply_scan_observations(
        scan_id=scan.scan_id, target_key="demo.test", observed_fingerprints=[]
    )
    assert services.issues.get(issue["issue_id"])["observation_status"] == "auto_closed"


def test_a_manual_fixed_issue_is_not_auto_closed(services):
    scan = _scan_with_key(services)
    issue, _ = services.issues.upsert_for_finding(
        scan_id=scan.scan_id, fingerprint="fp", title="XSS", severity="high", vuln_class="xss"
    )
    services.issues.set_triage(issue["issue_id"], status="fixed")
    services.issues.apply_scan_observations(
        scan_id=scan.scan_id, target_key="demo.test", observed_fingerprints=[]
    )
    assert services.issues.get(issue["issue_id"])["triage_status"] == "fixed"


def test_an_observed_issue_keeps_its_triage_state(services):
    scan = _scan_with_key(services)
    issue, _ = services.issues.upsert_for_finding(
        scan_id=scan.scan_id, fingerprint="fp", title="XSS", severity="high", vuln_class="xss"
    )
    services.issues.set_triage(issue["issue_id"], status="in_progress", assignee="sniper")
    counts = services.issues.apply_scan_observations(
        scan_id=scan.scan_id, target_key="demo.test", observed_fingerprints=["fp"]
    )
    assert counts["observed"] == 1
    stored = services.issues.get(issue["issue_id"])
    assert stored["observation_status"] == "observed"
    assert stored["triage_status"] == "in_progress"
    assert stored["assignee"] == "sniper"


def test_an_issue_is_found_by_its_target_and_fingerprint(services):
    scan = _scan_with_key(services)
    issue, _ = services.issues.upsert_for_finding(
        scan_id=scan.scan_id, fingerprint="fp", title="XSS", severity="high", vuln_class="xss"
    )
    found = services.issues.get_by_key(target_key="demo.test", fingerprint="fp")
    assert found["issue_id"] == issue["issue_id"]
    assert services.issues.get_by_key(target_key="other.test", fingerprint="fp") is None


def test_a_scan_without_a_target_key_never_shares_an_issue(services):
    first = services.scans.create(
        {
            "name": "unkeyed",
            "status": "queued",
            "created_by": "test",
            "definition": {"targets": ["https://demo.test/"]},
            "scope": {"authorized_hosts": ["demo.test"]},
        }
    )
    second = services.scans.create(
        {
            "name": "unkeyed",
            "status": "queued",
            "created_by": "test",
            "definition": {"targets": ["https://demo.test/"]},
            "scope": {"authorized_hosts": ["demo.test"]},
        }
    )
    for scan in (first, second):
        services.findings.upsert(
            scan_id=scan.scan_id,
            title="XSS",
            summary="s",
            vuln_class="xss",
            severity="high",
            host="demo.test",
            path="/x",
        )
    assert len(services.issues.list()) == 2


def test_the_triage_status_has_to_be_a_known_one(services):
    scan = _scan_with_key(services)
    issue, _ = services.issues.upsert_for_finding(
        scan_id=scan.scan_id, fingerprint="fp", title="XSS", severity="high", vuln_class="xss"
    )
    with pytest.raises(ValueError):
        services.issues.set_triage(issue["issue_id"], status="whatever")
