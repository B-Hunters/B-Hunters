"""The verdicts the verifier reaches have to reach the findings.

The verifier answers with one entry per candidate finding it looked at.
Without that answer being applied, every finding of a scan stays
"unverified" and the console cannot say which of them hold up.
"""

from __future__ import annotations

import pytest

from b_hunters.platform.agents.orchestrator import ScanContext, ScanOrchestrator
from b_hunters.platform.agents.schemas import CandidateFinding, Confidence

pytestmark = pytest.mark.integration


def _orchestrator(services) -> ScanOrchestrator:
    return ScanOrchestrator(
        database=services.db,
        settings=services.settings,
        provider_factory=lambda provider_name="": None,
    )


def _context(scan_id: str) -> ScanContext:
    return ScanContext(
        scan_id=scan_id,
        name="verdict test",
        targets=["https://demo.test/"],
        authorized_hosts=["demo.test"],
    )


def test_a_verdict_is_applied_to_the_finding_it_names(services) -> None:
    scan = services.scans.create(
        {
            "name": "verdict test",
            "status": "running",
            "created_by": "test",
            "definition": {"targets": ["https://demo.test/"]},
            "scope": {"authorized_hosts": ["demo.test"]},
        }
    )
    orchestrator = _orchestrator(services)
    context = _context(scan.scan_id)

    candidate = CandidateFinding(
        title="Boolean SQL injection in the pastes filter",
        vuln_class="sql_injection",
        severity="high",
        host="demo.test",
        path="/graphql",
        confidence=Confidence.HIGH,
    )
    services.findings.upsert(
        scan_id=scan.scan_id,
        title=candidate.title,
        summary="the filter is concatenated into a query",
        vuln_class=candidate.vuln_class,
        severity=candidate.severity,
        host=candidate.host,
        path=candidate.path,
        detected_by=["vuln_injection"],
        detection_source="agent",
    )

    orchestrator._apply_verdicts(
        context,
        [candidate],
        [
            {
                "title": candidate.title,
                "verification_status": "confirmed",
                "verification_notes": "reproduced with a boolean payload",
            }
        ],
    )

    findings = services.findings.list(scan.scan_id)
    assert len(findings) == 1
    assert findings[0]["verification_status"] == "confirmed"
    assert findings[0]["verified_by"] == "verifier"
    assert "reproduced" in findings[0]["verification_notes"]


def test_a_verdict_is_matched_by_order_when_the_title_does_not_match(services) -> None:
    scan = services.scans.create(
        {
            "name": "verdict test",
            "status": "running",
            "created_by": "test",
            "definition": {"targets": ["https://demo.test/"]},
            "scope": {"authorized_hosts": ["demo.test"]},
        }
    )
    orchestrator = _orchestrator(services)
    context = _context(scan.scan_id)

    candidate = CandidateFinding(
        title="Something the verifier words differently",
        vuln_class="xss",
        severity="medium",
        host="demo.test",
    )
    services.findings.upsert(
        scan_id=scan.scan_id,
        title=candidate.title,
        summary="reflected",
        vuln_class=candidate.vuln_class,
        severity=candidate.severity,
        host=candidate.host,
        detected_by=["vuln_xss"],
        detection_source="agent",
    )

    orchestrator._apply_verdicts(
        context,
        [candidate],
        [{"title": "a different title", "verification_status": "rejected"}],
    )

    findings = services.findings.list(scan.scan_id)
    assert findings[0]["verification_status"] == "rejected"


def test_a_verdict_is_accepted_under_the_name_the_role_uses(services) -> None:
    """The role says "verdict"; the platform says "verification_status"."""
    scan = services.scans.create(
        {
            "name": "verdict test",
            "status": "running",
            "created_by": "test",
            "definition": {"targets": ["https://demo.test/"]},
            "scope": {"authorized_hosts": ["demo.test"]},
        }
    )
    orchestrator = _orchestrator(services)
    context = _context(scan.scan_id)

    candidate = CandidateFinding(
        title="A finding",
        vuln_class="xss",
        severity="medium",
        host="demo.test",
    )
    services.findings.upsert(
        scan_id=scan.scan_id,
        title=candidate.title,
        summary="reflected",
        vuln_class=candidate.vuln_class,
        severity=candidate.severity,
        host=candidate.host,
        detected_by=["vuln_xss"],
        detection_source="agent",
    )

    orchestrator._apply_verdicts(
        context,
        [candidate],
        [{"title": candidate.title, "verdict": "rejected", "rationale": "it does not hold"}],
    )

    findings = services.findings.list(scan.scan_id)
    assert findings[0]["verification_status"] == "rejected"
    assert findings[0]["verification_notes"] == "it does not hold"


def test_an_unknown_verdict_status_is_not_written(services) -> None:
    scan = services.scans.create(
        {
            "name": "verdict test",
            "status": "running",
            "created_by": "test",
            "definition": {"targets": ["https://demo.test/"]},
            "scope": {"authorized_hosts": ["demo.test"]},
        }
    )
    orchestrator = _orchestrator(services)
    context = _context(scan.scan_id)

    candidate = CandidateFinding(
        title="A finding",
        vuln_class="xss",
        severity="medium",
        host="demo.test",
    )
    services.findings.upsert(
        scan_id=scan.scan_id,
        title=candidate.title,
        summary="reflected",
        vuln_class=candidate.vuln_class,
        severity=candidate.severity,
        host=candidate.host,
        detected_by=["vuln_xss"],
        detection_source="agent",
    )

    orchestrator._apply_verdicts(
        context,
        [candidate],
        [{"title": candidate.title, "verification_status": "made up"}],
    )

    findings = services.findings.list(scan.scan_id)
    assert findings[0]["verification_status"] == "unverified"
