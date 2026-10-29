"""A finding keeps the evidence it came with.

A model writes its evidence in whatever shape it likes.  The evidence of
a finding is what a reader trusts, so a shape the platform does not know
must not cost the finding its evidence - or the finding itself.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration


def test_evidence_written_as_a_string_is_kept(services) -> None:
    scan = services.scans.create(
        {
            "name": "evidence shape",
            "status": "running",
            "created_by": "test",
            "definition": {"targets": ["https://demo.test/"]},
            "scope": {"authorized_hosts": ["demo.test"]},
        }
    )

    document, _ = services.findings.upsert(
        scan_id=scan.scan_id,
        title="A finding with a sentence of evidence",
        summary="the model wrote its evidence as prose",
        vuln_class="xss",
        severity="medium",
        host="demo.test",
        detected_by=["vuln_xss"],
        detection_source="agent",
        evidence=["the /search endpoint reflected the payload in the body"],
    )

    evidence = services.findings.evidence_for(document["finding_id"])
    assert len(evidence) == 1
    assert "reflected the payload" in evidence[0]["excerpt"]
    assert evidence[0]["kind"] == "note"


def test_evidence_written_as_a_list_of_strings_is_kept(services) -> None:
    scan = services.scans.create(
        {
            "name": "evidence shape",
            "status": "running",
            "created_by": "test",
            "definition": {"targets": ["https://demo.test/"]},
            "scope": {"authorized_hosts": ["demo.test"]},
        }
    )

    document, _ = services.findings.upsert(
        scan_id=scan.scan_id,
        title="A finding with two sentences of evidence",
        summary="the model wrote its evidence as prose",
        vuln_class="xss",
        severity="medium",
        host="demo.test",
        detected_by=["vuln_xss"],
        detection_source="agent",
        evidence=["first observation", "second observation"],
    )

    evidence = services.findings.evidence_for(document["finding_id"])
    assert len(evidence) == 2
    assert [item["excerpt"] for item in evidence] == ["first observation", "second observation"]


def test_evidence_written_as_dictionaries_is_kept(services) -> None:
    scan = services.scans.create(
        {
            "name": "evidence shape",
            "status": "running",
            "created_by": "test",
            "definition": {"targets": ["https://demo.test/"]},
            "scope": {"authorized_hosts": ["demo.test"]},
        }
    )

    document, _ = services.findings.upsert(
        scan_id=scan.scan_id,
        title="A finding with structured evidence",
        summary="the model wrote its evidence as objects",
        vuln_class="xss",
        severity="medium",
        host="demo.test",
        detected_by=["vuln_xss"],
        detection_source="agent",
        evidence=[{"kind": "response", "reference": "https://demo.test/x", "excerpt": "payload"}],
    )

    evidence = services.findings.evidence_for(document["finding_id"])
    assert len(evidence) == 1
    assert evidence[0]["kind"] == "response"
    assert evidence[0]["reference"] == "https://demo.test/x"


def test_evidence_written_as_one_string_is_not_split_into_characters(services) -> None:
    scan = services.scans.create(
        {
            "name": "evidence shape",
            "status": "running",
            "created_by": "test",
            "definition": {"targets": ["https://demo.test/"]},
            "scope": {"authorized_hosts": ["demo.test"]},
        }
    )

    document, _ = services.findings.upsert(
        scan_id=scan.scan_id,
        title="A finding with a single string of evidence",
        summary="the model wrote one string",
        vuln_class="xss",
        severity="medium",
        host="demo.test",
        detected_by=["vuln_xss"],
        detection_source="agent",
        evidence="one observation, written as a string",
    )

    evidence = services.findings.evidence_for(document["finding_id"])
    assert len(evidence) == 1
