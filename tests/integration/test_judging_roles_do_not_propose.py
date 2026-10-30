"""A judge rules; it does not propose.

The roles that judge the findings are the verifier and the adjudicator.
When one of them proposed a finding of its own, the report carried the
same defect twice: once as the tool found it, with a verdict, and once
as the judge found it, without one — and with no host, so the two could
never be merged either.

The second defect is the same one seen from the other side: an agent's
finding that carries no host cannot be matched to the target it was
working on, and cannot merge with the finding the tools reported for the
same defect.
"""

from __future__ import annotations

import uuid

import pytest

from b_hunters.platform.agents.orchestrator import (
    JUDGING_ROLES,
    ScanOrchestrator,
)
from b_hunters.platform.agents.roles import (
    AGENT_OUTPUT_SCHEMA,
    JUDGEMENT_OUTPUT_SCHEMA,
)

pytestmark = pytest.mark.integration


def test_the_judging_roles_are_the_verifier_and_the_adjudicator():
    assert set(JUDGING_ROLES) == {"verifier", "adjudicator"}


def test_the_adjudicator_has_no_way_to_propose_a_finding():
    """The schema of a judge has no findings array at all."""
    assert "findings" not in JUDGEMENT_OUTPUT_SCHEMA["properties"]
    # The hypothesis roles keep theirs.
    assert "findings" in AGENT_OUTPUT_SCHEMA["properties"]


def test_the_adjudicator_uses_the_judging_schema(services):
    from b_hunters.platform.agents.roles import builtin_roles

    role = builtin_roles()["adjudicator"]

    assert role.output_schema is JUDGEMENT_OUTPUT_SCHEMA
    assert "findings" not in role.output_schema["properties"]


def test_a_finding_without_a_host_inherits_the_target(services):
    """An agent's finding belongs to the target the agent was working on."""
    from b_hunters.platform.db.repositories import FindingRepository

    scan_id = f"s-{uuid.uuid4().hex[:8]}"
    orchestrator = ScanOrchestrator(database=services.db, settings=services.settings)
    repository = FindingRepository(services.db)

    orchestrator._persist_agent_findings(
        context=type(
            "C",
            (),
            {"scan_id": scan_id, "authorized_hosts": ["demo.test"], "targets": []},
        )(),
        role="recon",
        task_id=f"{scan_id}:recon",
        findings=[
            {
                "title": "Unauthenticated configuration disclosure",
                "summary": "The endpoint answers without a session",
                "vuln_class": "information_disclosure",
                "severity": "medium",
                "host": "",
                "path": "/rest/admin/application-configuration",
                "summary_text": "",
            }
        ],
    )

    stored = repository.list(scan_id=scan_id)
    assert len(stored) == 1
    assert stored[0]["host"] == "demo.test"


def test_a_judging_role_never_persists_a_finding(services):
    from b_hunters.platform.db.repositories import FindingRepository

    scan_id = f"s-{uuid.uuid4().hex[:8]}"
    orchestrator = ScanOrchestrator(database=services.db, settings=services.settings)
    repository = FindingRepository(services.db)

    for role in JUDGING_ROLES:
        orchestrator._persist_agent_findings(
            context=type(
                "C",
                (),
                {"scan_id": scan_id, "authorized_hosts": ["demo.test"], "targets": []},
            )(),
            role=role,
            task_id=f"{scan_id}:{role}",
            findings=[
                {
                    "title": "Missing content-security-policy header",
                    "summary": "The header is absent",
                    "vuln_class": "security_misconfiguration",
                    "severity": "low",
                    "host": "demo.test",
                    "path": "/",
                }
            ],
        )

    assert repository.list(scan_id=scan_id) == []
