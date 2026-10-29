"""The profile of a scan has to survive the round trip.

The scan document holds the profile, and the runner rebuilds the scan
from it.  A profile that is not stored is not restored: the scanner
list, the agent roles, the concurrency and the limits the operator chose
would all be lost, and every scan would run the default plan whatever
the scan form said.
"""

from __future__ import annotations

import pytest

from b_hunters.platform.agents.orchestrator import ScanProfile

pytestmark = pytest.mark.integration


def _scan_payload(**overrides):
    payload = {
        "name": "profile scan",
        "targets": {
            "urls": ["https://demo.test/"],
            "authorized_hosts": ["demo.test"],
            "excluded_paths": [],
        },
        "profile": "standard",
        "scanners": ["security_headers", "asset_crawl"],
        "agent_roles": ["recon"],
        "max_concurrency": 2,
        "max_requests_per_second": 5,
        "request_timeout": 15,
        "max_duration_seconds": 240,
        "safe_mode": True,
        "allow_state_changing": False,
        "test_environment": False,
        "test_accounts": [],
    }
    payload.update(overrides)
    return payload


def test_the_profile_survives_the_round_trip():
    profile = ScanProfile.default()
    profile.agent_roles = ["recon"]
    profile.scanners = ["security_headers"]
    profile.max_concurrency = 2

    restored = ScanProfile.from_dict(profile.to_dict())

    assert restored.agent_roles == ["recon"]
    assert restored.scanners == ["security_headers"]
    assert restored.max_concurrency == 2


def test_an_empty_role_list_is_authoritative():
    profile = ScanProfile.default()
    profile.agent_roles = []

    restored = ScanProfile.from_dict(profile.to_dict())

    assert restored.agent_roles == []


def test_the_stored_profile_holds_what_the_operator_chose(client, csrf, services):
    response = client.post(
        "/api/v1/scans",
        json=_scan_payload(),
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 201, response.text
    scan_id = response.json()["scan_id"]

    stored = services.scans.get(scan_id)
    # The reporting role is always added: it reconciles the findings
    # and records a verdict for each of them.
    assert stored.definition["profile"]["agent_roles"] == ["recon", "adjudicator"]
    assert stored.definition["profile"]["scanners"] == ["security_headers", "asset_crawl"]
    assert stored.definition["profile"]["max_concurrency"] == 2


def test_the_runner_rebuilds_the_profile_the_operator_chose(client, csrf, services):
    from b_hunters.platform.agents.factory import build_scan_context

    client.post("/api/v1/scans", json=_scan_payload(), headers={"X-CSRF-Token": csrf})
    scan = services.scans.list()[0]

    context = build_scan_context(scan, services.settings)

    assert context.profile.agent_roles == ["recon", "adjudicator"]
    assert context.profile.scanners == ["security_headers", "asset_crawl"]
    assert context.profile.max_concurrency == 2


def test_a_reconnaissance_scan_keeps_its_own_plan(client, csrf, services):
    client.post(
        "/api/v1/scans",
        json=_scan_payload(profile="recon", agent_roles=["recon", "javascript"], scanners=[]),
        headers={"X-CSRF-Token": csrf},
    )
    scan = services.scans.list()[0]

    from b_hunters.platform.agents.factory import build_scan_context

    context = build_scan_context(scan, services.settings)

    assert context.profile.name == "recon"
    # The reconnaissance profile is reconnaissance only: the
    # vulnerability roles must not come back from the default.
    assert "vuln_injection" not in context.profile.agent_roles
    assert context.profile.agent_roles == ["recon", "javascript", "adjudicator"]
    # An empty scanner list means "the scanners of this profile": the
    # operator chose none, and the profile's own list applies.
    assert context.profile.scanners == ScanProfile.reconnaissance_only().scanners
