"""The scan names the hosts it must not touch, and the API keeps them.

A bug bounty programme names the assets that are out of scope.  The
wildcard that covers the domain covers them too, so the exclusions have
to be said separately - and they have to survive the round trip through
the API, or a scan of a real programme would touch a host the
programme says not to touch.
"""

from __future__ import annotations

import time

import pytest

pytestmark = pytest.mark.integration

#: The exclusions of a real programme: the hosts a wildcard covers but
#: the programme names as out of scope.
EXCLUDED = [
    "community.example.net",
    "support.example.net",
    "docs.example.net",
    "sandbox.example.net",
]


def _payload(**overrides):
    targets = {
        "urls": ["https://www.example.net/"],
        "authorized_hosts": ["*.example.net"],
        "excluded_paths": [],
        "denied_hosts": list(EXCLUDED),
    }
    targets.update(overrides.pop("targets", {}))
    body = {
        "name": f"scope integration scan {int(time.time() * 1000)}",
        "targets": targets,
        "profile": "standard",
        "scanners": ["security_headers"],
        "agent_roles": ["recon"],
        "max_concurrency": 2,
        "max_requests_per_second": 5,
        "request_timeout": 10,
        "max_duration_seconds": 120,
        "safe_mode": True,
        "allow_state_changing": False,
        "test_environment": False,
        "test_accounts": [],
    }
    body.update(overrides)
    return body


def test_the_scan_keeps_the_exclusions(client, admin_user) -> None:
    client.post(
        "/api/v1/auth/login",
        json={"username": admin_user["username"], "password": admin_user["password"]},
    )
    csrf = client.get("/api/v1/auth/me").json()["csrf_token"]

    response = client.post("/api/v1/scans", json=_payload(), headers={"X-CSRF-Token": csrf})

    assert response.status_code == 201, response.text
    scope = response.json()["scope"]
    assert scope["authorized_hosts"] == ["*.example.net"]
    assert scope["denied_hosts"] == EXCLUDED


def test_a_target_that_is_excluded_is_out_of_scope(client, admin_user) -> None:
    """The platform refuses to scan a host the scan excludes."""
    client.post(
        "/api/v1/auth/login",
        json={"username": admin_user["username"], "password": admin_user["password"]},
    )
    csrf = client.get("/api/v1/auth/me").json()["csrf_token"]

    response = client.post(
        "/api/v1/scans",
        json=_payload(targets={"urls": ["https://support.example.net/"]}),
        headers={"X-CSRF-Token": csrf},
    )

    assert response.status_code == 400, response.text
    detail = response.json()["detail"]
    assert detail["out_of_scope"]
    assert "support.example.net" in str(detail["out_of_scope"])


def test_a_scan_without_exclusions_is_accepted(client, admin_user) -> None:
    """The feature is optional: a scan with no exclusions still works."""
    client.post(
        "/api/v1/auth/login",
        json={"username": admin_user["username"], "password": admin_user["password"]},
    )
    csrf = client.get("/api/v1/auth/me").json()["csrf_token"]

    response = client.post(
        "/api/v1/scans",
        json=_payload(targets={"denied_hosts": []}),
        headers={"X-CSRF-Token": csrf},
    )

    assert response.status_code == 201, response.text
    assert response.json()["scope"]["denied_hosts"] == []
