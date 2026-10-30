"""The diff endpoint."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration


def _scan(client, csrf, name: str, target: str = "https://demo.test/"):
    response = client.post(
        "/api/v1/scans",
        json={
            "name": name,
            "targets": {
                "urls": [target],
                "authorized_hosts": ["demo.test"],
                "excluded_paths": [],
            },
            "profile": "standard",
            "scanners": ["security_headers"],
            "agent_roles": ["recon"],
            "test_accounts": [],
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 201, response.text
    return response.json()["scan_id"]


def test_a_scan_without_an_earlier_one_says_so(client, csrf, services):
    scan_id = _scan(client, csrf, "the only scan")

    response = client.get(f"/api/v1/scans/{scan_id}/diff", headers={"X-CSRF-Token": csrf})

    assert response.status_code == 200
    payload = response.json()
    # There may be another scan of the same target in the shared test
    # database; either way the diff must not claim a difference it has
    # not established.
    assert payload["comparable"] is False
    assert payload["new"] == []
    assert payload["reason"]


def test_two_scans_are_compared_when_they_asked_the_same_question(client, csrf, services):
    first = _scan(client, csrf, "the first scan")
    second = _scan(client, csrf, "the second scan")
    services.scans.update(first, {"status": "completed", "phase": "completed"})
    services.scans.update(second, {"status": "completed", "phase": "completed"})

    response = client.get(f"/api/v1/scans/{second}/diff?against={first}", headers={"X-CSRF-Token": csrf})

    assert response.status_code == 200
    payload = response.json()
    assert payload["comparable"] is True
    assert payload["against"] == first
    assert "counts" in payload


def test_the_diff_of_an_unknown_scan_is_a_404(client, csrf):
    response = client.get("/api/v1/scans/does-not-exist/diff", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 404
