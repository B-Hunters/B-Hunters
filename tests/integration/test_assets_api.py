"""The asset inventory endpoint."""

from __future__ import annotations

import pytest

from b_hunters.platform.db.assets import AssetRepository

pytestmark = pytest.mark.integration


def _scan(client, csrf):
    response = client.post(
        "/api/v1/scans",
        json={
            "name": "asset scan",
            "targets": {
                "urls": ["https://demo.test/"],
                "authorized_hosts": ["demo.test"],
                "excluded_paths": [],
            },
            "profile": "standard",
            "scanners": [],
            "agent_roles": [],
            "test_accounts": [],
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 201, response.text
    return response.json()["scan_id"]


def test_the_assets_of_a_scan_are_served(client, csrf, services):
    scan_id = _scan(client, csrf)
    AssetRepository(services.db).upsert(
        scan_id=scan_id,
        url="https://demo.test/app.js",
        kind="js",
        source="asset_crawl",
        content_type="application/javascript",
        size_bytes=900,
    )

    response = client.get(f"/api/v1/scans/{scan_id}/assets", headers={"X-CSRF-Token": csrf})

    assert response.status_code == 200
    payload = response.json()
    assert payload["count"] == 1
    assert payload["items"][0]["url"] == "https://demo.test/app.js"
    assert payload["counts"]["js"] == 1


def test_the_inventory_can_be_filtered_by_kind(client, csrf, services):
    scan_id = _scan(client, csrf)
    repository = AssetRepository(services.db)
    repository.upsert(scan_id=scan_id, url="https://demo.test/app.js", kind="js", source="asset_crawl")
    repository.upsert(scan_id=scan_id, url="https://demo.test/logo.png", kind="image", source="asset_crawl")

    response = client.get(f"/api/v1/scans/{scan_id}/assets?kind=js", headers={"X-CSRF-Token": csrf})

    assert response.status_code == 200
    payload = response.json()
    assert payload["count"] == 1
    assert payload["items"][0]["kind"] == "js"
    # The counts always describe the whole inventory, not the filter.
    assert payload["counts"]["image"] == 1


def test_the_inventory_of_an_unknown_scan_is_a_404(client, csrf):
    response = client.get("/api/v1/scans/does-not-exist/assets", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 404


def test_the_inventory_needs_a_session(client):
    response = client.get("/api/v1/scans/whatever/assets")
    assert response.status_code == 401
