"""The inventory across every scan.

A host that was seen in two scans is one host, listed once, with its
first sighting and its last.  The platform has to be able to say what
it knows about a host, not only what one scan of it found.
"""

from __future__ import annotations

import time
import uuid

import pytest

pytestmark = pytest.mark.integration


def _host() -> str:
    """A host of the test's own.

    The shared test database keeps the assets of every run, so each
    test needs a host of its own.
    """
    return f"demo-{uuid.uuid4().hex[:6]}.test"


def _scan(services, name: str, host: str) -> str:
    scan_id = f"s-{uuid.uuid4().hex[:8]}"
    services.db.collection("platform_scans").insert_one(
        {
            "scan_id": scan_id,
            "name": name,
            "status": "completed",
            "definition": {"targets": [f"https://{host}/"]},
            "scope": {"authorized_hosts": [host]},
            "target_key": host,
            "created_at": time.time(),
            "updated_at": time.time(),
        }
    )
    return scan_id


def _asset(services, scan_id: str, path: str, host: str, kind: str = "page") -> None:
    services.db.collection("platform_assets").insert_one(
        {
            "asset_id": uuid.uuid4().hex,
            "scan_id": scan_id,
            "url": f"https://{host}{path}",
            "kind": kind,
            "host": host,
            "scope": "first_party",
            "first_seen_at": time.time(),
            "last_seen_at": time.time(),
            "created_at": time.time(),
            "updated_at": time.time(),
        }
    )


def test_a_host_seen_in_two_scans_is_listed_once(client, auth_headers, services):
    host = _host()
    first = _scan(services, "the first scan", host)
    second = _scan(services, "the second scan", host)
    _asset(services, first, "/app/", host)
    _asset(services, second, "/api/x", host)

    response = client.get("/api/v1/inventory")

    assert response.status_code == 200, response.text
    hosts = {row["host"] for row in response.json()["hosts"]}
    assert host in hosts
    rows = [row for row in response.json()["hosts"] if row["host"] == host]
    assert len(rows) == 1


def test_a_host_names_the_scans_it_was_seen_in(client, auth_headers, services):
    host = _host()
    first = _scan(services, "the first scan", host)
    second = _scan(services, "the second scan", host)
    _asset(services, first, "/app/", host)
    _asset(services, second, "/api/x", host)

    response = client.get("/api/v1/inventory")

    rows = [row for row in response.json()["hosts"] if row["host"] == host]
    assert rows
    assert set(rows[0]["scans"]) == {first, second}


def test_a_host_names_its_urls(client, auth_headers, services):
    host = _host()
    scan_id = _scan(services, "the scan", host)
    _asset(services, scan_id, "/app/", host)
    _asset(services, scan_id, "/api/x", host)

    response = client.get("/api/v1/inventory")

    rows = [row for row in response.json()["hosts"] if row["host"] == host]
    assert rows
    assert len(rows[0]["urls"]) == 2


def test_the_inventory_can_be_filtered_by_host(client, auth_headers, services):
    host = _host()
    scan_id = _scan(services, "the scan", host)
    _asset(services, scan_id, "/app/", host)

    response = client.get("/api/v1/inventory", params={"host": host})

    assert response.status_code == 200, response.text
    assert [row["host"] for row in response.json()["hosts"]] == [host]


def test_the_inventory_can_be_filtered_by_kind(client, auth_headers, services):
    host = _host()
    scan_id = _scan(services, "the scan", host)
    _asset(services, scan_id, "/app.js", host, kind="js")
    _asset(services, scan_id, "/app/", host, kind="page")

    response = client.get("/api/v1/inventory", params={"kind": "js", "host": host})

    assert response.status_code == 200, response.text
    rows = response.json()["hosts"]
    assert [row["host"] for row in rows] == [host]
    assert len(rows[0]["urls"]) == 1


def test_the_inventory_needs_a_login(client):
    response = client.get("/api/v1/inventory")

    assert response.status_code in (401, 403)
