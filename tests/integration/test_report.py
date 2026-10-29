"""The report of a scan.

The report is more than the findings: it carries the assets the scan
saw, the tools that took part in it, the outcome of every agent role
and the verdict of the error ledger - so that it can be sent to
somebody who was not there.
"""

from __future__ import annotations

import time
from dataclasses import replace

import pytest

from b_hunters.platform.api.deps import Services, set_services
from b_hunters.platform.db.assets import AssetRepository
from b_hunters.platform.db.client import Database

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def database(settings):
    """A database of this test's own.

    The other agents work against the same MongoDB, so the rows of this
    test live in a database of their own and only its own collections are
    cleaned.
    """
    scoped = replace(settings, mongo_db=f"{settings.mongo_db}-report")
    db = Database(scoped)
    if not db.ping():
        pytest.skip(f"MongoDB is not reachable at {settings.mongo_uri}")
    db.ensure_indexes()
    yield db
    for name in (
        "platform_scans",
        "platform_tasks",
        "platform_messages",
        "platform_tool_calls",
        "platform_findings",
        "platform_scan_events",
        "platform_assets",
    ):
        db.collection(name).delete_many({})
    db.close()


@pytest.fixture
def services(database, settings):
    """The service container of this test's own database."""
    container = Services(database, replace(settings, mongo_db=database.settings.mongo_db))
    set_services(container)
    yield container
    set_services(None)


def _scan(client, csrf):
    payload = {
        "name": f"report scan {int(time.time() * 1000)}",
        "targets": {
            "urls": ["https://demo.test/"],
            "authorized_hosts": ["demo.test"],
            "excluded_paths": [],
        },
        "profile": "standard",
        "scanners": [],
        "agent_roles": [],
        "test_accounts": [],
    }
    response = client.post("/api/v1/scans", json=payload, headers={"X-CSRF-Token": csrf})
    assert response.status_code == 201, response.text
    return response.json()["scan_id"]


def _report(client, csrf, scan_id, query=""):
    response = client.get(f"/api/v1/scans/{scan_id}/report{query}", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200, response.text
    return response


def _agent_task(services, scan_id, role, *, status="succeeded", result=None):
    task_id = f"{scan_id}:{role}"
    services.tasks.upsert(
        scan_id=scan_id,
        task_id=task_id,
        title=f"{role} task",
        kind="agent",
        agent_role=role,
    )
    services.tasks.set_status(task_id, status, result=result)


def _chromium_available() -> bool:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return False
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            browser.close()
    except Exception:
        return False
    return True


# ----------------------------------------------------------------------
# The HTML report
# ----------------------------------------------------------------------
def test_the_html_report_carries_the_assets_and_the_participation(client, csrf, services) -> None:
    scan_id = _scan(client, csrf)
    AssetRepository(services.db).upsert(
        scan_id=scan_id,
        url="https://demo.test/app.js",
        kind="js",
        source="asset_crawl",
    )

    response = _report(client, csrf, scan_id, "?format=html")

    assert "app.js" in response.text
    assert "participation" in response.text.lower()


def test_the_html_report_carries_the_outcome_of_every_role(client, csrf, services) -> None:
    scan_id = _scan(client, csrf)
    _agent_task(
        services,
        scan_id,
        "recon",
        result={
            "role": "recon",
            "status": "succeeded",
            "stop_reason": "completed",
            "conclusion": "the target runs WordPress",
        },
    )

    response = _report(client, csrf, scan_id, "?format=html")

    assert "recon" in response.text
    assert "completed" in response.text


def test_the_html_report_carries_the_transcript(client, csrf, services) -> None:
    scan_id = _scan(client, csrf)
    services.messages.append(
        {
            "scan_id": scan_id,
            "task_id": f"{scan_id}:recon",
            "sender_role": "recon",
            "kind": "observation",
            "hypothesis": "the target answers with a login form",
            "at": time.time(),
        }
    )

    response = _report(client, csrf, scan_id, "?format=html")

    assert "the target answers with a login form" in response.text
    assert "/transcript" in response.text


def test_the_html_report_carries_the_verdict(client, csrf, services) -> None:
    scan_id = _scan(client, csrf)

    response = _report(client, csrf, scan_id, "?format=html")

    assert "Integrity" in response.text
    assert "pass" in response.text


# ----------------------------------------------------------------------
# The JSON report
# ----------------------------------------------------------------------
def test_the_json_report_carries_the_new_collections(client, csrf, services) -> None:
    scan_id = _scan(client, csrf)
    AssetRepository(services.db).upsert(
        scan_id=scan_id,
        url="https://demo.test/app.js",
        kind="js",
        source="asset_crawl",
    )

    response = _report(client, csrf, scan_id, "?format=json")

    payload = response.json()
    assert payload["assets"]
    assert payload["assets"][0]["url"] == "https://demo.test/app.js"
    assert payload["participation"]["workers"]
    assert payload["agents"]["built_in_roles"] == 13
    assert payload["integrity"]["verdict"] in ("pass", "fail")


def test_the_sarif_report_is_unchanged(client, csrf, services) -> None:
    scan_id = _scan(client, csrf)

    response = _report(client, csrf, scan_id, "?format=sarif")

    payload = response.json()
    assert payload["version"] == "2.1.0"
    assert "assets" not in payload
    assert "participation" not in payload


def test_the_report_of_an_unknown_scan_is_a_404(client, csrf) -> None:
    response = client.get("/api/v1/scans/does-not-exist/report", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 404


def test_the_report_needs_a_session(client) -> None:
    response = client.get("/api/v1/scans/whatever/report")
    assert response.status_code == 401


# ----------------------------------------------------------------------
# The PDF report
# ----------------------------------------------------------------------
@pytest.mark.skipif(not _chromium_available(), reason="no Chromium on this machine")
def test_the_report_is_printed_as_a_pdf(client, csrf, services) -> None:
    scan_id = _scan(client, csrf)

    response = client.get(f"/api/v1/scans/{scan_id}/report.pdf", headers={"X-CSRF-Token": csrf})

    assert response.status_code == 200, response.text
    assert response.headers["content-type"] == "application/pdf"
    assert response.content[:5] == b"%PDF-"


@pytest.mark.skipif(not _chromium_available(), reason="no Chromium on this machine")
def test_the_pdf_of_an_unknown_scan_is_a_404(client, csrf) -> None:
    response = client.get("/api/v1/scans/does-not-exist/report.pdf", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 404


def test_the_pdf_needs_a_session(client) -> None:
    response = client.get("/api/v1/scans/whatever/report.pdf")
    assert response.status_code == 401
