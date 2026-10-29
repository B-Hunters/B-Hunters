"""The merge of what the workers found into the asset inventory.

The inventory is fed by three sources: the crawler, the scanner workers
and the fingerprinters.  A URL that two of them saw is one row that names
both, and a path a worker found is a URL of the target it was found on.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from b_hunters.platform.agents.orchestrator import ScanContext, ScanOrchestrator, ScanProfile
from b_hunters.platform.db.assets import AssetRepository
from b_hunters.platform.db.client import Database
from b_hunters.platform.db.repositories import ScanRepository
from b_hunters.platform.db.worker_output_repository import WorkerOutputRepository

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def database(settings):
    """A database of this test's own.

    The other agents work against the same MongoDB, so the rows of this
    test live in a database of their own and only its own collections are
    cleaned.
    """
    scoped = replace(settings, mongo_db=f"{settings.mongo_db}-merge")
    db = Database(scoped)
    if not db.ping():
        pytest.skip(f"MongoDB is not reachable at {settings.mongo_uri}")
    db.ensure_indexes()
    yield db
    db.collection("platform_assets").delete_many({})
    db.collection("platform_worker_output").delete_many({})
    db.collection("platform_services").delete_many({})
    db.collection("platform_scan_events").delete_many({})
    db.close()


@pytest.fixture(autouse=True)
def _clean(database):
    """Empty the collections of this test before and after every test."""
    for name in ("platform_assets", "platform_worker_output", "platform_services"):
        database.collection(name).delete_many({})
    yield
    for name in ("platform_assets", "platform_worker_output", "platform_services"):
        database.collection(name).delete_many({})


def _scan(database) -> str:
    record = ScanRepository(database).create(
        {
            "name": "merge scan",
            "status": "queued",
            "created_by": "test",
            "definition": {"targets": ["https://demo.test/"]},
            "scope": {"authorized_hosts": ["demo.test"]},
        }
    )
    return record.scan_id


def _orchestrator(database, settings) -> ScanOrchestrator:
    return ScanOrchestrator(
        database=database,
        settings=replace(settings, mongo_db=database.settings.mongo_db),
    )


def _context(scan_id: str) -> ScanContext:
    profile = ScanProfile.default()
    profile.agent_roles = []
    return ScanContext(
        scan_id=scan_id,
        name="merge scan",
        targets=["https://demo.test/"],
        authorized_hosts=["demo.test"],
        profile=profile,
        max_duration_seconds=60,
        workspace_root="/tmp/b-hunters-merge",
    )


def test_one_url_seen_by_two_tools_is_one_row(database, settings) -> None:
    scan_id = _scan(database)
    WorkerOutputRepository(database).replace_for_scan(
        scan_id,
        [{"worker": "B-Hunters-Katana", "kind": "url", "value": "https://demo.test/app.js"}],
    )
    AssetRepository(database).upsert(
        scan_id=scan_id, url="https://demo.test/app.js", kind="js", source="asset_crawl"
    )
    orchestrator = _orchestrator(database, settings)
    orchestrator._merge_assets(_context(scan_id), "https://demo.test/")

    rows = AssetRepository(database).list_for_scan(scan_id)
    assert len(rows) == 1
    assert sorted(rows[0]["sources"]) == ["B-Hunters-Katana", "asset_crawl"]


def test_a_worker_path_is_resolved_against_the_target(database, settings) -> None:
    scan_id = _scan(database)
    WorkerOutputRepository(database).replace_for_scan(
        scan_id,
        [{"worker": "B-Hunters-dirsearch", "kind": "path", "value": "/admin"}],
    )
    orchestrator = _orchestrator(database, settings)
    orchestrator._merge_assets(_context(scan_id), "https://demo.test/")

    rows = AssetRepository(database).list_for_scan(scan_id)
    assert rows[0]["url"] == "https://demo.test/admin"
    assert rows[0]["status_code"] == 0


def test_a_javascript_file_from_the_jsscanner_is_classified_as_js(database, settings) -> None:
    scan_id = _scan(database)
    WorkerOutputRepository(database).replace_for_scan(
        scan_id,
        [{"worker": "B-Hunters-jsscanner", "kind": "item", "value": "https://demo.test/vendor/lib.js"}],
    )
    orchestrator = _orchestrator(database, settings)
    orchestrator._merge_assets(_context(scan_id), "https://demo.test/")

    rows = AssetRepository(database).list_for_scan(scan_id)
    assert rows[0]["kind"] == "js"


def test_a_fingerprinted_url_is_added_to_the_inventory(database, settings) -> None:
    scan_id = _scan(database)
    database.collection("platform_services").insert_one(
        {
            "scan_id": scan_id,
            "url": "https://demo.test/",
            "host": "demo.test",
            "status_code": 200,
            "services": [{"name": "nginx"}],
            "detector": "service_fingerprint",
        }
    )
    orchestrator = _orchestrator(database, settings)
    counts = orchestrator._merge_assets(_context(scan_id), "https://demo.test/")

    rows = AssetRepository(database).list_for_scan(scan_id)
    assert rows[0]["url"] == "https://demo.test/"
    assert rows[0]["sources"] == ["service_fingerprint"]
    assert counts["from_services"] == 1
    assert counts["assets"] == 1


def test_the_merge_counts_what_it_merged_and_says_so(database, settings) -> None:
    scan_id = _scan(database)
    WorkerOutputRepository(database).replace_for_scan(
        scan_id,
        [
            {"worker": "B-Hunters-Katana", "kind": "url", "value": "https://demo.test/app.js"},
            {"worker": "B-Hunters-dirsearch", "kind": "path", "value": "/admin"},
        ],
    )
    orchestrator = _orchestrator(database, settings)
    counts = orchestrator._merge_assets(_context(scan_id), "https://demo.test/")

    assert counts["from_workers"] == 2
    assert counts["assets"] == 2

    events = list(database.collection("platform_scan_events").find({"scan_id": scan_id}))
    merged = [event for event in events if event.get("kind") == "assets.merged"]
    assert merged
    assert merged[0]["payload"]["from_workers"] == 2


def test_a_relative_worker_url_is_resolved_against_the_target(database, settings) -> None:
    scan_id = _scan(database)
    WorkerOutputRepository(database).replace_for_scan(
        scan_id,
        [{"worker": "B-Hunters-Katana", "kind": "url", "value": "/static/app.css"}],
    )
    orchestrator = _orchestrator(database, settings)
    orchestrator._merge_assets(_context(scan_id), "https://demo.test/")

    rows = AssetRepository(database).list_for_scan(scan_id)
    assert rows[0]["url"] == "https://demo.test/static/app.css"
    assert rows[0]["kind"] == "css"


@pytest.mark.asyncio
async def test_the_crawlers_rows_are_part_of_the_inventory(database, settings) -> None:
    """The rows the crawler wrote are the third source of the merge."""
    from b_hunters.platform.scanners.base import ScanResult
    from b_hunters.platform.scanners.registry import build_default_registry
    from b_hunters.platform.security.scope import ScopeEnforcer

    scan_id = _scan(database)

    class Crawler:
        async def execute(self, request):
            return ScanResult(
                scanner="asset_crawl",
                kind="url",
                items=[
                    {
                        "value": "https://demo.test/app.js",
                        "kind": "js",
                        "scope": "first_party",
                        "status_code": 200,
                        "content_type": "application/javascript",
                        "size_bytes": 12,
                        "depth": 1,
                        "discovered_from": "https://demo.test/",
                    }
                ],
            )

    registry = build_default_registry({"asset_crawl": Crawler().execute})
    orchestrator = ScanOrchestrator(
        database=database,
        settings=replace(settings, mongo_db=database.settings.mongo_db),
        scanner_registry=registry,
    )
    context = _context(scan_id)
    context.profile.scanners = ["asset_crawl"]
    await orchestrator._dispatch_scanners(context, ScopeEnforcer(context.scope_policy()))

    rows = AssetRepository(database).list_for_scan(scan_id)
    assert len(rows) == 1
    assert rows[0]["url"] == "https://demo.test/app.js"
    assert rows[0]["sources"] == ["asset_crawl"]
    assert rows[0]["status_code"] == 200
    assert rows[0]["content_type"] == "application/javascript"

    # The worker that saw the same URL joins the row of the crawler.
    WorkerOutputRepository(database).replace_for_scan(
        scan_id,
        [{"worker": "B-Hunters-Katana", "kind": "url", "value": "https://demo.test/app.js"}],
    )
    counts = orchestrator._merge_assets(context, "https://demo.test/")
    rows = AssetRepository(database).list_for_scan(scan_id)
    assert len(rows) == 1
    assert sorted(rows[0]["sources"]) == ["B-Hunters-Katana", "asset_crawl"]
    assert counts["assets"] == 1
