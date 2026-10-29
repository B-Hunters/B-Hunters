"""Tests for the asset inventory repository.

The inventory holds one row per URL a scan saw.  The properties that
matter are the ones the merge and the console depend on: the same URL is
one row however many tools saw it, and every tool that saw it is named.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from b_hunters.platform.db.assets import AssetRepository
from b_hunters.platform.db.client import INDEXES, PLATFORM_COLLECTIONS, Database

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def database(settings):
    """A database of this test's own.

    The other agents work against the same MongoDB, so the rows of this
    test live in a database of their own and only its own collections are
    cleaned.
    """
    scoped = replace(settings, mongo_db=f"{settings.mongo_db}-assets")
    db = Database(scoped)
    if not db.ping():
        pytest.skip(f"MongoDB is not reachable at {settings.mongo_uri}")
    db.ensure_indexes()
    yield db
    db.collection("platform_assets").delete_many({})
    db.close()


@pytest.fixture(autouse=True)
def _clean(database):
    """Empty the inventory before and after every test."""
    database.collection("platform_assets").delete_many({})
    yield
    database.collection("platform_assets").delete_many({})


def test_an_asset_is_upserted_by_its_url(database):
    repo = AssetRepository(database)
    document, created = repo.upsert(
        scan_id="s1", url="https://demo.test/app.js", kind="js", source="asset_crawl"
    )
    assert created is True
    assert document["kind"] == "js"
    assert repo.upsert(scan_id="s1", url="https://demo.test/app.js", kind="js", source="katana")[1] is False


def test_a_second_source_is_added_to_the_same_row(database):
    repo = AssetRepository(database)
    repo.upsert(scan_id="s1", url="https://demo.test/app.js", kind="js", source="asset_crawl")
    document, _ = repo.upsert(scan_id="s1", url="https://demo.test/app.js", kind="js", source="katana")
    assert sorted(document["sources"]) == ["asset_crawl", "katana"]


def test_assets_are_counted_by_kind(database):
    repo = AssetRepository(database)
    repo.upsert(scan_id="s1", url="https://demo.test/", kind="page")
    repo.upsert(scan_id="s1", url="https://demo.test/a.js", kind="js")
    repo.upsert(scan_id="s1", url="https://demo.test/a.js", kind="js")
    counts = repo.counts_for_scan("s1")
    assert counts["page"] == 1
    assert counts["js"] == 1


def test_an_asset_carries_its_own_metadata(database):
    repo = AssetRepository(database)
    document, _ = repo.upsert(
        scan_id="s1",
        url="https://demo.test/logo.png",
        kind="image",
        scope="first_party",
        status_code=200,
        content_type="image/png",
        size_bytes=1234,
        depth=2,
        source="asset_crawl",
        discovered_from="https://demo.test/",
    )
    assert document["host"] == "demo.test"
    assert document["path"] == "/logo.png"
    assert document["extension"] == "png"
    assert document["status_code"] == 200
    assert document["content_type"] == "image/png"
    assert document["size_bytes"] == 1234
    assert document["depth"] == 2
    assert document["discovered_from"] == "https://demo.test/"
    assert document["asset_id"]


def test_a_second_look_fills_in_what_was_missing(database):
    """The crawler records a URL before it has fetched it."""
    repo = AssetRepository(database)
    repo.upsert(scan_id="s1", url="https://demo.test/app.js", kind="js", source="asset_crawl")
    document, _ = repo.upsert(
        scan_id="s1",
        url="https://demo.test/app.js",
        kind="js",
        status_code=200,
        content_type="application/javascript",
        size_bytes=42,
        source="asset_crawl",
    )
    assert document["status_code"] == 200
    assert document["content_type"] == "application/javascript"
    assert document["size_bytes"] == 42


def test_the_assets_of_a_scan_are_listed_by_url(database):
    repo = AssetRepository(database)
    repo.upsert(scan_id="s1", url="https://demo.test/b.js", kind="js")
    repo.upsert(scan_id="s1", url="https://demo.test/a.js", kind="js")
    repo.upsert(scan_id="s1", url="https://demo.test/logo.png", kind="image")
    repo.upsert(scan_id="s2", url="https://other.test/a.js", kind="js")
    rows = repo.list_for_scan("s1")
    assert [row["url"] for row in rows] == [
        "https://demo.test/a.js",
        "https://demo.test/b.js",
        "https://demo.test/logo.png",
    ]
    assert len(repo.list_for_scan("s1", kind="js")) == 2
    assert len(repo.list_for_scan("s1", scope="external")) == 0
    assert repo.count("s1") == 3
    assert repo.count() == 4


def test_an_asset_is_found_by_its_identifier(database):
    repo = AssetRepository(database)
    document, _ = repo.upsert(scan_id="s1", url="https://demo.test/app.js", kind="js")
    found = repo.get(document["asset_id"])
    assert found is not None
    assert found["url"] == "https://demo.test/app.js"
    assert repo.get("nothing") is None


def test_the_collection_and_its_indexes_are_registered():
    """The collection is owned by the platform and is indexed."""
    assert "platform_assets" in PLATFORM_COLLECTIONS
    assert "platform_worker_runs" in PLATFORM_COLLECTIONS
    specs = INDEXES["platform_assets"]
    keys = [tuple(spec.keys) for spec in specs]
    assert (("scan_id", 1), ("url", 1)) in keys
    assert (("scan_id", 1), ("kind", 1)) in keys
    assert (("host", 1),) in keys
    assert (("kind", 1), ("last_seen_at", -1)) in keys
    unique = [spec for spec in specs if spec.unique]
    assert len(unique) == 1
    worker_specs = INDEXES["platform_worker_runs"]
    assert (("scan_id", 1), ("worker", 1)) in [tuple(spec.keys) for spec in worker_specs]
