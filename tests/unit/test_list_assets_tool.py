"""The ``list_assets`` tool reads the real inventory.

The tool used to read a dictionary that nothing ever filled, so it
always answered that the scan had found nothing.  It now reads the
asset inventory, and it accepts both the old kind names and the new
ones.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any, cast

import pytest

from b_hunters.platform.db.assets import AssetRepository
from b_hunters.platform.db.client import Database
from b_hunters.platform.tools.builtin.scan import LIST_ASSETS_SCHEMA, list_assets
from b_hunters.platform.tools.gateway import ToolContext


@pytest.fixture(scope="module")
def database(settings):
    """A database of this test's own.

    The other agents work against the same MongoDB, so the rows of this
    test live in a database of their own and only its own collection is
    cleaned.
    """
    scoped = replace(settings, mongo_db=f"{settings.mongo_db}-list-assets")
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


def _context(database, scan_id: str) -> ToolContext:
    return ToolContext(
        scan_id=scan_id,
        task_id="task-1",
        role="recon",
        metadata={"asset_repository": AssetRepository(database), "scan_id": scan_id},
    )


def test_the_tool_lists_the_real_assets(database) -> None:
    AssetRepository(database).upsert(
        scan_id="s1", url="https://demo.test/app.js", kind="js", source="asset_crawl"
    )
    context = _context(database, "s1")
    result = list_assets("js", 100, context=context)
    assert result["count"] == 1
    assert result["assets"][0]["url"] == "https://demo.test/app.js"
    assert result["by_kind"]["js"] == 1


def test_javascript_is_an_alias_for_js(database) -> None:
    AssetRepository(database).upsert(
        scan_id="s1", url="https://demo.test/app.js", kind="js", source="asset_crawl"
    )
    context = _context(database, "s1")
    assert list_assets("javascript", 100, context=context)["count"] == 1


def test_the_old_kind_names_are_accepted(database) -> None:
    """The names the tool used before still ask for everything."""
    AssetRepository(database).upsert(
        scan_id="s1", url="https://demo.test/app.js", kind="js", source="asset_crawl"
    )
    context = _context(database, "s1")
    for kind in ("", "url", "route", "host", "technology"):
        result = list_assets(kind, 100, context=context)
        assert result["count"] == 1
        assert result["kind"] == "all"


def test_the_new_kinds_are_accepted(database) -> None:
    AssetRepository(database).upsert(scan_id="s1", url="https://demo.test/", kind="page")
    AssetRepository(database).upsert(scan_id="s1", url="https://demo.test/logo.png", kind="image")
    context = _context(database, "s1")
    assert list_assets("image", 100, context=context)["count"] == 1
    assert list_assets("page", 100, context=context)["count"] == 1
    assert list_assets("css", 100, context=context)["count"] == 0


def test_the_result_carries_the_shape_of_the_surface(database) -> None:
    AssetRepository(database).upsert(scan_id="s1", url="https://demo.test/", kind="page")
    AssetRepository(database).upsert(scan_id="s1", url="https://demo.test/app.js", kind="js")
    context = _context(database, "s1")
    result = list_assets("", 100, context=context)
    assert result["by_kind"]["page"] == 1
    assert result["by_kind"]["js"] == 1
    assert result["by_kind"]["image"] == 0
    assert result["count"] == 2


def test_a_missing_repository_returns_the_empty_result(database) -> None:
    """The tool must not raise when the inventory is not there."""
    context = ToolContext(scan_id="s1", task_id="task-1", role="recon")
    result = list_assets("js", 100, context=context)
    assert result["count"] == 0
    assert result["assets"] == []


def test_the_schema_accepts_the_old_and_the_new_kinds() -> None:
    schema = cast(dict[str, Any], LIST_ASSETS_SCHEMA)
    enum = schema["properties"]["kind"]["enum"]
    for kind in ("url", "route", "host", "technology", "javascript"):
        assert kind in enum
    for kind in ("page", "js", "image", "css", "api", "other"):
        assert kind in enum


def test_the_tool_context_carries_the_inventory(database, settings) -> None:
    """The context the orchestrator builds lets the tool read the rows."""
    from pathlib import Path

    from b_hunters.platform.agents.orchestrator import ScanContext, ScanOrchestrator, ScanProfile
    from b_hunters.platform.agents.schemas import AgentTask
    from b_hunters.platform.security.scope import ScopeEnforcer

    orchestrator = ScanOrchestrator(
        database=database,
        settings=replace(settings, mongo_db=database.settings.mongo_db),
    )
    context = ScanContext(
        scan_id="s1",
        name="tool context scan",
        targets=["https://demo.test/"],
        authorized_hosts=["demo.test"],
        profile=ScanProfile.default(),
    )
    task = AgentTask(task_id="s1:recon", scan_id="s1", role="recon", title="recon")
    tool_context = orchestrator._make_tool_context(
        context, task, ScopeEnforcer(context.scope_policy()), Path("/tmp")
    )

    assert tool_context.metadata["asset_repository"] is orchestrator.assets
    assert tool_context.metadata["scan_id"] == "s1"

    AssetRepository(database).upsert(
        scan_id="s1", url="https://demo.test/app.js", kind="js", source="asset_crawl"
    )
    result = list_assets("js", 100, context=tool_context)
    assert result["count"] == 1
