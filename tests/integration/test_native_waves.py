"""The native adapters run in two waves.

The crawler seeds itself from the URLs the fingerprinters recorded, so it
must run after them.  A scan that runs them at the same time starts the
crawler with nothing to crawl.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from b_hunters.platform.agents.orchestrator import ScanContext, ScanOrchestrator, ScanProfile
from b_hunters.platform.db.client import Database
from b_hunters.platform.db.repositories import ScanRepository
from b_hunters.platform.scanners.base import ScanResult
from b_hunters.platform.scanners.registry import build_default_registry
from b_hunters.platform.settings import Settings, load_settings

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def database(settings):
    """A database of this test's own.

    The other agents work against the same MongoDB, so the rows of this
    test live in a database of their own.
    """
    scoped = replace(settings, mongo_db=f"{settings.mongo_db}-waves")
    db = Database(scoped)
    if not db.ping():
        pytest.skip(f"MongoDB is not reachable at {settings.mongo_uri}")
    db.ensure_indexes()
    yield db
    db.close()


class Recorder:
    """An adapter that records the order it runs in."""

    def __init__(self, name: str, order: list[str]) -> None:
        self.name = name
        self.kind = "native"
        self._order = order

    async def execute(self, request):
        self._order.append(self.name)
        return ScanResult(scanner=self.name, items=[])


def _profile() -> ScanProfile:
    profile = ScanProfile.default()
    profile.scanners = ["service_fingerprint", "asset_crawl"]
    profile.agent_roles = []
    return profile


def _context(scan_id: str) -> ScanContext:
    return ScanContext(
        scan_id=scan_id,
        name="wave scan",
        targets=["https://demo.test/"],
        authorized_hosts=["demo.test"],
        profile=_profile(),
        max_duration_seconds=60,
        workspace_root="/tmp/b-hunters-waves",
    )


@pytest.mark.asyncio
async def test_the_asset_crawl_runs_after_the_fingerprinters(database, settings) -> None:
    order: list[str] = []
    registry = build_default_registry(
        {
            "asset_crawl": Recorder("asset_crawl", order).execute,
            "service_fingerprint": Recorder("service_fingerprint", order).execute,
        }
    )
    scan = ScanRepository(database).create(
        {
            "name": "wave scan",
            "status": "queued",
            "created_by": "test",
            "definition": {"targets": ["https://demo.test/"]},
            "scope": {"authorized_hosts": ["demo.test"]},
        }
    )
    orchestrator = ScanOrchestrator(
        database=database,
        settings=replace(settings, mongo_db=database.settings.mongo_db),
        scanner_registry=registry,
    )
    result = await orchestrator.run(_context(scan.scan_id))

    assert result["status"] == "completed"
    assert order == ["service_fingerprint", "asset_crawl"]


def test_the_crawler_is_part_of_the_standard_profile() -> None:
    """Every scan crawls the target unless the operator removes it."""
    assert "asset_crawl" in ScanProfile.default().scanners


def test_the_crawler_is_registered_with_its_executor(database, settings) -> None:
    """The orchestrator the platform builds can really crawl."""
    from b_hunters.platform.agents.factory import build_orchestrator
    from b_hunters.platform.api.deps import Services

    services = Services(database, replace(settings, mongo_db=database.settings.mongo_db))
    orchestrator = build_orchestrator(services)
    adapter = orchestrator.scanner_registry.get("asset_crawl")
    assert adapter is not None
    assert adapter.spec.kind == "native"
    assert getattr(adapter, "_executor", None) is not None


def test_the_phase_shares_come_from_the_settings() -> None:
    """The worker phase takes the share the deployment configures."""
    # The share is even by default: the measurement gave the workers
    # ten minutes and seven findings, and the agent roles three minutes
    # each and the interesting ones.
    assert Settings().worker_phase_share == 0.5
    assert load_settings(overrides={"worker_phase_share": 0.9}).worker_phase_share == 0.9
    assert load_settings(overrides={"worker_phase_share": 0.9}).worker_phase_share != 0.5

    from b_hunters.platform.agents import orchestrator as orchestrator_module

    # The share is configured, not compiled in.
    assert not hasattr(orchestrator_module, "WORKER_PHASE_SHARE")
    assert not hasattr(orchestrator_module, "AGENT_PHASE_SHARE")
