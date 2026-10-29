"""What every worker did in a scan.

The participation table says *why* a tool did not report.  The facts
behind that table are recorded while the scan runs: which workers were
online when it started, how many tasks each of them consumed, how many
findings it produced and how many of its tasks crashed.

A worker that consumed a task and crashed must be told apart from one
that consumed a task and found nothing - the first errored, the second
ran.  The facts are recorded here; the table that reads them is built
by the participation endpoint.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from b_hunters.platform.agents.orchestrator import ScanContext, ScanOrchestrator, ScanProfile
from b_hunters.platform.api.deps import Services
from b_hunters.platform.db.client import Database
from b_hunters.platform.db.repositories import ScanRepository
from b_hunters.platform.scanners.karton_bridge import KartonWorkerBridge, WorkerResults, WorkerTarget

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def database(settings):
    """A database of this test's own.

    The other agents work against the same MongoDB, so the rows of this
    test live in a database of their own and only its own collections are
    cleaned.
    """
    scoped = replace(settings, mongo_db=f"{settings.mongo_db}-workerruns")
    db = Database(scoped)
    if not db.ping():
        pytest.skip(f"MongoDB is not reachable at {settings.mongo_uri}")
    db.ensure_indexes()
    yield db
    db.collection("platform_worker_runs").delete_many({})
    db.collection("platform_scans").delete_many({})
    db.close()


@pytest.fixture
def services(database, settings):
    """The service container of this test's own database."""
    return Services(database, replace(settings, mongo_db=database.settings.mongo_db))


@pytest.fixture(autouse=True)
def _clean(database):
    """Empty the collection of this test before and after every test."""
    database.collection("platform_worker_runs").delete_many({})
    yield
    database.collection("platform_worker_runs").delete_many({})


# ----------------------------------------------------------------------
# Fakes
# ----------------------------------------------------------------------
class FakeRedis:
    """The part of the Karton Redis the bridge reads."""

    def __init__(self, consumed: dict[str, int] | None = None) -> None:
        self.consumed = dict(consumed or {})

    def hgetall(self, name: str) -> dict[bytes, bytes]:
        if name != "karton.metrics.consumed":
            return {}
        return {key.encode(): str(value).encode() for key, value in self.consumed.items()}


class FakeTask:
    """A task of the Karton analysis tree."""

    def __init__(self, receiver: str, crashed: bool = True) -> None:
        from karton.core.task import TaskState

        self.headers = {"receiver": receiver}
        self.status = TaskState.CRASHED if crashed else TaskState.FINISHED


class FakeBackend:
    """The part of the Karton backend the bridge reads."""

    def __init__(
        self,
        *,
        identities: tuple[str, ...] = (),
        consumed: dict[str, int] | None = None,
        crashed: list[Any] | None = None,
        unreachable: bool = False,
    ) -> None:
        self.identities = {name: [] for name in identities}
        self.crashed = list(crashed or [])
        self.unreachable = unreachable
        self.redis = FakeRedis(consumed)

    def get_online_consumers(self) -> dict[str, list[Any]]:
        if self.unreachable:
            raise RuntimeError("the Karton backend is not reachable")
        return dict(self.identities)

    def get_binds(self) -> list[Any]:
        return []

    def iter_task_tree(self, root_uid: str, parse_resources: bool = False) -> list[Any]:
        return list(self.crashed)


class FakeProducer:
    """The producer the bridge publishes its tasks through."""

    def __init__(self, backend: FakeBackend) -> None:
        self.backend = backend
        self.tasks: list[Any] = []

    def send_task(self, task: Any) -> None:
        self.tasks.append(task)


class FakeCollection:
    """A collection of the legacy documents."""

    def __init__(self, documents: list[dict[str, Any]] | None = None) -> None:
        self.documents = list(documents or [])

    def insert_one(self, document: dict[str, Any]) -> Any:
        self.documents.append(document)
        return type("Result", (), {"inserted_id": document.get("_id")})()

    def find_one(self, query: dict[str, Any]) -> dict[str, Any] | None:
        for document in self.documents:
            if all(document.get(key) == value for key, value in query.items()):
                return document
        return None


class FakeDatabase:
    """The legacy documents the bridge reads back."""

    def __init__(self, documents: dict[str, list[dict[str, Any]]] | None = None) -> None:
        self.collections = {name: FakeCollection(rows) for name, rows in (documents or {}).items()}

    def collection(self, name: str) -> FakeCollection:
        return self.collections.setdefault(name, FakeCollection())


# ----------------------------------------------------------------------
# The repository
# ----------------------------------------------------------------------
def test_a_crashed_worker_is_reported_as_errored(services) -> None:
    repo = services.worker_runs
    repo.record(
        scan_id="s1",
        worker="B-Hunters-Nuclei",
        tasks=2,
        findings=1,
        crashed_tasks=1,
        connected=True,
    )

    rows = repo.list_for_scan("s1")

    assert len(rows) == 1
    assert rows[0]["crashed_tasks"] == 1
    assert rows[0]["tasks"] == 2
    assert rows[0]["findings"] == 1
    assert rows[0]["connected"] is True


def test_a_worker_is_recorded_once_per_scan(services) -> None:
    repo = services.worker_runs
    repo.record(scan_id="s1", worker="B-Hunters-Nuclei", tasks=1)
    repo.record(scan_id="s1", worker="B-Hunters-Nuclei", tasks=3)

    rows = repo.list_for_scan("s1")

    assert len(rows) == 1
    assert rows[0]["tasks"] == 3


def test_a_worker_that_was_online_but_never_dispatched_is_recorded(services) -> None:
    repo = services.worker_runs
    repo.snapshot_connection("s1", ["B-Hunters-Katana", "B-Hunters-Nuclei"])

    rows = repo.list_for_scan("s1")

    assert [row["worker"] for row in rows] == ["B-Hunters-Katana", "B-Hunters-Nuclei"]
    assert all(row["connected"] is True for row in rows)
    assert all(row["tasks"] == 0 for row in rows)


def test_the_snapshot_keeps_what_a_worker_did(services) -> None:
    """A snapshot taken after the work does not wipe the work."""
    repo = services.worker_runs
    repo.record(scan_id="s1", worker="B-Hunters-Katana", tasks=4, findings=2)

    repo.snapshot_connection("s1", ["B-Hunters-Katana"])

    rows = repo.list_for_scan("s1")
    assert len(rows) == 1
    assert rows[0]["tasks"] == 4
    assert rows[0]["findings"] == 2


def test_the_runs_of_one_scan_do_not_leak_into_another(services) -> None:
    repo = services.worker_runs
    repo.record(scan_id="s1", worker="B-Hunters-Katana", tasks=2)
    repo.record(scan_id="s2", worker="B-Hunters-Katana", tasks=1)

    assert len(repo.list_for_scan("s1")) == 1
    assert repo.list_for_scan("s1")[0]["tasks"] == 2
    assert repo.list_for_scan("s2")[0]["tasks"] == 1


# ----------------------------------------------------------------------
# The bridge
# ----------------------------------------------------------------------
def test_the_online_identities_are_the_consumer_names() -> None:
    backend = FakeBackend(identities=("B-Hunters-Katana", "B-Hunters-Nuclei"))
    bridge = KartonWorkerBridge(producer=FakeProducer(backend), database=FakeDatabase())

    assert bridge.online_identities() == ["B-Hunters-Katana", "B-Hunters-Nuclei"]


def test_an_unreachable_backend_reports_no_identity() -> None:
    """An unreachable backend is not evidence that a worker is absent."""
    backend = FakeBackend(unreachable=True)
    bridge = KartonWorkerBridge(producer=FakeProducer(backend), database=FakeDatabase())

    assert bridge.online_identities() == []


def test_the_tasks_a_worker_consumed_are_counted() -> None:
    backend = FakeBackend(identities=("B-Hunters-Katana",), consumed={"B-Hunters-Katana": 3})
    bridge = KartonWorkerBridge(producer=FakeProducer(backend), database=FakeDatabase())
    target = bridge.prepare(url="https://demo.test/", platform_scan_id="s1")

    # The workers consume their tasks while the scan runs.
    backend.redis.consumed["B-Hunters-Katana"] = 5

    outcomes = bridge.worker_outcomes("s1")

    assert outcomes == [{"worker": "B-Hunters-Katana", "tasks": 2, "findings": 0, "crashed_tasks": 0}]


def test_the_crashed_tasks_of_the_analysis_are_counted_per_worker() -> None:
    backend = FakeBackend(
        identities=("B-Hunters-Nuclei",),
        crashed=[FakeTask("B-Hunters-Nuclei"), FakeTask("B-Hunters-Nuclei")],
    )
    bridge = KartonWorkerBridge(producer=FakeProducer(backend), database=FakeDatabase())
    target = bridge.prepare(url="https://demo.test/", platform_scan_id="s1")
    bridge.dispatch(target)
    # The workers consume their tasks while the scan runs.
    backend.redis.consumed["B-Hunters-Nuclei"] = 2

    outcomes = bridge.worker_outcomes("s1")

    assert outcomes[0]["worker"] == "B-Hunters-Nuclei"
    assert outcomes[0]["tasks"] == 2
    assert outcomes[0]["crashed_tasks"] == 2


def test_the_findings_of_a_worker_are_counted() -> None:
    from bson import ObjectId

    report_id = ObjectId()
    database = FakeDatabase({"scans": [], "reports": [], "domains": []})
    backend = FakeBackend(identities=("B-Hunters-Nuclei",))
    bridge = KartonWorkerBridge(producer=FakeProducer(backend), database=database, poll_seconds=0.0)
    target = bridge.prepare(url="https://demo.test/", platform_scan_id="s1")
    bridge.dispatch(target)
    database.collection("domains").insert_one(
        {
            "Scanid": target.legacy_scan_id,
            "Domain": target.domain,
            "report_id": str(report_id),
        }
    )
    database.collection("reports").insert_one(
        {
            "_id": report_id,
            "Vulns": {"Nuclei": ["exposed-panel\nhttps://demo.test/admin"]},
        }
    )
    backend.redis.consumed["B-Hunters-Nuclei"] = 1

    results = bridge.collect(target, root_uid="root", deadline=0.0)

    assert results.consumed is True
    outcomes = bridge.worker_outcomes("s1")
    assert outcomes[0]["worker"] == "B-Hunters-Nuclei"
    assert outcomes[0]["findings"] == 1
    assert outcomes[0]["crashed_tasks"] == 0


# ----------------------------------------------------------------------
# The orchestrator
# ----------------------------------------------------------------------
class FakeBridge:
    """A bridge that says which workers took part."""

    def __init__(self) -> None:
        self.online = ["B-Hunters-Katana"]
        self.outcomes = [{"worker": "B-Hunters-Katana", "tasks": 3, "findings": 2, "crashed_tasks": 0}]
        self.snapshotted = False

    def online_identities(self) -> list[str]:
        return list(self.online)

    def consumed_tasks(self) -> dict[str, int]:
        return {"B-Hunters-Katana": 3}

    def prepare(self, *, url: str, description: str = "", platform_scan_id: str = "") -> WorkerTarget:
        return WorkerTarget(
            url=url,
            domain=url.replace("https://", "").rstrip("/"),
            legacy_scan_id="legacy",
            platform_scan_id=platform_scan_id,
        )

    def dispatch(self, target: WorkerTarget) -> str:
        return "root-uid"

    def collect(self, target: WorkerTarget, *, root_uid: str = "", deadline: Any = None) -> WorkerResults:
        return WorkerResults(findings=[], consumed=True)

    def worker_outcomes(self, scan_id: str) -> list[dict[str, Any]]:
        self.snapshotted = True
        return list(self.outcomes)


def _scan(database) -> str:
    record = ScanRepository(database).create(
        {
            "name": "worker run scan",
            "status": "queued",
            "created_by": "test",
            "definition": {"targets": ["https://demo.test/"]},
            "scope": {"authorized_hosts": ["demo.test"]},
        }
    )
    return record.scan_id


def _context(scan_id: str) -> ScanContext:
    profile = ScanProfile.default()
    profile.agent_roles = []
    profile.scanners = []
    return ScanContext(
        scan_id=scan_id,
        name="worker run scan",
        targets=["https://demo.test/"],
        authorized_hosts=["demo.test"],
        profile=profile,
        max_duration_seconds=60,
        workspace_root="/tmp/b-hunters-workerruns",
    )


@pytest.mark.asyncio
async def test_the_orchestrator_records_what_every_worker_did(database, settings) -> None:
    scan_id = _scan(database)
    bridge = FakeBridge()
    orchestrator = ScanOrchestrator(
        database=database,
        settings=replace(settings, mongo_db=database.settings.mongo_db),
        worker_bridge=bridge,
    )

    await orchestrator.run(_context(scan_id))

    rows = orchestrator.worker_runs.list_for_scan(scan_id)
    by_worker = {row["worker"]: row for row in rows}
    # The worker was online when the scan started and it did work.
    assert by_worker["B-Hunters-Katana"]["connected"] is True
    assert by_worker["B-Hunters-Katana"]["tasks"] == 3
    assert by_worker["B-Hunters-Katana"]["findings"] == 2
    assert bridge.snapshotted is True


@pytest.mark.asyncio
async def test_a_scan_without_workers_records_nothing(database, settings) -> None:
    """A scan that never reached the workers has no worker rows."""
    scan_id = _scan(database)
    orchestrator = ScanOrchestrator(
        database=database,
        settings=replace(settings, mongo_db=database.settings.mongo_db),
    )

    await orchestrator.run(_context(scan_id))

    assert orchestrator.worker_runs.list_for_scan(scan_id) == []
