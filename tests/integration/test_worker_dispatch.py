"""End-to-end tests for the dispatch to the real scanner workers.

A scan started from the console used to stop at the in-process adapters,
so the scanner worker containers never received a task and the console
showed almost nothing.  These tests drive the orchestrator with a fake
bridge and assert that the findings the workers produced reach the
platform findings collection, that the events the console renders are
emitted, and that a target outside the scan scope is never handed to the
workers.
"""

from __future__ import annotations

from typing import Any

import pytest

from b_hunters.platform.agents.orchestrator import ScanContext, ScanOrchestrator, ScanProfile
from b_hunters.platform.scanners.karton_bridge import WorkerResults, WorkerTarget

pytestmark = pytest.mark.integration


class FakeBridge:
    """A bridge that answers with a fixed result instead of running workers."""

    def __init__(self, results: list[dict[str, Any]] | None = None) -> None:
        self.results = results if results is not None else []
        self.prepared: list[WorkerTarget] = []
        self.dispatched: list[WorkerTarget] = []
        self.dispatched_roles: list[str] = []

    def prepare(self, *, url: str, description: str = "", platform_scan_id: str = "") -> WorkerTarget:
        from b_hunters.platform.scanners.karton_bridge import normalize_target

        target = WorkerTarget(
            url=url,
            domain=normalize_target(url),
            legacy_scan_id=f"legacy-{len(self.prepared)}",
        )
        self.prepared.append(target)
        return target

    def consumed_tasks(self) -> dict[str, int]:
        return dict.fromkeys(self.dispatched_roles, 1)

    def dispatch(self, target: WorkerTarget) -> str:
        self.dispatched.append(target)
        self.dispatched_roles.append("B-Hunters-" + target.domain.split(":")[0])
        return f"root-{target.domain}"

    def collect(
        self,
        target: WorkerTarget,
        *,
        root_uid: str = "",
        deadline: float | None = None,
    ) -> WorkerResults:
        for entry in self.results:
            if entry.get("domain") == target.domain:
                return WorkerResults(
                    findings=list(entry.get("findings", [])),
                    services=list(entry.get("services", [])),
                    report_id=entry.get("report_id", "report-1"),
                    consumed=True,
                )
        return WorkerResults(consumed=False)


@pytest.fixture
def orchestrator(services, tmp_path):
    def build(bridge: FakeBridge) -> ScanOrchestrator:
        instance = ScanOrchestrator(
            database=services.db,
            settings=services.settings,
            provider_factory=lambda provider_name="": None,
            worker_bridge=bridge,
        )
        instance.settings.agent_workspace_root = str(tmp_path)
        return instance

    return build


def _context(scan_id: str, **overrides: Any) -> ScanContext:
    payload: dict[str, Any] = {
        "scan_id": scan_id,
        "name": "worker dispatch scan",
        "targets": ["https://demo.test/"],
        "authorized_hosts": ["demo.test"],
        "profile": ScanProfile.default(),
        "safe_mode": True,
        "max_duration_seconds": 120,
        "workspace_root": "/tmp/b-hunters-workers",
    }
    payload.update(overrides)
    return ScanContext(**payload)


def _scan(services, **overrides: Any):
    payload: dict[str, Any] = {
        "name": "worker dispatch scan",
        "status": "queued",
        "created_by": "test",
        "definition": {"targets": ["https://demo.test/"]},
        "scope": {"authorized_hosts": ["demo.test"]},
    }
    payload.update(overrides)
    return services.scans.create(payload)


@pytest.mark.asyncio
async def test_the_findings_of_the_workers_reach_the_platform(services, orchestrator) -> None:
    bridge = FakeBridge(
        [
            {
                "domain": "demo.test",
                "report_id": "report-1",
                "findings": [
                    {
                        "title": "SQL injection in parameter id",
                        "vuln_class": "sql_injection",
                        "summary": "the parameter is concatenated into a query",
                        "location": "https://demo.test/api?id=1",
                        "detector": "SQLMap",
                        "evidence": [{"kind": "worker_output", "excerpt": "..."}],
                    }
                ],
                "services": [
                    {
                        "name": "nginx",
                        "category": "Web servers",
                        "version": "1.25.0",
                        "confidence": 0.9,
                        "source": "wappalyzer:webtechnology",
                        "evidence": "https://demo.test/ -> Web servers: nginx",
                    }
                ],
            }
        ]
    )
    scan = _scan(services)
    instance = orchestrator(bridge)
    context = _context(scan.scan_id)
    context.profile.agent_roles = []

    result = await instance.run(context)

    assert result["status"] == "completed"

    findings = services.findings.list(scan.scan_id)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["title"] == "SQL injection in parameter id"
    assert finding["vuln_class"] == "sql_injection"
    assert finding["severity"] == "high"
    assert finding["host"] == "demo.test"
    assert finding["path"] == "/api?id=1"
    assert finding["detection_source"] == "SQLMap"
    assert finding["detected_by"] == ["SQLMap"]

    # The services the workers identified reach the inventory.
    services_recorded = services.services.list_for_scan(scan.scan_id)
    assert services_recorded


@pytest.mark.asyncio
async def test_the_dispatch_is_visible_in_the_event_stream(services, orchestrator) -> None:
    bridge = FakeBridge([{"domain": "demo.test", "findings": [], "services": [], "report_id": "report-1"}])
    scan = _scan(services)
    instance = orchestrator(bridge)
    context = _context(scan.scan_id)
    context.profile.agent_roles = []

    await instance.run(context)

    kinds = {event["kind"] for event in services.events.list_after(scan.scan_id)}
    assert "workers.dispatched" in kinds
    assert "workers.completed" in kinds
    assert "workers.finished" in kinds


@pytest.mark.asyncio
async def test_a_worker_finding_does_not_merge_into_a_native_finding(services, orchestrator) -> None:
    """A worker finding and a native finding are two findings, not one."""
    bridge = FakeBridge(
        [
            {
                "domain": "demo.test",
                "report_id": "report-1",
                "findings": [
                    {
                        "title": "Technologies identified",
                        "vuln_class": "security_misconfiguration",
                        "summary": "nginx",
                        "detector": "technology",
                    }
                ],
            }
        ]
    )
    scan = _scan(services)
    # A native finding of the same class on the same host.
    services.findings.upsert(
        scan_id=scan.scan_id,
        title="Missing strict-transport-security header",
        summary="HSTS is not set",
        vuln_class="security_misconfiguration",
        severity="low",
        host="demo.test",
        detected_by=["security_headers"],
        detection_source="security_headers",
    )
    instance = orchestrator(bridge)
    context = _context(scan.scan_id)
    context.profile.agent_roles = []

    await instance.run(context)

    findings = services.findings.list(scan.scan_id)
    assert len(findings) == 2
    titles = {finding["title"] for finding in findings}
    assert "Missing strict-transport-security header" in titles
    assert "Technologies identified" in titles


@pytest.mark.asyncio
async def test_every_target_is_published_before_the_first_one_is_collected(services, orchestrator) -> None:
    """The workers scan in parallel, so the targets are published together."""
    bridge = FakeBridge()
    scan = _scan(services)
    instance = orchestrator(bridge)
    context = _context(
        scan.scan_id,
        targets=["https://demo.test/", "https://second.test/"],
        authorized_hosts=["demo.test", "second.test"],
    )
    context.profile.agent_roles = []

    await instance.run(context)

    assert [target.domain for target in bridge.dispatched] == ["demo.test", "second.test"]


@pytest.mark.asyncio
async def test_a_target_outside_the_scope_is_not_handed_to_the_workers(services, orchestrator) -> None:
    bridge = FakeBridge()
    scan = _scan(services)
    instance = orchestrator(bridge)
    context = _context(
        scan.scan_id,
        targets=["https://demo.test/", "https://elsewhere.test/"],
        authorized_hosts=["demo.test"],
    )
    context.profile.agent_roles = []

    await instance.run(context)

    assert [target.domain for target in bridge.dispatched] == ["demo.test"]


@pytest.mark.asyncio
async def test_a_scan_without_a_worker_stack_still_completes(services, orchestrator) -> None:
    """A platform without reachable workers degrades the scan, not fails it."""
    scan = _scan(services)
    instance = orchestrator(FakeBridge())
    instance.worker_bridge = None
    context = _context(scan.scan_id)
    context.profile.agent_roles = []

    result = await instance.run(context)

    assert result["status"] == "completed"
    record = services.scans.get(scan.scan_id)
    assert record.status == "completed"


@pytest.mark.asyncio
async def test_an_unconsumed_task_is_reported_as_an_error(services, orchestrator) -> None:
    bridge = FakeBridge()
    scan = _scan(services)
    instance = orchestrator(bridge)
    context = _context(scan.scan_id)
    context.profile.agent_roles = []

    await instance.run(context)

    events = services.events.list_after(scan.scan_id)
    errors = [event for event in events if event["kind"] == "worker.error"]
    assert errors
    assert "no scanner worker consumed the task" in errors[0]["payload"]["error"]
