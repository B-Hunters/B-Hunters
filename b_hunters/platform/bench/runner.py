"""The benchmark runner.

A benchmark run:

1. ensures the laboratory is up and the target application is ready;
2. creates a scan whose scope is exactly that application, with
   ``allow_private_network`` enabled because the lab lives on a private
   Docker network;
3. waits for the scan to finish;
4. matches the resulting findings against the manifest's test cases;
5. produces a scored summary.

The runner never invents a result.  If the application does not come up, or
the scan fails, the affected test cases are recorded as ``inconclusive``
rather than being silently dropped.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Optional

from ..db.client import Database
from ..db.repositories import FindingRepository, ScanRepository
from .lab import LabManager
from .manifest import BenchmarkApplication, TestCase
from .scoring import (
    OUTCOME_FALSE_NEGATIVE,
    OUTCOME_FALSE_POSITIVE,
    OUTCOME_INCONCLUSIVE,
    OUTCOME_NOT_APPLICABLE,
    OUTCOME_TRUE_POSITIVE,
    TestResult,
    build_summary,
    match_finding,
)

log = logging.getLogger(__name__)


def lab_host(manifest: BenchmarkApplication) -> str:
    """The name the laboratory is reachable under.

    The applications are published on the loopback interface, so the host
    resolves this name to ``127.0.0.1``; the worker containers resolve it
    through Docker DNS on the worker network.  One name, one URL, both
    callers.
    """
    return manifest.internal_host or f"bench-{manifest.slug}"


#: How long to wait for a scan to reach a terminal state.
SCAN_TIMEOUT_SECONDS = 3600


@dataclass
class BenchmarkRunConfig:
    """Configuration of one benchmark run."""

    benchmark_id: str = "default"
    applications: list[str] = field(default_factory=list)
    provider: str = ""
    profile: str = "standard"
    wait_for_lab: bool = True
    started_by: str = "system"
    notes: str = ""


class BenchmarkRunner:
    """Runs the benchmark suite and scores the results."""

    def __init__(
        self,
        *,
        database: Database,
        lab: Optional[LabManager] = None,
        scan_creator: Optional[Callable[..., Any]] = None,
        worker_collector: Optional[Any] = None,
    ) -> None:
        self.db = database
        self.scans = ScanRepository(database)
        self.findings = FindingRepository(database)
        self.lab = lab or LabManager()
        #: Injected by the API layer; creates and starts a scan.
        self.scan_creator = scan_creator
        #: An optional collector that drives the real Karton workers and
        #: returns their findings.
        self.worker_collector = worker_collector

    # ------------------------------------------------------------------
    async def run(self, config: BenchmarkRunConfig) -> dict[str, Any]:
        """Run the benchmark."""
        started = time.monotonic()
        results: list[TestResult] = []

        manifests = [
            manifest
            for manifest in self.lab.manifests()
            if not config.applications or manifest.slug in config.applications
        ]
        if not manifests:
            raise RuntimeError("no benchmark applications matched the selection")

        for manifest in manifests:
            results.extend(await self._run_application(manifest, config))

        duration = time.monotonic() - started
        summary = build_summary(results, duration_seconds=duration)
        return {
            "benchmark_id": config.benchmark_id,
            "started_at": started,
            "finished_at": time.time(),
            "summary": summary,
            "results": [result.to_dict() for result in results],
            "config": {
                "applications": config.applications,
                "profile": config.profile,
                "provider": config.provider,
                "notes": config.notes,
            },
        }

    async def _run_application(
        self, manifest: BenchmarkApplication, config: BenchmarkRunConfig
    ) -> list[TestResult]:
        log.info("benchmark: starting %s", manifest.name)
        if config.wait_for_lab:
            ready, reason = self.lab.wait_healthy(manifest)
            if not ready:
                log.warning("benchmark: %s is not ready: %s", manifest.slug, reason)
                return [
                    TestResult(
                        test_id=case.test_id,
                        application=manifest.slug,
                        vuln_class=case.vuln_class,
                        outcome=OUTCOME_INCONCLUSIVE,
                        expected=case.expectation == "expected",
                        notes=reason,
                        expected_severity=case.expected_severity,
                    )
                    for case in manifest.test_cases
                ]

        base_url = manifest.internal_url or (
            f"http://{lab_host(manifest)}:{manifest.port}{manifest.base_path}"
        )
        try:
            scan_id = await self._start_scan(manifest, base_url, config)
        except Exception as exc:
            log.exception("benchmark: could not start the scan for %s", manifest.slug)
            return [
                TestResult(
                    test_id=case.test_id,
                    application=manifest.slug,
                    vuln_class=case.vuln_class,
                    outcome=OUTCOME_INCONCLUSIVE,
                    expected=case.expectation == "expected",
                    notes=f"the scan could not be started: {exc}",
                    expected_severity=case.expected_severity,
                )
                for case in manifest.test_cases
            ]

        report_id = self._report_id_for(scan_id)
        await self._await_scan(scan_id)
        findings = self.findings.list(scan_id, limit=5000)

        # The findings the real scanner workers produced.
        worker_findings: list[dict[str, Any]] = []
        if self.worker_collector is not None:
            try:
                worker_findings = self.worker_collector(
                    scan_id=scan_id,
                    report_id=report_id,
                    target=lab_host(manifest),
                    url=base_url,
                )
            except Exception as exc:  # pragma: no cover - the collector is optional
                log.warning("the worker collector failed for %s: %s", manifest.slug, exc)

        # The time from the start of the scan to the moment a finding was
        # first recorded is the "time to first valid finding".
        scan_started = self._scan_started_at(scan_id)
        results: list[TestResult] = []
        for case in manifest.test_cases:
            result = self._evaluate(case, manifest, findings)
            if not result.detected and worker_findings:
                result = self._evaluate(case, manifest, worker_findings)
            if result.detected:
                elapsed = self._first_finding_delay(scan_id, scan_started)
                if elapsed is not None:
                    result.duration_ms = elapsed
            results.append(result)
        return results

    def _report_id_for(self, scan_id: str) -> Any:
        """The report document the workers write to."""
        document = self.db.collection("domains").find_one({"Scanid": scan_id})
        if document and document.get("report_id"):
            return document["report_id"]
        return None

    def _scan_started_at(self, scan_id: str) -> float:
        document = self.scans.get(scan_id)
        return float(document.created_at) if document else 0.0

    def _first_finding_delay(self, scan_id: str, started_at: float) -> int | None:
        """Milliseconds between the start of the scan and the first finding."""
        earliest = None
        for finding in self.findings.list(scan_id, limit=5000):
            first_seen = float(finding.get("first_seen_at") or 0.0)
            if first_seen and (earliest is None or first_seen < earliest):
                earliest = first_seen
        if earliest is None or not started_at:
            return None
        return int(max(0.0, earliest - started_at) * 1000)

    # ------------------------------------------------------------------
    async def _start_scan(
        self, manifest: BenchmarkApplication, base_url: str, config: BenchmarkRunConfig
    ) -> str:
        if self.scan_creator is None:
            raise RuntimeError("no scan creator is configured")
        scan = await self.scan_creator(
            name=f"benchmark:{manifest.slug}:{int(time.time())}",
            targets=[base_url],
            authorized_hosts=[
                "127.0.0.1",
                "localhost",
                manifest.slug,
                lab_host(manifest),
            ],
            profile=config.profile,
            allow_private_network=True,
            allow_state_changing=False,
            provider=config.provider,
        )
        # The creator returns a mapping; the runner needs the scan id.
        if isinstance(scan, dict):
            scan_id = scan.get("scan_id")
        else:
            scan_id = scan
        if not scan_id:
            raise RuntimeError("the scan creator did not return a scan id")
        return str(scan_id)

    async def _await_scan(self, scan_id: str, timeout: int = SCAN_TIMEOUT_SECONDS) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            record = self.scans.get(scan_id)
            if record is None:
                return
            if record.status in {"completed", "failed", "cancelled"}:
                return
            await asyncio.sleep(2.0)

    def _evaluate(
        self,
        case: TestCase,
        manifest: BenchmarkApplication,
        findings: Sequence[dict[str, Any]],
    ) -> TestResult:
        """Compare the findings against one test case."""
        matches = [
            finding
            for finding in findings
            if match_finding(
                finding,
                vuln_class=case.vuln_class,
                expected_evidence=case.expected_evidence,
                location_hint=str(case.probe.get("path", "")),
            )
        ]

        if case.expectation == "not_applicable":
            return TestResult(
                test_id=case.test_id,
                application=manifest.slug,
                vuln_class=case.vuln_class,
                outcome=OUTCOME_NOT_APPLICABLE,
                expected=False,
                detected=bool(matches),
                finding_ids=[finding.get("finding_id", "") for finding in matches],
                notes=case.unsupported or "this application does not contain this vulnerability class",
                expected_severity=case.expected_severity,
            )

        if case.expectation == "hygiene":
            if matches:
                return TestResult(
                    test_id=case.test_id,
                    application=manifest.slug,
                    vuln_class=case.vuln_class,
                    outcome=OUTCOME_FALSE_POSITIVE,
                    expected=False,
                    detected=True,
                    severity=matches[0].get("severity", ""),
                    finding_ids=[finding.get("finding_id", "") for finding in matches],
                    matched_finding_id=matches[0].get("finding_id", ""),
                    evidence=list(case.expected_evidence),
                    notes="the application is not expected to contain this vulnerability class",
                    expected_severity=case.expected_severity,
                )
            return TestResult(
                test_id=case.test_id,
                application=manifest.slug,
                vuln_class=case.vuln_class,
                outcome=OUTCOME_TRUE_POSITIVE,
                expected=False,
                detected=False,
                notes="no false positive was reported for a class the application does not contain",
                expected_severity=case.expected_severity,
            )

        if matches:
            return TestResult(
                test_id=case.test_id,
                application=manifest.slug,
                vuln_class=case.vuln_class,
                outcome=OUTCOME_TRUE_POSITIVE,
                expected=True,
                detected=True,
                severity=matches[0].get("severity", ""),
                finding_ids=[finding.get("finding_id", "") for finding in matches],
                matched_finding_id=matches[0].get("finding_id", ""),
                evidence=list(case.expected_evidence),
                detection_source=", ".join(matches[0].get("detected_by", []) or []),
                expected_severity=case.expected_severity,
            )

        return TestResult(
            test_id=case.test_id,
            application=manifest.slug,
            vuln_class=case.vuln_class,
            outcome=OUTCOME_FALSE_NEGATIVE,
            expected=True,
            detected=False,
            expected_severity=case.expected_severity,
            notes="the expected vulnerability was not reported",
        )
