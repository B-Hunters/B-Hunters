"""Tests for the bridge to the real Karton scanner workers.

The workers are containers, so the bridge is exercised against a fake
producer and a fake database.  What matters is the contract: the payload
names, the persistent flags and the correlation keys are the ones the
worker sources read, and a finding the workers wrote reaches the platform
as a platform finding.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest
from bson import ObjectId

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from b_hunters.platform.scanners.karton_bridge import (  # noqa: E402
    KartonWorkerBridge,
    WorkerTarget,
    finding_for_platform,
    host_of,
    normalize_target,
)


# ----------------------------------------------------------------------
# Fakes
# ----------------------------------------------------------------------
class FakeTask:
    """A stand-in for ``karton.core.Task`` that records the payloads."""

    def __init__(self, headers: dict[str, Any]) -> None:
        self.headers = dict(headers)
        self.payload: dict[str, Any] = {}
        self.payload_persistent: dict[str, Any] = {}

    def add_payload(self, name: str, value: Any, persistent: bool = False) -> None:
        if persistent:
            self.payload_persistent[name] = value
        else:
            self.payload[name] = value


class FakeProducer:
    def __init__(self) -> None:
        self.tasks: list[FakeTask] = []

    def send_task(self, task: FakeTask) -> None:
        self.tasks.append(task)


class FakeCollection:
    def __init__(self, documents: list[dict[str, Any]] | None = None) -> None:
        self.documents = list(documents or [])
        self.inserted: list[dict[str, Any]] = []

    def insert_one(self, document: dict[str, Any]) -> Any:
        self.inserted.append(document)
        self.documents.append(document)
        return type("Result", (), {"inserted_id": document.get("_id")})()

    def find_one(self, query: dict[str, Any]) -> dict[str, Any] | None:
        for document in self.documents:
            if all(document.get(key) == value for key, value in query.items()):
                return document
        return None

    def find(self, query: dict[str, Any], projection: dict[str, Any] | None = None):
        return [
            document
            for document in self.documents
            if all(document.get(key) == value for key, value in query.items())
        ]


class FakeDatabase:
    def __init__(self, collections: dict[str, FakeCollection]) -> None:
        self.collections = collections

    def collection(self, name: str) -> FakeCollection:
        return self.collections[name]


def _database(report: dict[str, Any] | None = None, domain: dict[str, Any] | None = None):
    return FakeDatabase(
        {
            "scans": FakeCollection(),
            "reports": FakeCollection([report] if report else []),
            "domains": FakeCollection([domain] if domain else []),
        }
    )


# ----------------------------------------------------------------------
# Normalisation
# ----------------------------------------------------------------------
class TestNormalizeTarget:
    def test_the_scheme_is_removed(self) -> None:
        assert normalize_target("http://lab-dvga:5013/") == "lab-dvga:5013"
        assert normalize_target("https://lab-dvga:5013/") == "lab-dvga:5013"

    def test_the_trailing_slashes_are_removed(self) -> None:
        assert normalize_target("http://lab-dvga:5013///") == "lab-dvga:5013"

    def test_the_port_is_kept(self) -> None:
        """The workers use the host with the port as the status key."""
        assert normalize_target("http://bench-dvga:5013/") == "bench-dvga:5013"

    def test_the_path_is_kept(self) -> None:
        assert normalize_target("http://lab-webgoat:8080/WebGoat/") == "lab-webgoat:8080/WebGoat"

    def test_the_host_of_a_target_drops_the_port(self) -> None:
        assert host_of("lab-dvga:5013") == "lab-dvga"
        assert host_of("lab-webgoat:8080/WebGoat") == "lab-webgoat"


# ----------------------------------------------------------------------
# Publishing
# ----------------------------------------------------------------------
class TestDispatch:
    def test_prepare_writes_the_legacy_scan_document(self) -> None:
        database = _database()
        bridge = KartonWorkerBridge(producer=FakeProducer(), database=database)

        target = bridge.prepare(url="http://lab-dvga:5013/", description="a scan")

        document = database.collection("scans").inserted[0]
        assert document["Domain"] == "lab-dvga:5013"
        assert document["Type"] == "single"
        assert document["Description"] == "a scan"
        # The workers resolve "scans" through ObjectId(), so the identifier
        # has to be one.
        assert str(document["_id"]) == target.legacy_scan_id

    def test_dispatch_publishes_the_task_the_workers_consume(self) -> None:
        producer = FakeProducer()
        bridge = KartonWorkerBridge(producer=producer, database=_database())
        target = bridge.prepare(url="http://lab-dvga:5013/")

        bridge.dispatch(target)

        assert len(producer.tasks) == 1
        task = producer.tasks[0]
        assert task.headers == {"type": "domain", "stage": "new"}
        # The target and the scan identifier travel persistently, so that
        # they survive the whole task subtree.
        assert task.payload_persistent["domain"] == "lab-dvga:5013"
        assert task.payload_persistent["scantype"] == "single"
        assert task.payload_persistent["scan_id"] == target.legacy_scan_id
        assert task.payload["data"] == "lab-dvga:5013"
        assert task.payload["source"] == "producer"

    def test_each_target_gets_its_own_scan_identifier(self) -> None:
        bridge = KartonWorkerBridge(producer=FakeProducer(), database=_database())

        first = bridge.prepare(url="http://lab-dvga:5013/")
        second = bridge.prepare(url="http://lab-dvga:5013/")

        assert first.legacy_scan_id != second.legacy_scan_id


# ----------------------------------------------------------------------
# Collecting
# ----------------------------------------------------------------------
class TestCollect:
    def test_the_findings_of_the_report_are_returned(self) -> None:
        report_oid = ObjectId()
        report = {
            "_id": report_oid,
            "Vulns": {
                "Nuclei": ["exposed-panel\nhttp://lab-dvga:5013/admin"],
            },
            "Ports": [{"target": "lab-dvga:5013", "ports": ["Port: 8080, State: open, Product: nginx"]}],
            "Technology": {},
        }
        domain = {
            "Scanid": "6ad9739f61d70e848ebac739",
            "Domain": "lab-dvga:5013",
            "report_id": str(report_oid),
            "status": {"processing": [], "finished": ["B-Hunters-Nuclei"]},
        }
        bridge = KartonWorkerBridge(
            producer=FakeProducer(),
            database=_database(report=report, domain=domain),
            poll_seconds=0.0,
        )
        target = WorkerTarget(
            url="http://lab-dvga:5013/",
            domain="lab-dvga:5013",
            legacy_scan_id="6ad9739f61d70e848ebac739",
        )

        results = bridge.collect(target, deadline=0.0)

        assert results.consumed is True
        assert results.report_id == str(report_oid)
        assert [f["title"] for f in results.findings]
        assert results.services

    def test_the_findings_of_every_report_of_the_scan_are_returned(self) -> None:
        """A host the discovery found has a report of its own.

        The workers write what they find into the report of the host
        they scanned, and the discovery worker gives every host it finds
        a report.  A platform that reads only the report of the target
        reads only the findings of the target.
        """
        target_oid = ObjectId()
        subdomain_oid = ObjectId()
        target_report = {
            "_id": target_oid,
            "Vulns": {"Nuclei": ["exposed-panel\nhttp://demo.test/admin"]},
            "Ports": [],
            "Technology": {},
        }
        subdomain_report = {
            "_id": subdomain_oid,
            "Vulns": {"Nuclei": ["open-redirect\nhttp://api.demo.test/next"]},
            "Ports": [],
            "Technology": {},
        }
        domains = [
            {
                "Scanid": "6ad9739f61d70e848ebac739",
                "Domain": "demo.test",
                "report_id": str(target_oid),
                "status": {"processing": [], "finished": ["B-Hunters-Nuclei"]},
            },
            {
                "Scanid": "6ad9739f61d70e848ebac739",
                "Domain": "api.demo.test",
                "report_id": str(subdomain_oid),
                "status": {"processing": [], "finished": ["B-Hunters-Nuclei"]},
            },
        ]
        database = FakeDatabase(
            {
                "scans": FakeCollection(),
                "reports": FakeCollection([target_report, subdomain_report]),
                "domains": FakeCollection(domains),
            }
        )
        bridge = KartonWorkerBridge(
            producer=FakeProducer(),
            database=database,
            poll_seconds=0.0,
        )
        target = WorkerTarget(
            url="https://demo.test/",
            domain="demo.test",
            legacy_scan_id="6ad9739f61d70e848ebac739",
        )

        results = bridge.collect(target, deadline=0.0)

        titles = [f["title"] for f in results.findings]
        assert "exposed-panel" in titles
        assert "open-redirect" in titles

    def test_an_unconsumed_task_is_reported_as_such(self) -> None:
        bridge = KartonWorkerBridge(
            producer=FakeProducer(),
            database=_database(),
            poll_seconds=0.0,
        )
        target = WorkerTarget(
            url="http://lab-dvga:5013/",
            domain="lab-dvga:5013",
            legacy_scan_id="6ad9739f61d70e848ebac739",
        )

        results = bridge.collect(target, deadline=0.0)

        assert results.consumed is False
        assert results.findings == []


# ----------------------------------------------------------------------
# Mapping onto the platform shape
# ----------------------------------------------------------------------
class TestFindingForPlatform:
    def test_a_worker_finding_becomes_a_platform_finding(self) -> None:
        target = WorkerTarget(
            url="http://lab-dvga:5013/",
            domain="lab-dvga:5013",
            legacy_scan_id="x",
        )
        finding = {
            "title": "SQL injection in parameter id",
            "vuln_class": "sql_injection",
            "summary": "the parameter is concatenated into a query",
            "location": "http://lab-dvga:5013/api?id=1",
            "detector": "SQLMap",
            "evidence": [{"kind": "worker_output", "excerpt": "..."}],
        }

        mapped = finding_for_platform(finding, target)

        assert mapped["title"] == "SQL injection in parameter id"
        assert mapped["vuln_class"] == "sql_injection"
        assert mapped["severity"] == "high"
        assert mapped["host"] == "lab-dvga"
        assert mapped["path"] == "/api?id=1"
        assert mapped["affected_url"] == "http://lab-dvga:5013/api?id=1"
        assert mapped["detection_source"] == "SQLMap"
        assert mapped["detected_by"] == ["SQLMap"]

    def test_the_extra_key_distinguishes_the_finding(self) -> None:
        """Two findings of one class on one host must not collapse."""
        target = WorkerTarget(
            url="http://lab-dvga:5013/",
            domain="lab-dvga:5013",
            legacy_scan_id="x",
        )

        first = finding_for_platform(
            {"title": "Technologies identified", "vuln_class": "security_misconfiguration"}, target
        )
        second = finding_for_platform(
            {"title": "Open ports", "vuln_class": "security_misconfiguration"}, target
        )

        assert first["extra_key"] != second["extra_key"]
        assert first["extra_key"].startswith("worker:")

    def test_the_severity_follows_the_vulnerability_class(self) -> None:
        target = WorkerTarget(url="http://x/", domain="x", legacy_scan_id="x")

        xss = finding_for_platform({"title": "t", "vuln_class": "xss"}, target)
        unknown = finding_for_platform({"title": "t", "vuln_class": "something_new"}, target)

        assert xss["severity"] == "medium"
        assert unknown["severity"] == "medium"

    def test_a_finding_without_a_location_keeps_the_target_url(self) -> None:
        target = WorkerTarget(
            url="http://lab-dvga:5013/",
            domain="lab-dvga:5013",
            legacy_scan_id="x",
        )

        mapped = finding_for_platform({"title": "t", "vuln_class": "xss"}, target)

        assert mapped["affected_url"] == "http://lab-dvga:5013/"
        assert mapped["path"] == ""


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__])
