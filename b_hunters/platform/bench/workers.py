"""Collect findings from the real scanner workers.

The benchmark has to measure the whole pipeline, not only the in-process
adapters.  This module drives the Karton workers exactly as a real scan
does - a ``subdomain``/``new`` task for the discovery workers and a
``paths``/``scan`` task for the scanners - and then reads what they wrote
into the report document.

Each worker owns a field of the report document:

===================  ==========================================
Report field         Worker
===================  ==========================================
``Vulns.SQLMap``     the SQL injection scanner
``Vulns.dalfox``     the XSS scanner
``Vulns.Nuclei``     the template scanner
``Ports``            the port scanner
``Technology``       the technology fingerprint
``Paths``            the crawler
===================  ==========================================

The worker output is turned into findings with a canonical vulnerability
class, so that it can be matched against the benchmark's test cases.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Sequence
from typing import Any

from bson import ObjectId

log = logging.getLogger(__name__)

#: How a report field maps onto a canonical vulnerability class.
FIELD_CLASSES = {
    "SQLMap": "sql_injection",
    "dalfox": "xss",
    "Nuclei": "active_vulnerability",
    "SSTI": "ssti",
    "Wapiti": "active_vulnerability",
    "xray": "active_vulnerability",
}

#: The class a nuclei template implies, when the template names one.
TEMPLATE_CLASS_HINTS = (
    ("xss", "xss"),
    ("sqli", "sql_injection"),
    ("sql-injection", "sql_injection"),
    ("ssrf", "ssrf"),
    ("lfi", "path_traversal"),
    ("path-traversal", "path_traversal"),
    ("rce", "active_vulnerability"),
    ("cve", "active_vulnerability"),
    ("exposure", "information_disclosure"),
    ("misconfig", "security_misconfiguration"),
    ("header", "security_misconfiguration"),
)


def _class_for_nuclei(line: str) -> str:
    """Infer the class from a nuclei template identifier."""
    lowered = line.lower()
    for hint, vuln_class in TEMPLATE_CLASS_HINTS:
        if hint in lowered:
            return vuln_class
    return "active_vulnerability"


def findings_from_report(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Turn a report document into findings."""
    findings: list[dict[str, Any]] = []
    vulns = report.get("Vulns") or {}
    if not isinstance(vulns, dict):
        return findings

    for field, entries in vulns.items():
        if not isinstance(entries, list):
            continue
        base_class = FIELD_CLASSES.get(field, "active_vulnerability")
        for entry in entries:
            if isinstance(entry, dict):
                title = str(entry.get("title") or entry.get("message_str") or entry.get("type") or field)
                location = str(entry.get("data") or entry.get("url") or entry.get("path") or "")
                vuln_class = base_class
                extra = ""
            else:
                text = str(entry)
                title = text.split("\n", 1)[0][:200]
                location = ""
                extra = text
                vuln_class = _class_for_nuclei(text) if field == "Nuclei" else base_class
            findings.append(
                {
                    "title": title,
                    "vuln_class": vuln_class,
                    "summary": extra[:500] or title,
                    "evidence": [{"kind": "worker_output", "excerpt": (extra or title)[:600]}],
                    "location": location,
                    "detector": field,
                }
            )
    return findings


def security_header_findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Turn the technology and port sections into informational findings."""
    findings: list[dict[str, Any]] = []

    technology = report.get("Technology") or {}
    if isinstance(technology, dict) and technology:
        names: list[str] = []
        for value in technology.values():
            if isinstance(value, list):
                for entry in value:
                    if isinstance(entry, dict):
                        for item in entry.values():
                            if isinstance(item, list):
                                names.extend(str(name) for name in item)
                    elif isinstance(entry, list):
                        names.extend(str(name) for name in entry)
        if names:
            findings.append(
                {
                    "title": "Technologies identified",
                    "vuln_class": "security_misconfiguration",
                    "summary": ", ".join(sorted(set(names))[:20]),
                    "evidence": [{"kind": "worker_output", "excerpt": ", ".join(sorted(set(names))[:20])}],
                    "detector": "technology",
                }
            )

    ports = report.get("Ports") or []
    if isinstance(ports, list) and ports:
        open_ports = []
        for entry in ports:
            if isinstance(entry, dict):
                open_ports.extend(str(port) for port in entry.get("ports", []))
        if open_ports:
            findings.append(
                {
                    "title": "Open ports",
                    "vuln_class": "security_misconfiguration",
                    "summary": "; ".join(open_ports[:20]),
                    "evidence": [{"kind": "worker_output", "excerpt": "; ".join(open_ports[:20])}],
                    "detector": "nmap",
                }
            )
    return findings


def collect_from_report(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Every finding a report document holds."""
    return findings_from_report(report) + security_header_findings(report)


class KartonWorkerRunner:
    """Drives the real Karton workers for one benchmark application."""

    def __init__(
        self,
        *,
        producer: Any,
        mongo_database: Any,
        wait_seconds: int = 240,
        s3_endpoint: str = "http://127.0.0.1:9000",
        s3_access_key: str = "",
        s3_secret_key: str = "",
        s3_bucket: str = "bhunters",
    ) -> None:
        self.producer = producer
        self.db = mongo_database
        self.wait_seconds = wait_seconds
        self.s3_endpoint = s3_endpoint
        self.s3_access_key = s3_access_key
        self.s3_secret_key = s3_secret_key
        self.s3_bucket = s3_bucket

    def run(
        self,
        *,
        scan_id: str,
        report_id: ObjectId,
        target: str,
        url: str,
        source: str = "spider",
    ) -> list[dict[str, Any]]:
        """Send the tasks the workers bind to and wait for them to finish."""
        from karton.core import Task

        self._send(
            Task({"type": "subdomain", "stage": "new"}),
            scan_id=scan_id,
            report_id=report_id,
            target=target,
            url=url,
            source=source,
        )
        # The path scanners download their input from the artefact store, so
        # the list has to be there before the task is published.
        self._upload_paths(source, scan_id, target, self.discovered_urls(url))
        self._send(
            Task({"type": "paths", "stage": "scan"}),
            scan_id=scan_id,
            report_id=report_id,
            target=target,
            url=url,
            source=source,
        )

        deadline = time.time() + self.wait_seconds
        while time.time() < deadline:
            report = self.db.collection("reports").find_one({"_id": report_id}) or {}
            if report.get("Vulns") or report.get("Paths") or report.get("Ports"):
                # Give the remaining workers a moment to finish.
                time.sleep(8)
                break
            time.sleep(2)
        report = self.db.collection("reports").find_one({"_id": report_id}) or {}
        return collect_from_report(report)

    def _send(
        self,
        task: Any,
        *,
        scan_id: str,
        report_id: ObjectId,
        target: str,
        url: str,
        source: str,
    ) -> None:
        task.add_payload("data", url)
        task.add_payload("subdomain", target)
        task.add_payload("source", source)
        task.add_payload("report_id", str(report_id), persistent=True)
        task.add_payload("scan_id", scan_id, persistent=True)
        task.add_payload("domain", target, persistent=True)
        task.add_payload("scantype", "single", persistent=True)
        self.producer.send_task(task)

    @staticmethod
    def discovered_urls(url: str) -> list[str]:
        """The URL list a crawler would have produced for a target.

        The platform does not crawl in the benchmark, so the list is derived
        from the target itself.  The scanners need a real list to work on.
        """
        return [
            url,
            f"{url}/robots.txt",
            f"{url}/admin",
            f"{url}/api",
            f"{url}/.env",
        ]

    def _upload_paths(self, source: str, scan_id: str, target: str, urls: Sequence[str]) -> None:
        """Upload the URL list a path scanner downloads.

        The key is the one the workers build from the task's ``data``
        payload, so the producer and the consumer have to agree on it.
        """
        import re

        # The same encoding the worker base class uses for artefact names.
        safe = re.sub(r'[<>:"/\\|?*]', "_", target)
        key = f"{source}_{scan_id}_{safe}"
        body = "\n".join(urls).encode("utf-8")
        try:
            import boto3
            from botocore.config import Config

            client = boto3.client(
                "s3",
                endpoint_url=self.s3_endpoint,
                aws_access_key_id=self.s3_access_key,
                aws_secret_access_key=self.s3_secret_key,
                config=Config(signature_version="s3v4"),
            )
            client.put_object(Bucket=self.s3_bucket, Key=key, Body=body)
        except Exception as exc:  # pragma: no cover - the store is optional
            log.warning("could not upload the path list: %s", exc)
