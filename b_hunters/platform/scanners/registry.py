"""The scanner adapter registry.

Contains:

* one adapter for each of the 17 existing B-Hunters Karton workers, using
  the real task headers those workers filter on, so the existing scan
  pipeline keeps working unchanged;
* adapters for capabilities that the existing modules do not cover at all
  and that measurably improve coverage: security headers, TLS
  configuration, secret detection, OpenAPI discovery, GraphQL analysis and
  dependency analysis.

The Karton adapters dispatch through the real Karton producer, so a scan
started from the platform uses exactly the same worker code path as a scan
started from the CLI.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from typing import Any, Optional

from .base import (
    AdapterSpec,
    BaseAdapter,
    Capability,
    HealthStatus,
    ScanRequest,
)

log = logging.getLogger(__name__)


# ----------------------------------------------------------------------
# Existing B-Hunters Karton workers
# ----------------------------------------------------------------------
def _karton_spec(
    name: str,
    version: str,
    description: str,
    identity: str,
    task_type: str,
    task_stage: str,
    capabilities: list[Capability],
    output_kinds: list[str],
    *,
    license_name: str = "GPL-3.0",
    upstream: str = "",
    maintenance: str = "maintained",
    required_inputs: Optional[list[str]] = None,
    cancellation: bool = False,
) -> AdapterSpec:
    return AdapterSpec(
        name=name,
        version=version,
        description=description,
        capabilities=capabilities,
        karton_identity=identity,
        karton_task_type=task_type,
        karton_task_stage=task_stage,
        required_inputs=required_inputs or ["target"],
        output_kinds=output_kinds,
        timeout_seconds=900.0,
        concurrency=4,
        supports_cancellation=cancellation,
        max_retries=1,
        required_permissions=["network"],
        container_image=f"bormaa/{name.lower()}:latest",
        installation_requirements=["docker image pull"],
        license=license_name,
        upstream=upstream,
        maintenance_status=maintenance,
        kind="karton",
    )


def default_all_adapters() -> list[AdapterSpec]:
    """Every adapter the platform ships with."""
    specs: list[AdapterSpec] = [
        _karton_spec(
            "subrecon",
            "1.1.16",
            "Passive subdomain enumeration and resolution (subfinder, assetfinder, chaos, findomain, vita, Sublist3r).",
            "B-Hunters-subrecon",
            "domain",
            "new",
            [Capability.SUBDOMAIN_ENUMERATION, Capability.HOST_RESOLUTION],
            ["host"],
            upstream="https://github.com/B-Hunters/B-Hunters-Subrecon",
        ),
        _karton_spec(
            "nmap",
            "1.1.16",
            "TCP port scan and service detection.",
            "B-Hunters-Nmap",
            "subdomain",
            "new",
            [Capability.PORT_SCAN, Capability.SERVICE_DETECTION],
            ["port"],
            upstream="https://github.com/B-Hunters/B-Hunters-NMap",
        ),
        _karton_spec(
            "gowitness",
            "1.1.16",
            "Headless browser screenshots and response header capture.",
            "B-Hunters-GoWitness",
            "subdomain",
            "new",
            [Capability.SCREENSHOT, Capability.TECHNOLOGY_DETECTION],
            ["screenshot", "technology"],
            upstream="https://github.com/B-Hunters/B-Hunters-gowitness",
        ),
        _karton_spec(
            "dirsearch",
            "1.1.16",
            "Directory and file brute force.",
            "B-Hunters-dirsearch",
            "subdomain",
            "new",
            [Capability.DIRECTORY_BRUTEFORCE],
            ["url"],
            upstream="https://github.com/B-Hunters/B-Hunters-Dirsearch",
        ),
        _karton_spec(
            "paramspider",
            "1.1.16",
            "Parameter discovery from crawled pages.",
            "B-Hunters-ParamSpider",
            "subdomain",
            "new",
            [Capability.PARAMETER_DISCOVERY],
            ["url"],
            upstream="https://github.com/B-Hunters/B-Hunters-ParamSpider",
        ),
        _karton_spec(
            "webtechnology",
            "1.1.16",
            "Technology fingerprinting with wappalyzer.",
            "B-Hunters-web-technology",
            "subdomain",
            "new",
            [Capability.TECHNOLOGY_DETECTION],
            ["technology"],
            upstream="https://github.com/B-Hunters/B-Hunters-Web-Technology",
        ),
        _karton_spec(
            "wayback",
            "1.1.16",
            "Historical URL collection from Wayback, gau and waymore.",
            "B-Hunters-wayback",
            "subdomain",
            "new",
            [Capability.HTTP_CRAWL],
            ["url"],
            upstream="https://github.com/B-Hunters/B-Hunters-Wayback",
        ),
        _karton_spec(
            "gospider",
            "1.1.16",
            "Fast web spider producing links and JavaScript references.",
            "B-Hunters-GoSpider",
            "url",
            "new",
            [Capability.HTTP_CRAWL, Capability.JAVASCRIPT_COLLECTION],
            ["url", "javascript"],
            upstream="https://github.com/B-Hunters/B-Hunters-GoSpider",
        ),
        _karton_spec(
            "katana",
            "1.1.16",
            "Concurrent web crawler with JavaScript parsing.",
            "B-Hunters-Katana",
            "url",
            "new",
            [Capability.HTTP_CRAWL, Capability.JAVASCRIPT_COLLECTION],
            ["url", "javascript"],
            upstream="https://github.com/B-Hunters/B-Hunters-Katana",
        ),
        _karton_spec(
            "getjs",
            "1.1.16",
            "JavaScript asset collection from in-scope pages.",
            "B-Hunters-getjs",
            "url",
            "new",
            [Capability.JAVASCRIPT_COLLECTION],
            ["javascript"],
            upstream="https://github.com/B-Hunters/B-Hunters-GetJS",
        ),
        _karton_spec(
            "jsscanner",
            "1.1.16",
            "JavaScript secret detection with SecretFinder.",
            "B-Hunters-jsscanner",
            "js",
            "new",
            [Capability.SECRET_DETECTION, Capability.JAVASCRIPT_ANALYSIS],
            ["secret"],
            upstream="https://github.com/B-Hunters/B-Hunters-jsscanner",
        ),
        _karton_spec(
            "nuclei",
            "1.1.16",
            "Template driven vulnerability scanning with Nuclei.",
            "B-Hunters-Nuclei",
            "subdomain",
            "new",
            [Capability.NUCLEI_TEMPLATES, Capability.ACTIVE_VULNERABILITY],
            ["finding"],
            license_name="MIT",
            upstream="https://github.com/B-Hunters/B-Hunters-Nuclei",
        ),
        _karton_spec(
            "sqlmap",
            "1.1.16",
            "SQL injection detection with sqlmap.",
            "B-Hunters-SQLMap",
            "subdomain",
            "new",
            [Capability.SQL_INJECTION],
            ["finding"],
            license_name="GPL-2.0",
            upstream="https://github.com/B-Hunters/B-Hunters-Sqlmap",
        ),
        _karton_spec(
            "dalfox",
            "1.1.16",
            "Cross-site scripting detection with DalFox.",
            "B-Hunters-DalFox",
            "paths",
            "scan",
            [Capability.XSS],
            ["finding"],
            license_name="MIT",
            upstream="https://github.com/B-Hunters/B-Hunters-DalFox",
        ),
        _karton_spec(
            "ssti",
            "1.1.16",
            "Server-side template injection detection with SSTImap.",
            "B-Hunters-SSTI-Checker",
            "paths",
            "scan",
            [Capability.SSTI],
            ["finding"],
            upstream="https://github.com/B-Hunters/b-hunters-SSTI-Checker",
        ),
        _karton_spec(
            "wapiti",
            "1.1.16",
            "Broad web application vulnerability scanner.",
            "B-Hunters-wapiti",
            "subdomain",
            "new",
            [Capability.ACTIVE_VULNERABILITY],
            ["finding"],
            license_name="GPL-2.0",
            upstream="https://github.com/B-Hunters/B-Hunters-Wapiti",
        ),
        _karton_spec(
            "xray",
            "1.1.16",
            "Active vulnerability scanner with the xray engine.",
            "B-Hunters-xray",
            "subdomain",
            "new",
            [Capability.ACTIVE_VULNERABILITY],
            ["finding"],
            upstream="https://github.com/B-Hunters/B-Hunters-xray",
        ),
        # --- capabilities the existing modules do not cover ---------------
        _native_spec(
            "service_fingerprint",
            "1.0.0",
            "Identifies the services running on each URL, with their versions, using "
            "banner grabbing, cookie and meta analysis, body markers, known path "
            "probing, favicon hashing and TLS certificate analysis.",
            [Capability.TECHNOLOGY_DETECTION],
            ["service"],
            upstream="in-process",
        ),
        _native_spec(
            "security_headers",
            "1.0.0",
            "Evaluates the presence and correctness of security response headers.",
            [Capability.SECURITY_HEADERS],
            ["finding"],
            upstream="in-process",
        ),
        _native_spec(
            "tls_configuration",
            "1.0.0",
            "Inspects TLS version, cipher selection and certificate validity.",
            [Capability.TLS_CONFIGURATION],
            ["finding"],
            upstream="in-process",
        ),
        _native_spec(
            "secret_scan",
            "1.0.0",
            "Credential detection over supplied source and JavaScript artefacts, with redaction.",
            [Capability.SECRET_DETECTION],
            ["secret"],
            upstream="in-process",
        ),
        _native_spec(
            "openapi_discovery",
            "1.0.0",
            "Locates and parses OpenAPI/Swagger specifications and checks documented operations.",
            [Capability.OPENAPI_DISCOVERY],
            ["url", "finding"],
            upstream="in-process",
        ),
        _native_spec(
            "graphql_analysis",
            "1.0.0",
            "Introspects a GraphQL endpoint and reviews its schema for exposure.",
            [Capability.GRAPHQL_ANALYSIS],
            ["url", "finding"],
            upstream="in-process",
        ),
        _native_spec(
            "dependency_analysis",
            "1.0.0",
            "Checks dependency manifests against the OSV advisory database when available.",
            [Capability.DEPENDENCY_ANALYSIS],
            ["finding"],
            upstream="https://github.com/google/osv-scanner",
        ),
        _native_spec(
            "asset_crawl",
            "1.0.0",
            "Crawls the target and records every URL it serves, with its kind, scope, "
            "status, content type and size. Metadata only: no body is ever stored.",
            [Capability.HTTP_CRAWL],
            ["url"],
            upstream="in-process",
        ),
    ]
    return specs


def _native_spec(
    name: str,
    version: str,
    description: str,
    capabilities: list[Capability],
    output_kinds: list[str],
    *,
    upstream: str,
    license_name: str = "Apache-2.0",
) -> AdapterSpec:
    return AdapterSpec(
        name=name,
        version=version,
        description=description,
        capabilities=capabilities,
        required_inputs=["target"],
        output_kinds=output_kinds,
        timeout_seconds=120.0,
        concurrency=8,
        supports_cancellation=True,
        max_retries=1,
        retry_backoff_seconds=1.0,
        required_permissions=["network"],
        container_image="",
        installation_requirements=["runs inside the platform worker"],
        license=license_name,
        upstream=upstream,
        maintenance_status="maintained",
        kind="native",
    )


# ----------------------------------------------------------------------
# Registry
# ----------------------------------------------------------------------
class AdapterRegistry:
    """Holds the available adapters and their health."""

    def __init__(self) -> None:
        self._adapters: dict[str, BaseAdapter] = {}
        self._specs: dict[str, AdapterSpec] = {}

    def register(
        self, spec: AdapterSpec, executor: Optional[Callable[[ScanRequest], Any]] = None
    ) -> BaseAdapter:
        adapter = BaseAdapter(spec, executor)
        self._adapters[spec.name] = adapter
        self._specs[spec.name] = spec
        return adapter

    def get(self, name: str) -> Optional[BaseAdapter]:
        return self._adapters.get(name)

    def spec(self, name: str) -> Optional[AdapterSpec]:
        return self._specs.get(name)

    def names(self) -> list[str]:
        return sorted(self._adapters)

    def all_adapters(self) -> list[BaseAdapter]:
        return [self._adapters[name] for name in sorted(self._adapters)]

    def enabled(self) -> list[BaseAdapter]:
        return [a for a in self.all_adapters() if a.spec.enabled]

    async def health(self, *, include_disabled: bool = False) -> dict[str, Any]:
        """Check every adapter and return a health summary."""
        results: list[dict[str, Any]] = []
        for adapter in self.all_adapters():
            if not adapter.spec.enabled and not include_disabled:
                results.append(
                    {
                        "name": adapter.name,
                        "version": adapter.version,
                        "status": HealthStatus.DISABLED.value,
                        "detail": "disabled",
                        "capabilities": [c.value for c in adapter.capabilities],
                    }
                )
                continue
            health = await adapter.health()
            results.append(
                {
                    "name": adapter.name,
                    "version": adapter.version,
                    "status": health.status.value,
                    "detail": health.detail,
                    "latency_ms": health.latency_ms,
                    "capabilities": [c.value for c in adapter.capabilities],
                    "kind": adapter.spec.kind,
                }
            )
        by_status: dict[str, int] = {}
        for item in results:
            by_status[item["status"]] = by_status.get(item["status"], 0) + 1
        return {
            "total": len(results),
            "by_status": by_status,
            "adapters": results,
            "checked_at": asyncio.get_running_loop().time(),
        }

    def specs(self) -> list[AdapterSpec]:
        return [self._specs[name] for name in sorted(self._specs)]


def build_default_registry(
    executors: Optional[dict[str, Callable[[ScanRequest], Any]]] = None,
) -> AdapterRegistry:
    """Build the registry with the default adapter set."""
    registry = AdapterRegistry()
    executors = executors or {}
    for spec in default_all_adapters():
        registry.register(spec, executors.get(spec.name))
    return registry
