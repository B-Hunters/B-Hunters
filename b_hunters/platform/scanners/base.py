"""The common scanner-adapter interface.

Every capability the platform can run - whether it is one of the existing
B-Hunters Karton workers or a new in-process adapter - is described by a
:class:`ScannerAdapter`.  The interface is deliberately declarative so
that the dashboard can show what a tool supports, what it needs, whether it
is healthy and which licence it ships under, without running it.

An adapter may either:

* **dispatch** work to an existing Karton worker, in which case the
  ``karton_task_type``/``karton_task_stage`` fields describe the headers
  the worker filters on, or
* **execute** in-process, in which case ``execute`` is implemented.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Optional, Protocol

log = logging.getLogger(__name__)


class Capability(str, Enum):
    """The scan capabilities the platform understands."""

    SUBDOMAIN_ENUMERATION = "subdomain_enumeration"
    HOST_RESOLUTION = "host_resolution"
    PORT_SCAN = "port_scan"
    SERVICE_DETECTION = "service_detection"
    TECHNOLOGY_DETECTION = "technology_detection"
    HTTP_CRAWL = "http_crawl"
    DIRECTORY_BRUTEFORCE = "directory_bruteforce"
    PARAMETER_DISCOVERY = "parameter_discovery"
    JAVASCRIPT_COLLECTION = "javascript_collection"
    JAVASCRIPT_ANALYSIS = "javascript_analysis"
    SECRET_DETECTION = "secret_detection"
    SCREENSHOT = "screenshot"
    XSS = "xss"
    SQL_INJECTION = "sql_injection"
    SSTI = "ssti"
    NUCLEI_TEMPLATES = "nuclei_templates"
    ACTIVE_VULNERABILITY = "active_vulnerability"
    SECURITY_HEADERS = "security_headers"
    TLS_CONFIGURATION = "tls_configuration"
    OPENAPI_DISCOVERY = "openapi_discovery"
    GRAPHQL_ANALYSIS = "graphql_analysis"
    DEPENDENCY_ANALYSIS = "dependency_analysis"
    AUTHENTICATED_CRAWL = "authenticated_crawl"
    BROWSER_CRAWL = "browser_crawl"


class HealthStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"
    DISABLED = "disabled"


@dataclass
class AdapterHealth:
    """The result of an adapter health check."""

    status: HealthStatus = HealthStatus.UNKNOWN
    detail: str = ""
    checked_at: float = field(default_factory=time.time)
    latency_ms: int = 0
    version: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data


@dataclass
class ScanRequest:
    """The input contract of a scanner adapter."""

    scan_id: str
    targets: list[str]
    options: dict[str, Any] = field(default_factory=dict)
    #: The authorised scope the request must stay inside.
    scope: Any = None
    #: Files or seeds supplied by the operator.
    seeds: list[str] = field(default_factory=list)
    test_accounts: list[dict[str, Any]] = field(default_factory=list)
    timeout: float = 300.0
    cancel_token: Optional[Any] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "targets": list(self.targets),
            "options": dict(self.options),
            "seeds": list(self.seeds),
            "timeout": self.timeout,
        }


@dataclass
class ScanResult:
    """The output contract of a scanner adapter."""

    scanner: str
    ok: bool = True
    error: str = ""
    #: Normalised results.  ``kind`` selects the shape:
    #: ``url``, ``host``, ``port``, ``technology``, ``javascript``,
    #: ``secret``, ``finding``, ``screenshot``.
    kind: str = "url"
    items: list[dict[str, Any]] = field(default_factory=list)
    duration_ms: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)
    cancelled: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanner": self.scanner,
            "ok": self.ok,
            "error": self.error,
            "kind": self.kind,
            "items": self.items,
            "duration_ms": self.duration_ms,
            "metadata": self.metadata,
            "cancelled": self.cancelled,
        }


class ScannerAdapter(Protocol):
    """The protocol every scanner adapter implements."""

    name: str
    version: str
    capabilities: Sequence[Capability]

    async def health(self) -> AdapterHealth: ...

    async def execute(self, request: ScanRequest) -> ScanResult: ...


@dataclass
class AdapterSpec:
    """Declarative metadata about an adapter."""

    name: str
    version: str
    description: str
    capabilities: list[Capability]
    #: The Karton identity that implements it, when it is a Karton worker.
    karton_identity: str = ""
    #: The Karton task headers the worker filters on.
    karton_task_type: str = ""
    karton_task_stage: str = ""
    #: What the adapter needs in order to run.
    required_inputs: list[str] = field(default_factory=list)
    #: The result kinds it can produce.
    output_kinds: list[str] = field(default_factory=list)
    timeout_seconds: float = 300.0
    concurrency: int = 4
    #: Whether the adapter supports cooperative cancellation.
    supports_cancellation: bool = False
    #: How the adapter behaves when it fails.
    max_retries: int = 0
    retry_backoff_seconds: float = 2.0
    #: The capabilities the agent needs for the adapter to run.
    required_permissions: list[str] = field(default_factory=list)
    #: Container image, when the adapter is containerised.
    container_image: str = ""
    installation_requirements: list[str] = field(default_factory=list)
    license: str = "unknown"
    #: Upstream project and whether it is still maintained.
    upstream: str = ""
    maintenance_status: str = "unknown"
    enabled: bool = True
    #: ``"karton"`` dispatches to a worker, ``"native"`` runs in-process.
    kind: str = "native"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["capabilities"] = [c.value for c in self.capabilities]
        return data


class BaseAdapter:
    """Convenience base class implementing the declarative half of the protocol."""

    def __init__(self, spec: AdapterSpec, executor: Optional[Callable[[ScanRequest], Any]] = None) -> None:
        self.spec = spec
        self.name = spec.name
        self.version = spec.version
        self.capabilities = spec.capabilities
        self._executor = executor
        self._last_health: Optional[AdapterHealth] = None

    async def health(self) -> AdapterHealth:
        if not self.spec.enabled:
            health = AdapterHealth(
                status=HealthStatus.DISABLED, detail="the adapter is disabled", version=self.version
            )
            self._last_health = health
            return health
        started = time.monotonic()
        try:
            probe = getattr(self, "probe", None)
            if self._executor is not None and probe is not None:
                detail = await probe()
                status = HealthStatus.HEALTHY
            else:
                detail = "adapter is registered and ready"
                status = HealthStatus.HEALTHY
        except Exception as exc:
            status = HealthStatus.UNAVAILABLE
            detail = f"{type(exc).__name__}: {exc}"
        health = AdapterHealth(
            status=status,
            detail=detail,
            latency_ms=int((time.monotonic() - started) * 1000),
            version=self.version,
        )
        self._last_health = health
        return health

    async def execute(self, request: ScanRequest) -> ScanResult:
        if not self.spec.enabled:
            return ScanResult(scanner=self.name, ok=False, error="the adapter is disabled")
        if self._executor is None:
            return ScanResult(
                scanner=self.name,
                ok=False,
                error=f"adapter '{self.name}' is dispatch-only and has no in-process executor",
            )
        started = time.monotonic()
        try:
            result = self._executor(request)
            if asyncio.iscoroutine(result):
                result = await result
        except asyncio.CancelledError:
            return ScanResult(scanner=self.name, ok=False, error="cancelled", cancelled=True)
        except Exception as exc:
            return ScanResult(scanner=self.name, ok=False, error=f"{type(exc).__name__}: {exc}")
        result.duration_ms = int((time.monotonic() - started) * 1000)
        return result
