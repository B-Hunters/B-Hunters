"""Scan lifecycle endpoints: creation, preview, control and monitoring."""

from __future__ import annotations

import asyncio
import re
import time
from typing import Any, Optional
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator

from ...agents.orchestrator import ScanContext, ScanOrchestrator, ScanProfile
from ...agents.provider import ProviderConfig
from ...security.scope import ScopeEnforcer, build_policy_from_scan
from ..deps import (
    CurrentUser,
    Services,
    current_user,
    enforce_csrf,
    get_services,
    require_role,
    strip_object_id,
)

router = APIRouter(prefix="/scans", tags=["scans"])

#: A hostname label pattern.
_LABEL = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")


class ScanTargets(BaseModel):
    urls: list[str] = Field(default_factory=list)
    authorized_hosts: list[str] = Field(default_factory=list)
    start_paths: list[str] = Field(default_factory=list)
    url_lists: list[str] = Field(default_factory=list)
    excluded_paths: list[str] = Field(default_factory=list)


class ScanRequestModel(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=4000)
    targets: ScanTargets
    profile: str = Field(default="standard", max_length=64)
    scanners: list[str] = Field(default_factory=list)
    agent_roles: list[str] = Field(default_factory=list)
    artifacts: list[str] = Field(default_factory=list)
    schema_artifacts: list[str] = Field(default_factory=list)
    test_accounts: list[dict[str, Any]] = Field(default_factory=list)
    max_concurrency: int = Field(default=4, ge=1, le=32)
    max_requests_per_second: float = Field(default=10.0, ge=0.1, le=500)
    request_timeout: float = Field(default=20.0, ge=1, le=300)
    max_duration_seconds: int = Field(default=3600, ge=30, le=86400)
    safe_mode: bool = True
    allow_state_changing: bool = False
    test_environment: bool = False
    provider: str = Field(default="", max_length=128)

    @field_validator("name")
    @classmethod
    def _strip_name(cls, value: str) -> str:
        return value.strip()


class ScopeValidation(BaseModel):
    urls: list[str] = Field(default_factory=list)
    authorized_hosts: list[str] = Field(default_factory=list)
    excluded_paths: list[str] = Field(default_factory=list)
    allow_private_network: bool = False
    allow_state_changing: bool = False


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def _normalise_host(host: str) -> str:
    host = (host or "").strip().lower().rstrip(".")
    if "://" in host:
        host = urlsplit(host).hostname or ""
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host


def _host_from_url(url: str) -> str:
    try:
        parts = urlsplit(url if "://" in url else f"https://{url}")
        return (parts.hostname or "").lower()
    except ValueError:
        return ""


def _is_valid_host(host: str) -> bool:
    if not host or len(host) > 253:
        return False
    if host.replace(".", "").isdigit():
        # A bare IPv4 literal is allowed only in an explicitly isolated lab.
        return True
    labels = host.split(".")
    if not labels or len(labels) > 8:
        return False
    return all(_LABEL.match(label) for label in labels)


def _validate_scope(
    *,
    urls: list[str],
    authorized_hosts: list[str],
    excluded_paths: list[str],
    allow_private_network: bool,
    allow_state_changing: bool,
    strict: bool = True,
) -> dict[str, Any]:
    """Validate that every target is covered by the authorised host list.

    A target supplied by the operator must be inside the declared scope.  A
    host discovered later during crawling is *not* automatically authorised:
    the authorised list is fixed when the scan is created.
    """
    hosts = [_normalise_host(h) for h in authorized_hosts if h and h.strip()]
    hosts = [h for h in hosts if h]
    invalid_hosts = [h for h in hosts if not _is_valid_host(h)]
    if not hosts:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="at least one explicitly authorised host is required",
        )
    if invalid_hosts:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"invalid authorised host(s): {', '.join(invalid_hosts)}",
        )

    policy = build_policy_from_scan(
        authorized_hosts=hosts,
        excluded_paths=excluded_paths,
        allow_private_network=allow_private_network,
        allow_http=True,
        allow_state_changing=allow_state_changing,
    )
    enforcer = ScopeEnforcer(policy)

    out_of_scope: list[dict[str, str]] = []
    accepted: list[str] = []
    for url in urls:
        url = (url or "").strip()
        if not url:
            continue
        if "://" not in url:
            url = f"https://{url}"
        host = _host_from_url(url)
        if not host:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=f"could not parse the target '{url}'"
            )
        decision = enforcer.evaluate_url(url, resolve=False)
        if not decision.allowed:
            out_of_scope.append({"url": url, "reason": decision.reason})
        else:
            accepted.append(url)

    if strict and out_of_scope and not accepted:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "message": "no target is inside the authorised scope",
                "out_of_scope": out_of_scope,
            },
        )

    return {
        "authorized_hosts": hosts,
        "accepted_urls": accepted,
        "out_of_scope": out_of_scope,
        "policy": policy,
    }


def _profile_for(name: str, overrides: dict[str, Any]) -> ScanProfile:
    if name == "recon":
        profile = ScanProfile.reconnaissance_only()
    else:
        profile = ScanProfile.default()
    profile.name = name
    for key, value in overrides.items():
        if value in (None, "", [], 0):
            continue
        if hasattr(profile, key):
            setattr(profile, key, value)
    return profile


# ----------------------------------------------------------------------
# Endpoints
# ----------------------------------------------------------------------
@router.post("/validate-scope")
async def validate_scope(
    payload: ScopeValidation,
    user: CurrentUser = Depends(current_user),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """Validate a proposed scope without creating a scan."""
    result = _validate_scope(
        urls=payload.urls,
        authorized_hosts=payload.authorized_hosts,
        excluded_paths=payload.excluded_paths,
        allow_private_network=payload.allow_private_network,
        allow_state_changing=payload.allow_state_changing,
        strict=False,
    )
    services.audit.record(
        action="scan.validate_scope",
        actor=user.username,
        detail={"hosts": result["authorized_hosts"], "accepted": len(result["accepted_urls"])},
    )
    return {
        "authorized_hosts": result["authorized_hosts"],
        "accepted_urls": result["accepted_urls"],
        "out_of_scope": result["out_of_scope"],
        "valid": bool(result["accepted_urls"]),
    }


@router.post("/preview")
async def preview_scan(
    payload: ScanRequestModel,
    user: CurrentUser = Depends(current_user),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """Return a scan preview without creating anything."""
    result = _validate_scope(
        urls=payload.targets.urls,
        authorized_hosts=payload.targets.authorized_hosts,
        excluded_paths=payload.targets.excluded_paths,
        allow_private_network=payload.test_environment,
        allow_state_changing=payload.allow_state_changing,
        strict=False,
    )
    profile = _profile_for(
        payload.profile,
        {
            "agent_roles": payload.agent_roles,
            "scanners": payload.scanners,
            "max_concurrency": payload.max_concurrency,
            "max_requests_per_second": payload.max_requests_per_second,
            "request_timeout": payload.request_timeout,
            "max_duration_seconds": payload.max_duration_seconds,
            "allow_state_changing": payload.allow_state_changing,
            "safe_mode": payload.safe_mode,
        },
    )
    known_scanners = {spec.name for spec in services.scanner_registry_specs()}
    unknown = [name for name in profile.scanners if name not in known_scanners]
    return {
        "name": payload.name,
        "profile": profile.name,
        "authorized_hosts": result["authorized_hosts"],
        "accepted_urls": result["accepted_urls"],
        "out_of_scope": result["out_of_scope"],
        "agent_roles": profile.agent_roles,
        "scanners": profile.scanners,
        "unknown_scanners": unknown,
        "max_duration_seconds": profile.max_duration_seconds,
        "safe_mode": profile.safe_mode,
        "warnings": _preview_warnings(profile, unknown, result),
    }


def _preview_warnings(profile: ScanProfile, unknown: list[str], result: dict[str, Any]) -> list[str]:
    warnings: list[str] = []
    if unknown:
        warnings.append(f"unknown scanner(s): {', '.join(unknown)}")
    if result["out_of_scope"]:
        warnings.append(
            f"{len(result['out_of_scope'])} target(s) are outside the authorised scope and will be refused"
        )
    if not profile.agent_roles:
        warnings.append("no agent roles selected; only deterministic scanners will run")
    if profile.allow_state_changing:
        warnings.append(
            "state-changing requests are enabled; only use this against a disposable test environment"
        )
    return warnings


@router.get("/scanner-specs")
async def scanner_specs(
    user: CurrentUser = Depends(current_user),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """Return the declarative specs of every available scanner adapter."""
    specs = services.scanner_registry_specs()
    return {
        "scanners": [
            {
                "name": spec.name,
                "version": spec.version,
                "description": spec.description,
                "capabilities": [c.value for c in spec.capabilities],
                "kind": spec.kind,
                "karton_identity": spec.karton_identity,
                "license": spec.license,
                "maintenance_status": spec.maintenance_status,
                "upstream": spec.upstream,
                "timeout_seconds": spec.timeout_seconds,
                "supports_cancellation": spec.supports_cancellation,
                "required_permissions": spec.required_permissions,
            }
            for spec in specs
        ],
        "count": len(specs),
    }


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_scan(
    payload: ScanRequestModel,
    request: Request,
    user: CurrentUser = Depends(require_role("operator")),
    services: Services = Depends(get_services),
    csrf: None = Depends(enforce_csrf),
) -> dict[str, Any]:
    """Create a scan.  The scan is created in ``queued`` state."""
    result = _validate_scope(
        urls=payload.targets.urls,
        authorized_hosts=payload.targets.authorized_hosts,
        excluded_paths=payload.targets.excluded_paths,
        allow_private_network=payload.test_environment,
        allow_state_changing=payload.allow_state_changing,
    )
    profile = _profile_for(
        payload.profile,
        {
            "agent_roles": payload.agent_roles,
            "scanners": payload.scanners,
            "max_concurrency": payload.max_concurrency,
            "max_requests_per_second": payload.max_requests_per_second,
            "request_timeout": payload.request_timeout,
            "max_duration_seconds": payload.max_duration_seconds,
            "allow_state_changing": payload.allow_state_changing,
            "safe_mode": payload.safe_mode,
        },
    )

    definition = {
        "description": payload.description,
        "targets": result["accepted_urls"],
        "start_paths": payload.targets.start_paths,
        "url_lists": payload.targets.url_lists,
        "artifacts": payload.artifacts,
        "schema_artifacts": payload.schema_artifacts,
        "test_accounts": [{"username": account.get("username", "")} for account in payload.test_accounts],
        "profile": profile.to_dict() if hasattr(profile, "to_dict") else {},
        "provider": payload.provider,
        "test_environment": payload.test_environment,
        "safe_mode": payload.safe_mode,
    }
    scope = {
        "authorized_hosts": result["authorized_hosts"],
        "excluded_paths": payload.targets.excluded_paths,
        "allow_private_network": payload.test_environment,
        "allow_state_changing": payload.allow_state_changing,
        "max_requests_per_second": payload.max_requests_per_second,
        "max_concurrency": payload.max_concurrency,
        "request_timeout": payload.request_timeout,
        "max_duration_seconds": payload.max_duration_seconds,
    }

    record = services.scans.create(
        {
            "name": payload.name,
            "status": "queued",
            "created_by": user.username,
            "created_by_id": user.user_id,
            "definition": definition,
            "scope": scope,
            "stats": {},
        }
    )
    services.events.append(
        scan_id=record.scan_id,
        kind="scan.created",
        payload={"name": record.name, "profile": profile.name, "hosts": scope["authorized_hosts"]},
        actor=user.username,
    )
    services.audit.record(
        action="scan.create",
        actor=user.username,
        target_type="scan",
        target_id=record.scan_id,
        detail={"name": record.name, "hosts": scope["authorized_hosts"]},
        ip_address=request.client.host if request.client else "",
    )
    return record.public()


@router.get("")
async def list_scans(
    status_filter: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    user: CurrentUser = Depends(current_user),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """List scans with their status and finding counts."""
    scans = services.scans.list(status=status_filter or "", limit=limit, offset=offset)
    items = []
    for scan in scans:
        public = scan.public()
        public["finding_counts"] = services.findings.severity_counts(scan.scan_id)
        items.append(public)
    return {"items": items, "count": len(items), "total": services.scans.count()}


@router.get("/{scan_id}")
async def get_scan(
    scan_id: str,
    user: CurrentUser = Depends(current_user),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """Return the full detail of one scan."""
    scan = services.scans.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="the scan does not exist")
    public = scan.public()
    public["finding_counts"] = services.findings.severity_counts(scan_id)
    public["task_counts"] = services.tasks.counts_by_status(scan_id)
    public["agents"] = [strip_object_id(item) for item in services.agents.list_for_scan(scan_id)]
    public["scope_violations"] = len(scan.scope.get("violations", []))
    return public


@router.post("/{scan_id}/start")
async def start_scan(
    scan_id: str,
    request: Request,
    user: CurrentUser = Depends(require_role("operator")),
    services: Services = Depends(get_services),
    csrf: None = Depends(enforce_csrf),
) -> dict[str, Any]:
    """Start a queued scan."""
    scan = services.scans.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="the scan does not exist")
    if scan.status not in {"draft", "queued"}:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"the scan is '{scan.status}' and cannot be started",
        )

    definition = scan.definition or {}
    profile_data = definition.get("profile") or {}
    profile = ScanProfile.from_dict(profile_data) if profile_data else ScanProfile.default()
    context = ScanContext(
        scan_id=scan_id,
        name=scan.name,
        targets=list(definition.get("targets", [])),
        authorized_hosts=list((scan.scope or {}).get("authorized_hosts", [])),
        excluded_paths=list((scan.scope or {}).get("excluded_paths", [])),
        profile=profile,
        test_accounts=list(definition.get("test_accounts", [])),
        artifacts=list(definition.get("artifacts", [])),
        schema_artifacts=list(definition.get("schema_artifacts", [])),
        safe_mode=bool(definition.get("safe_mode", True)),
        allow_private_network=bool((scan.scope or {}).get("allow_private_network", False)),
        allow_state_changing=bool((scan.scope or {}).get("allow_state_changing", False)),
        max_duration_seconds=int((scan.scope or {}).get("max_duration_seconds", 3600)),
        max_requests_per_second=float((scan.scope or {}).get("max_requests_per_second", 10.0)),
        request_timeout=float((scan.scope or {}).get("request_timeout", 20.0)),
        workspace_root=services.settings.agent_workspace_root,
        options={"provider": definition.get("provider", "")},
    )

    orchestrator = _build_orchestrator(services)
    services.orchestrators[scan_id] = orchestrator

    asyncio.create_task(_run_scan(orchestrator, context, services))
    services.audit.record(
        action="scan.start",
        actor=user.username,
        target_type="scan",
        target_id=scan_id,
        ip_address=request.client.host if request.client else "",
    )
    return {"status": "starting", "scan_id": scan_id}


async def _run_scan(orchestrator: ScanOrchestrator, context: ScanContext, services: Services) -> None:
    try:
        await orchestrator.run(context)
    except asyncio.CancelledError:
        services.scans.set_status(context.scan_id, "cancelled")
    except Exception as exc:  # pragma: no cover - defensive
        services.scans.set_status(context.scan_id, "failed", error=str(exc))
    finally:
        services.orchestrators.pop(context.scan_id, None)


def _build_orchestrator(services: Services) -> ScanOrchestrator:
    from ...agents.provider import Provider
    from ...scanners.graphql_adapter import graphql_analysis_executor
    from ...scanners.native import (
        dependency_analysis_executor,
        openapi_discovery_executor,
        secret_scan_executor,
        security_headers_executor,
        tls_configuration_executor,
    )
    from ...scanners.registry import build_default_registry
    from ...tools.builtin import build_tool_registry

    registry = build_default_registry(
        {
            "security_headers": security_headers_executor,
            "tls_configuration": tls_configuration_executor,
            "secret_scan": secret_scan_executor,
            "openapi_discovery": openapi_discovery_executor,
            "graphql_analysis": graphql_analysis_executor,
            "dependency_analysis": dependency_analysis_executor,
        }
    )

    def provider_factory(provider_name: str = "") -> Provider:
        config = _provider_config(services, provider_name)
        return Provider(config)

    return ScanOrchestrator(
        database=services.db,
        settings=services.settings,
        provider_factory=provider_factory,
        tool_registry=build_tool_registry(),
        scanner_registry=registry,
    )


def _provider_config(services: Services, provider_name: str = "") -> ProviderConfig:
    from ...agents.provider import provider_config_from_env

    if provider_name:
        document = services.providers.get(provider_name)
        if document:
            return ProviderConfig(
                name=document.get("name", provider_name),
                base_url=document.get("base_url", ""),
                api_key=document.get("api_key", "") or "",
                model=document.get("model", ""),
                role_models=document.get("role_models", {}) or {},
                temperature=float(document.get("temperature", 0.0)),
                max_output_tokens=int(document.get("max_output_tokens", 4096)),
                max_context_tokens=int(document.get("max_context_tokens", 128000)),
                timeout_seconds=float(document.get("timeout_seconds", 120.0)),
                max_retries=int(document.get("max_retries", 2)),
                concurrency=int(document.get("concurrency", 4)),
                extra_headers=document.get("extra_headers", {}) or {},
                enabled=bool(document.get("enabled", True)),
            )
    return provider_config_from_env()


@router.post("/{scan_id}/pause")
async def pause_scan(
    scan_id: str,
    request: Request,
    user: CurrentUser = Depends(require_role("operator")),
    services: Services = Depends(get_services),
    csrf: None = Depends(enforce_csrf),
) -> dict[str, Any]:
    """Pause a running scan.

    The pause is a real control: the orchestrator checks the scan status
    before starting each task and will not start new work while the scan
    is paused.
    """
    scan = services.scans.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="the scan does not exist")
    if scan.status not in {"running", "queued"}:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"the scan is '{scan.status}' and cannot be paused",
        )
    services.scans.set_status(scan_id, "paused")
    services.events.append(scan_id=scan_id, kind="scan.paused", payload={"at": time.time()})
    services.audit.record(
        action="scan.pause",
        actor=user.username,
        target_type="scan",
        target_id=scan_id,
        ip_address=request.client.host if request.client else "",
    )
    return {"status": "paused", "scan_id": scan_id}


@router.post("/{scan_id}/resume")
async def resume_scan(
    scan_id: str,
    request: Request,
    user: CurrentUser = Depends(require_role("operator")),
    services: Services = Depends(get_services),
    csrf: None = Depends(enforce_csrf),
) -> dict[str, Any]:
    """Resume a paused scan."""
    scan = services.scans.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="the scan does not exist")
    if scan.status != "paused":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"the scan is '{scan.status}' and cannot be resumed",
        )
    services.scans.set_status(scan_id, "running")
    services.events.append(scan_id=scan_id, kind="scan.resumed", payload={"at": time.time()})
    services.audit.record(
        action="scan.resume",
        actor=user.username,
        target_type="scan",
        target_id=scan_id,
        ip_address=request.client.host if request.client else "",
    )
    return {"status": "resumed", "scan_id": scan_id}


@router.post("/{scan_id}/stop")
async def stop_scan(
    scan_id: str,
    request: Request,
    user: CurrentUser = Depends(require_role("operator")),
    services: Services = Depends(get_services),
    csrf: None = Depends(enforce_csrf),
) -> dict[str, Any]:
    """Stop a scan and cancel its pending tasks."""
    scan = services.scans.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="the scan does not exist")
    orchestrator = services.orchestrators.get(scan_id)
    if orchestrator is not None:
        orchestrator.cancel(scan_id)
    else:
        services.scans.set_status(scan_id, "cancelled")
        for task in services.tasks.list_for_scan(scan_id):
            if task.get("status") in {"pending", "ready", "running"}:
                services.tasks.set_status(task["task_id"], "cancelled", error="stopped by operator")
        services.events.append(scan_id=scan_id, kind="scan.cancelled", payload={"at": time.time()})
    services.audit.record(
        action="scan.stop",
        actor=user.username,
        target_type="scan",
        target_id=scan_id,
        ip_address=request.client.host if request.client else "",
    )
    return {"status": "stopping", "scan_id": scan_id}


@router.get("/{scan_id}/events")
async def scan_events(
    scan_id: str,
    after: int = 0,
    limit: int = 200,
    user: CurrentUser = Depends(current_user),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """Return the scan events after a sequence number (used for SSE replay)."""
    if services.scans.get(scan_id) is None:
        raise HTTPException(status_code=404, detail="the scan does not exist")
    events = services.events.list_after(scan_id, after_seq=after, limit=limit)
    return {
        "events": [_event_public(event) for event in events],
        "last_seq": events[-1]["seq"] if events else after,
    }


def _event_public(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "seq": event.get("seq"),
        "event_id": event.get("event_id"),
        "kind": event.get("kind"),
        "at": event.get("at"),
        "actor": event.get("actor"),
        "payload": event.get("payload", {}),
    }


@router.get("/{scan_id}/tasks")
async def scan_tasks(
    scan_id: str,
    user: CurrentUser = Depends(current_user),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """Return the task graph of a scan."""
    if services.scans.get(scan_id) is None:
        raise HTTPException(status_code=404, detail="the scan does not exist")
    tasks = services.tasks.list_for_scan(scan_id)
    return {
        "tasks": [
            {
                "task_id": task.get("task_id"),
                "title": task.get("title"),
                "kind": task.get("kind"),
                "agent_role": task.get("agent_role"),
                "status": task.get("status"),
                "depends_on": task.get("depends_on", []),
                "attempts": task.get("attempts", 0),
                "error": task.get("error", ""),
                "created_at": task.get("created_at"),
                "updated_at": task.get("updated_at"),
                "karton_task_uid": task.get("karton_task_uid", ""),
            }
            for task in tasks
        ],
        "counts": services.tasks.counts_by_status(scan_id),
    }


@router.get("/{scan_id}/agents")
async def scan_agents(
    scan_id: str,
    user: CurrentUser = Depends(current_user),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """Return the live agent status of a scan."""
    if services.scans.get(scan_id) is None:
        raise HTTPException(status_code=404, detail="the scan does not exist")
    return {"agents": [strip_object_id(item) for item in services.agents.list_for_scan(scan_id)]}


@router.get("/{scan_id}/messages")
async def scan_messages(
    scan_id: str,
    limit: int = 200,
    kind: str = "",
    user: CurrentUser = Depends(current_user),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """Return the structured agent collaboration messages."""
    if services.scans.get(scan_id) is None:
        raise HTTPException(status_code=404, detail="the scan does not exist")
    messages = services.messages.list_for_scan(scan_id, limit=limit, kind=kind)
    return {
        "messages": [strip_object_id(item) for item in messages],
        "count": len(messages),
    }


@router.get("/{scan_id}/tool-calls")
async def scan_tool_calls(
    scan_id: str,
    limit: int = 200,
    agent_role: str = "",
    user: CurrentUser = Depends(current_user),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """Return the tool invocation history of a scan."""
    if services.scans.get(scan_id) is None:
        raise HTTPException(status_code=404, detail="the scan does not exist")
    calls = services.tool_calls.list_for_scan(scan_id, limit=limit, agent_role=agent_role)
    failed, total = services.tool_calls.failure_rate(scan_id)
    return {
        "tool_calls": [strip_object_id(item) for item in calls],
        "total": total,
        "failed": failed,
    }
