"""Scan lifecycle endpoints: creation, preview, control and monitoring."""

from __future__ import annotations

import re
import time
from typing import Any, Optional
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator

from ...agents.orchestrator import (
    REPORTING_ROLES,
    VERIFICATION_ROLES,
    ScanProfile,
)
from ...scan_factory import build_scan
from ...scanners import worker_output
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
    #: The hosts the scan must not touch, even though a wildcard in the
    #: authorised list covers them.  A bug bounty programme names the
    #: assets that are out of scope, and a wildcard is the usual way of
    #: covering a domain - so the exclusions have to be said separately.
    denied_hosts: list[str] = Field(default_factory=list)


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
    #: The identities the scan logs in with.  The first is the primary
    #: one; the second is what an access-control comparison uses.
    identity_ids: list[str] = Field(default_factory=list)
    #: What to do when the session cannot be established.
    #:
    #: ``fail`` stops the scan: an authenticated scan that runs without
    #: a session reports what an unauthenticated scan finds, which is
    #: not what the operator asked for.  ``continue_unauthenticated``
    #: runs it anyway and says so.
    on_login_failure: str = Field(default="fail")
    max_concurrency: int = Field(default=4, ge=1, le=32)
    max_requests_per_second: float = Field(default=10.0, ge=0.1, le=500)
    request_timeout: float = Field(default=20.0, ge=1, le=300)
    max_duration_seconds: int = Field(default=3600, ge=30, le=86400)
    safe_mode: bool = True
    allow_state_changing: bool = False
    test_environment: bool = False
    provider: str = Field(default="", max_length=128)
    #: Whether this scan runs the independent verifier.  ``None`` follows
    #: the platform's setting; ``True`` or ``False`` decide it for this
    #: scan alone.
    independent_verifier: Optional[bool] = None

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
    """Is this a host the platform can authorise?

    A leading wildcard is allowed.  ``*.example.com`` is how a bug
    bounty programme covers a domain - the scope engine matches that
    form, and the exclusions are expressed against it - so the
    validator must not be stricter than the matcher.  A validator that
    rejects the wildcard makes it impossible to say what the scan
    covers.
    """
    if not host or len(host) > 253:
        return False
    if host.replace(".", "").isdigit():
        # A bare IPv4 literal is allowed only in an explicitly isolated lab.
        return True
    labels = host.split(".")
    if not labels or len(labels) > 8:
        return False
    if labels[0] == "*":
        # The wildcard covers the subdomains of the domain behind it.
        labels = labels[1:]
        if not labels:
            return False
    return all(_LABEL.match(label) for label in labels)


def _validate_scope(
    *,
    urls: list[str],
    authorized_hosts: list[str],
    excluded_paths: list[str],
    allow_private_network: bool,
    allow_state_changing: bool,
    denied_hosts: list[str] | None = None,
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
        denied_hosts=denied_hosts or [],
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
        "denied_hosts": [str(h).strip().lower() for h in (denied_hosts or []) if str(h).strip()],
        "accepted_urls": accepted,
        "out_of_scope": out_of_scope,
        "policy": policy,
    }


def _profile_for(
    name: str,
    overrides: dict[str, Any],
    *,
    verification_enabled: bool = False,
) -> ScanProfile:
    """The profile of a scan.

    The independent verifier is opt-in.  It re-checks every candidate
    finding, which costs a request each, so it is left out unless the
    platform is configured to run it or the scan names the role itself.
    """
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
    # The reporting role always runs: it reconciles the findings and
    # records a verdict for each of them.  The independent verifier is
    # opt-in - it re-checks every candidate finding, which costs a
    # request each - so it is left out unless the platform is configured
    # to run it or the scan names the role itself.
    roles = list(profile.agent_roles)
    for role in REPORTING_ROLES:
        if role not in roles:
            roles.append(role)
    if verification_enabled:
        for role in VERIFICATION_ROLES:
            if role not in roles:
                roles.append(role)
    profile.agent_roles = roles
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
        verification_enabled=(
            payload.independent_verifier
            if payload.independent_verifier is not None
            else services.settings.agent_verification_enabled
        ),
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
        "independent_verifier": "verifier" in profile.agent_roles,
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
        denied_hosts=payload.targets.denied_hosts,
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
        verification_enabled=(
            payload.independent_verifier
            if payload.independent_verifier is not None
            else services.settings.agent_verification_enabled
        ),
    )

    # The document of the scan.  The runner makes the same document when
    # a schedule comes due, so that a scheduled scan and a requested one
    # are comparable.
    document = build_scan(
        name=payload.name,
        payload=payload.model_dump(),
        profile=profile,
        accepted_urls=result["accepted_urls"],
        authorized_hosts=result["authorized_hosts"],
        denied_hosts=result["denied_hosts"],
        description=payload.description,
        created_by=user.username,
        created_by_id=user.user_id,
    )
    scope = document["scope"]

    record = services.scans.create(document)
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
    """Queue a scan for the runner.

    The API does not run the scan: it writes a job document and returns.
    The scan therefore survives a restart of the API, and the runner is
    the only process that runs the agents.
    """
    scan = services.scans.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="the scan does not exist")
    if scan.status not in {"draft", "queued"}:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"the scan is '{scan.status}' and cannot be started",
        )
    if services.jobs.find_live(scan_id) is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="the scan already has a job in flight",
        )

    job = services.jobs.enqueue(
        kind="scan",
        payload={
            "scan_id": scan_id,
            # The target key arrives with the phase checkpoints; until
            # then it is empty and the runner runs the job without a
            # target lock.
            "target_key": getattr(scan, "target_key", ""),
        },
        max_attempts=services.settings.job_max_attempts,
    )
    services.scans.set_status(scan_id, "queued")
    services.events.append(
        scan_id=scan_id,
        kind="scan.queued",
        payload={"job_id": job["job_id"]},
        actor=user.username,
    )
    services.audit.record(
        action="scan.start",
        actor=user.username,
        target_type="scan",
        target_id=scan_id,
        ip_address=request.client.host if request.client else "",
    )
    return {"status": "queued", "scan_id": scan_id, "job_id": job["job_id"]}


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
    """Stop a scan and cancel its pending tasks.

    A scan that is still queued has not run at all: its job is cancelled,
    so it never starts.  A scan that is already running notices the
    ``stopping`` status through the database and stops on its own.
    """
    scan = services.scans.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="the scan does not exist")

    job = services.jobs.find_live(scan_id)
    if job is not None:
        services.jobs.cancel(job["job_id"])
    services.scans.set_status(scan_id, "stopping")
    for task in services.tasks.list_for_scan(scan_id):
        if task.get("status") in {"pending", "ready", "running"}:
            services.tasks.set_status(task["task_id"], "cancelled", error="stopped by operator")
    services.events.append(
        scan_id=scan_id,
        kind="scan.stop_requested",
        payload={"at": time.time(), "job_id": job["job_id"] if job else ""},
        actor=user.username,
    )
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


@router.get("/{scan_id}/services")
async def scan_services(
    scan_id: str,
    user: CurrentUser = Depends(current_user),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """The service inventory of a scan: what runs where, and which version.

    The inventory is what the fingerprinting adapter and the scanner
    workers identified for every URL, with the signal that identified it.
    """
    if services.scans.get(scan_id) is None:
        raise HTTPException(status_code=404, detail="the scan does not exist")
    documents = services.services.list_for_scan(scan_id)
    return {
        "scan_id": scan_id,
        "urls": documents,
        "summary": services.services.summary(scan_id),
    }


@router.get("/{scan_id}/scanners")
async def scan_scanners(
    scan_id: str,
    user: CurrentUser = Depends(current_user),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """What every scanner worker did, and what it found.

    The console scan starts seventeen worker containers at once, so a
    worker that finds nothing and a worker that never ran look the same.
    This answers the difference: the task counters say which workers
    took part, and the documents they wrote say what they found.
    """
    scan = services.scans.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="the scan does not exist")

    participation = dict(scan.workers or {})
    live = _live_worker_tasks(services)
    connected = _connected_workers(services)

    # While the scan runs, the participation is not recorded yet.  The
    # counters from before the scan say which workers took part in it.
    if not participation:
        before = scan.workers_before or {}
        participation = {
            identity: count - int(before.get(identity, 0))
            for identity, count in live.items()
            if count - int(before.get(identity, 0)) > 0
        }

    report = worker_output.scanner_report(
        services.db,
        scan_id,
        participation=participation,
        live=live,
        connected=connected,
    )
    report["participation"] = participation
    return report


def _live_worker_tasks(services: Services) -> dict[str, int]:
    """How many tasks each worker has consumed, over every scan.

    The per-scan counters are written when the scan ends, so during a
    scan this is the only view of who is working.
    """
    try:
        from karton.core import Config, Producer

        producer = Producer(
            config=Config(path=services.settings.karton_config_path),
            identity=services.settings.karton_identity,
        )
        raw = producer.backend.redis.hgetall("karton.metrics.consumed")
    except Exception:  # pragma: no cover - the backend may be down
        return {}
    counts: dict[str, int] = {}
    for identity, value in (raw or {}).items():
        name = identity.decode() if isinstance(identity, bytes) else str(identity)
        try:
            counts[name] = int(value)
        except (TypeError, ValueError):
            continue
    return counts


def _connected_workers(services: Services) -> list[str]:
    """The workers that are bound to the task router right now."""
    try:
        from karton.core import Config, Producer
        from karton.core.inspect import KartonState

        producer = Producer(
            config=Config(path=services.settings.karton_config_path),
            identity=services.settings.karton_identity,
        )
        return sorted(KartonState(producer.backend).queues.keys())
    except Exception:  # pragma: no cover - the backend may be down
        return []


@router.get("/{scan_id}/worker-output")
async def scan_worker_output(
    scan_id: str,
    worker: str = "",
    kind: str = "",
    limit: int = 500,
    user: CurrentUser = Depends(current_user),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """What the scanner workers produced, saved per scan.

    The console lists it and offers to scan it again; an agent reads it
    with the `list_worker_output` tool.
    """
    if services.scans.get(scan_id) is None:
        raise HTTPException(status_code=404, detail="the scan does not exist")
    items = [
        {key: value for key, value in item.items() if key != "_id"}
        for item in services.worker_output.list_for_scan(scan_id, worker=worker, kind=kind, limit=limit)
    ]
    return {
        "scan_id": scan_id,
        "items": items,
        "count": len(items),
        "counts": services.worker_output.counts_for_scan(scan_id),
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
