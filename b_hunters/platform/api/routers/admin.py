"""Administration: users, model providers, agent definitions and audit log."""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from ...agents.roles import builtin_roles
from ...runner import DRAIN_COUNTER_KEY
from ...security.passwords import validate_password_strength
from ..deps import (
    CurrentUser,
    Services,
    current_user,
    enforce_csrf,
    get_services,
    require_role,
    strip_object_id,
)

router = APIRouter(prefix="/admin", tags=["admin"])


# ----------------------------------------------------------------------
# Users
# ----------------------------------------------------------------------
class CreateUser(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    role: str = Field(default="viewer", pattern="^(admin|operator|viewer)$")
    email: str = Field(default="", max_length=256)
    display_name: str = Field(default="", max_length=128)


class UpdateUser(BaseModel):
    role: Optional[str] = Field(default=None, pattern="^(admin|operator|viewer)$")
    active: Optional[bool] = None
    email: Optional[str] = Field(default=None, max_length=256)
    display_name: Optional[str] = Field(default=None, max_length=128)
    password: Optional[str] = Field(default=None, max_length=256)


@router.get("/users")
async def list_users(
    user: CurrentUser = Depends(require_role("admin")),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """List the platform users."""
    users = services.users.list_users()
    return {"items": [services.users.public(item) for item in users], "count": len(users)}


@router.post("/users", status_code=status.HTTP_201_CREATED)
async def create_user(
    payload: CreateUser,
    request: Request,
    user: CurrentUser = Depends(require_role("admin")),
    services: Services = Depends(get_services),
    csrf: None = Depends(enforce_csrf),
) -> dict[str, Any]:
    """Create a user."""
    problems = validate_password_strength(payload.password)
    if problems:
        raise HTTPException(status_code=400, detail="; ".join(problems))
    try:
        created = services.users.create(
            username=payload.username,
            password=payload.password,
            role=payload.role,
            email=payload.email,
            display_name=payload.display_name,
        )
    except Exception as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    services.audit.record(
        action="user.create",
        actor=user.username,
        target_type="user",
        target_id=created["user_id"],
        detail={"username": created["username"], "role": created["role"]},
        ip_address=request.client.host if request.client else "",
    )
    return services.users.public(created)


@router.patch("/users/{user_id}")
async def update_user(
    user_id: str,
    payload: UpdateUser,
    request: Request,
    user: CurrentUser = Depends(require_role("admin")),
    services: Services = Depends(get_services),
    csrf: None = Depends(enforce_csrf),
) -> dict[str, Any]:
    """Update a user."""
    target = services.users.get_by_id(user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="the user does not exist")

    changes = payload.model_dump(exclude_none=True)
    password = changes.pop("password", None)
    if password:
        problems = validate_password_strength(password)
        if problems:
            raise HTTPException(status_code=400, detail="; ".join(problems))
        services.users.set_password(user_id, password)
        services.sessions.delete_for_user(user_id)

    if changes:
        if changes.get("role") and target["user_id"] == user.user_id and changes["role"] != "admin":
            raise HTTPException(
                status_code=400, detail="an administrator cannot remove their own administrator role"
            )
        services.users.update(user_id, changes)

    services.audit.record(
        action="user.update",
        actor=user.username,
        target_type="user",
        target_id=user_id,
        detail={"changes": sorted(changes.keys()) + (["password"] if password else [])},
        ip_address=request.client.host if request.client else "",
    )
    updated = services.users.get_by_id(user_id)
    return services.users.public(updated or {})


# ----------------------------------------------------------------------
# Model providers
# ----------------------------------------------------------------------
class ProviderRequest(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    base_url: str = Field(min_length=1, max_length=2048)
    api_key: str = Field(default="", max_length=2048)
    model: str = Field(default="", max_length=256)
    role_models: dict[str, str] = Field(default_factory=dict)
    temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    max_output_tokens: int = Field(default=4096, ge=256, le=200000)
    max_context_tokens: int = Field(default=128000, ge=1024)
    timeout_seconds: float = Field(default=120.0, ge=5.0, le=1200.0)
    max_retries: int = Field(default=2, ge=0, le=10)
    concurrency: int = Field(default=4, ge=1, le=64)
    extra_headers: dict[str, str] = Field(default_factory=dict)
    price_per_million_prompt: float = Field(default=0.0, ge=0.0)
    price_per_million_completion: float = Field(default=0.0, ge=0.0)
    enabled: bool = True


@router.get("/providers")
async def list_providers(
    user: CurrentUser = Depends(require_role("admin")),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """List the configured model providers (without their secrets)."""
    providers = services.providers.list()
    return {
        "items": [services.providers.public(item) for item in providers],
        "count": len(providers),
    }


@router.post("/providers", status_code=status.HTTP_201_CREATED)
async def upsert_provider(
    payload: ProviderRequest,
    request: Request,
    user: CurrentUser = Depends(require_role("admin")),
    services: Services = Depends(get_services),
    csrf: None = Depends(enforce_csrf),
) -> dict[str, Any]:
    """Create or update a model provider."""
    document = payload.model_dump()
    existing = services.providers.get(payload.name)
    if existing and not document.get("api_key"):
        # Keep the stored secret when the operator did not supply a new
        # one.  The key is stored encrypted, so it is read back through
        # the repository rather than from the document.
        document["api_key"] = services.providers.secret_for(payload.name)
    services.providers.upsert(document)
    services.audit.record(
        action="provider.upsert",
        actor=user.username,
        target_type="provider",
        target_id=payload.name,
        detail={"base_url": payload.base_url, "model": payload.model},
        ip_address=request.client.host if request.client else "",
    )
    return services.providers.public(services.providers.get(payload.name) or document)


@router.delete("/providers/{name}")
async def delete_provider(
    name: str,
    request: Request,
    user: CurrentUser = Depends(require_role("admin")),
    services: Services = Depends(get_services),
    csrf: None = Depends(enforce_csrf),
) -> dict[str, Any]:
    """Remove a model provider."""
    removed = services.providers.delete(name)
    if not removed:
        raise HTTPException(status_code=404, detail="the provider does not exist")
    services.audit.record(
        action="provider.delete",
        actor=user.username,
        target_type="provider",
        target_id=name,
        ip_address=request.client.host if request.client else "",
    )
    return {"status": "deleted", "name": name}


@router.get("/providers/{name}/health")
async def provider_health(
    name: str,
    user: CurrentUser = Depends(require_role("admin")),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """Check the connectivity and model availability of a provider."""
    from ...agents.provider import Provider, ProviderConfig

    document = services.providers.get(name)
    if document is None:
        raise HTTPException(status_code=404, detail="the provider does not exist")
    config = ProviderConfig(
        name=document.get("name", name),
        base_url=document.get("base_url", ""),
        # The key is stored encrypted.  Reading the plaintext field here
        # would send an empty credential and report the provider as
        # unreachable.
        api_key=services.providers.secret_for(name),
        model=document.get("model", ""),
        role_models=document.get("role_models", {}) or {},
        temperature=float(document.get("temperature", 0.0)),
        max_output_tokens=int(document.get("max_output_tokens", 4096)),
        max_context_tokens=int(document.get("max_context_tokens", 128000)),
        timeout_seconds=float(document.get("timeout_seconds", 120.0)),
        max_retries=int(document.get("max_retries", 2)),
        concurrency=int(document.get("concurrency", 4)),
        extra_headers=document.get("extra_headers", {}) or {},
    )
    provider = Provider(config)
    try:
        health = await provider.health_check()
    finally:
        await provider.aclose()
    return health


# ----------------------------------------------------------------------
# Agent definitions
# ----------------------------------------------------------------------
class AgentDefinitionRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    role: str = Field(min_length=1, max_length=64)
    system_prompt: str = Field(default="", max_length=20000)
    instructions: str = Field(default="", max_length=20000)
    model_ref: str = Field(default="", max_length=256)
    tools: list[str] = Field(default_factory=list)
    permissions: dict[str, Any] = Field(default_factory=dict)
    budget: dict[str, Any] = Field(default_factory=dict)
    output_schema: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True


@router.get("/agent-definitions")
async def list_agent_definitions(
    role: str = "",
    enabled_only: bool = False,
    user: CurrentUser = Depends(require_role("admin")),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """List the versioned agent definitions."""
    definitions = services.agent_definitions.list(role=role, enabled_only=enabled_only)
    return {"items": definitions, "count": len(definitions)}


@router.post("/agent-definitions", status_code=status.HTTP_201_CREATED)
async def create_agent_definition(
    payload: AgentDefinitionRequest,
    request: Request,
    user: CurrentUser = Depends(require_role("admin")),
    services: Services = Depends(get_services),
    csrf: None = Depends(enforce_csrf),
) -> dict[str, Any]:
    """Create a new version of an agent definition."""
    document = payload.model_dump()
    document["created_by"] = user.username
    created = services.agent_definitions.create(document)
    services.audit.record(
        action="agent_definition.create",
        actor=user.username,
        target_type="agent_definition",
        target_id=created["definition_id"],
        detail={"role": created["role"], "version": created["version"]},
        ip_address=request.client.host if request.client else "",
    )
    return created


@router.post("/agent-definitions/{definition_id}/enable")
async def enable_agent_definition(
    definition_id: str,
    request: Request,
    user: CurrentUser = Depends(require_role("admin")),
    services: Services = Depends(get_services),
    csrf: None = Depends(enforce_csrf),
) -> dict[str, Any]:
    """Enable or disable an agent definition."""
    definition = services.agent_definitions.get(definition_id)
    if definition is None:
        raise HTTPException(status_code=404, detail="the agent definition does not exist")
    enabled = not bool(definition.get("enabled", True))
    services.agent_definitions.set_enabled(definition_id, enabled)
    services.audit.record(
        action="agent_definition.toggle",
        actor=user.username,
        target_type="agent_definition",
        target_id=definition_id,
        detail={"enabled": enabled},
        ip_address=request.client.host if request.client else "",
    )
    return {"definition_id": definition_id, "enabled": enabled}


@router.get("/agent-roles")
async def list_agent_roles(
    user: CurrentUser = Depends(current_user),
) -> dict[str, Any]:
    """List the built-in agent roles."""
    return {
        "roles": [role.to_dict() for role in builtin_roles().values()],
        "count": len(builtin_roles()),
    }


# ----------------------------------------------------------------------
# Runner
# ----------------------------------------------------------------------
@router.post("/runner/drain")
async def drain_runner(
    request: Request,
    user: CurrentUser = Depends(require_role("admin")),
    services: Services = Depends(get_services),
    csrf: None = Depends(enforce_csrf),
) -> dict[str, Any]:
    """Ask the runner to stop claiming new jobs.

    The job the runner is working on is allowed to finish; the runner
    then stops.  The flag lives in the database, so it survives the
    restart of the runner.
    """
    services.db.collection("platform_counters").update_one(
        {"key": DRAIN_COUNTER_KEY},
        {"$set": {"value": 1}},
        upsert=True,
    )
    services.audit.record(
        action="runner.drain",
        actor=user.username,
        target_type="runner",
        target_id="runner",
        ip_address=request.client.host if request.client else "",
    )
    return {"status": "draining"}


@router.delete("/runner/drain")
async def resume_runner(
    request: Request,
    user: CurrentUser = Depends(require_role("admin")),
    services: Services = Depends(get_services),
    csrf: None = Depends(enforce_csrf),
) -> dict[str, Any]:
    """Let the runner claim jobs again."""
    services.db.collection("platform_counters").delete_one({"key": DRAIN_COUNTER_KEY})
    services.audit.record(
        action="runner.resume",
        actor=user.username,
        target_type="runner",
        target_id="runner",
        ip_address=request.client.host if request.client else "",
    )
    return {"status": "running"}


# ----------------------------------------------------------------------
# Audit
# ----------------------------------------------------------------------
@router.get("/audit")
async def list_audit(
    limit: int = Query(default=100, ge=1, le=1000),
    action: str = "",
    actor: str = "",
    user: CurrentUser = Depends(require_role("admin")),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """Return the audit log."""
    entries = services.audit.list(limit=limit, action=action, actor=actor)
    return {"items": [strip_object_id(item) for item in entries], "count": len(entries)}
