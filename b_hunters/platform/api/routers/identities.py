"""The identity vault through the API.

The secrets go in and never come out: the API accepts a password, a
one-time password secret, headers, cookies and the session state, and
every response says only whether the identity *has* them.  Decryption
happens in the runner, at the moment the credentials are used.
"""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..deps import CurrentUser, Services, current_user, get_services, require_role

router = APIRouter(prefix="/identities", tags=["identities"])


class IdentityRequest(BaseModel):
    """What an operator sends when they store an identity."""

    name: str = Field(min_length=1, max_length=200)
    kind: str = Field(default="form", max_length=32)
    login_url: str = Field(default="", max_length=2000)
    username: str = Field(default="", max_length=512)
    password: str = Field(default="", max_length=4096)
    totp_secret: str = Field(default="", max_length=256)
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    username_field: str = Field(default="", max_length=128)
    password_field: str = Field(default="", max_length=128)
    success_url: str = Field(default="", max_length=2000)
    success_selector: str = Field(default="", max_length=512)
    verify_url: str = Field(default="", max_length=2000)
    verify_selector: str = Field(default="", max_length=512)
    verify_text: str = Field(default="", max_length=512)


@router.post("", status_code=201)
async def create_identity(
    payload: IdentityRequest,
    user: CurrentUser = Depends(require_role("operator")),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """Store an identity."""
    repository = services.identities
    try:
        document = repository.create(
            name=payload.name,
            kind=payload.kind,
            login_url=payload.login_url,
            username=payload.username,
            password=payload.password,
            totp_secret=payload.totp_secret,
            headers=dict(payload.headers),
            cookies=dict(payload.cookies),
            username_field=payload.username_field,
            password_field=payload.password_field,
            success_url=payload.success_url,
            success_selector=payload.success_selector,
            verify_url=payload.verify_url,
            verify_selector=payload.verify_selector,
            verify_text=payload.verify_text,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    services.audit.record(
        action="identity.create",
        actor=user.username,
        target_type="identity",
        target_id=document["identity_id"],
        detail={"name": payload.name, "kind": payload.kind},
    )
    return repository.public(document)


@router.get("")
async def list_identities(
    user: CurrentUser = Depends(current_user),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """Every identity, without its secrets."""
    repository = services.identities
    items = [repository.public(identity) for identity in repository.list()]
    return {"items": items, "count": len(items)}


@router.get("/{identity_id}")
async def get_identity(
    identity_id: str,
    user: CurrentUser = Depends(current_user),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """One identity, without its secrets."""
    repository = services.identities
    document = repository.get(identity_id)
    if document is None:
        raise HTTPException(status_code=404, detail="the identity does not exist")
    return repository.public(document)


@router.patch("/{identity_id}")
async def update_identity(
    identity_id: str,
    payload: IdentityRequest,
    user: CurrentUser = Depends(require_role("operator")),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """Change an identity."""
    repository = services.identities
    if repository.get(identity_id) is None:
        raise HTTPException(status_code=404, detail="the identity does not exist")
    try:
        repository.update(identity_id, payload.model_dump(exclude_defaults=True))
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    services.audit.record(
        action="identity.update",
        actor=user.username,
        target_type="identity",
        target_id=identity_id,
    )
    return repository.public(repository.get(identity_id) or {})


@router.delete("/{identity_id}")
async def delete_identity(
    identity_id: str,
    user: CurrentUser = Depends(require_role("operator")),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """Remove an identity."""
    repository = services.identities
    if not repository.delete(identity_id):
        raise HTTPException(status_code=404, detail="the identity does not exist")
    services.audit.record(
        action="identity.delete",
        actor=user.username,
        target_type="identity",
        target_id=identity_id,
    )
    return {"deleted": True, "identity_id": identity_id}


@router.post("/{identity_id}/login", status_code=202)
async def login_identity(
    identity_id: str,
    user: CurrentUser = Depends(require_role("operator")),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """Queue a login for an identity.

    The recorder runs in the runner: it decrypts the credentials there,
    drives the browser and stores the session.  The API never decrypts,
    so the response is a job and nothing else.
    """
    repository = services.identities
    if repository.get(identity_id) is None:
        raise HTTPException(status_code=404, detail="the identity does not exist")
    job = services.jobs.enqueue(
        kind="identity_login",
        payload={"identity_id": identity_id},
    )
    services.audit.record(
        action="identity.login",
        actor=user.username,
        target_type="identity",
        target_id=identity_id,
        detail={"job_id": job["job_id"]},
    )
    return {"status": "queued", "job_id": job["job_id"], "identity_id": identity_id}


@router.get("/{identity_id}/status")
async def identity_status(
    identity_id: str,
    user: CurrentUser = Depends(current_user),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """The state of an identity: whether it has a session, and when it was used."""
    repository = services.identities
    document: Optional[dict[str, Any]] = repository.get(identity_id)
    if document is None:
        raise HTTPException(status_code=404, detail="the identity does not exist")
    return {
        "identity_id": identity_id,
        "status": document.get("status", "ready"),
        "last_login_at": document.get("last_login_at"),
        "last_used_at": document.get("last_used_at"),
        "session_expires_at": document.get("session_expires_at"),
        "has_storage_state": bool(document.get("storage_state_ciphertext")),
    }
