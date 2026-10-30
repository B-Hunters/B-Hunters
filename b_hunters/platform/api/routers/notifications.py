"""The notifications and the API tokens.

A notification is a webhook the platform posts to when something
happens.  An API token is how a pipeline asks the platform for
something without a browser.

The token is shown once, when it is created.  The database holds its
hash, so a dump of the database is not a way in.
"""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..deps import (
    CurrentUser,
    Services,
    current_user,
    enforce_csrf,
    get_services,
    require_role,
    strip_object_ids,
)

router = APIRouter(tags=["notifications"])


class NotificationRequest(BaseModel):
    """A webhook the platform posts to."""

    name: str = ""
    kind: str = "webhook"
    target: str = ""
    events: list[str] = Field(default_factory=list)
    secret: str = ""
    filters: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True


class NotificationUpdate(BaseModel):
    """A change to a notification."""

    name: str = ""
    target: str = ""
    events: list[str] = Field(default_factory=list)
    filters: dict[str, Any] = Field(default_factory=dict)
    secret: str = ""
    enabled: Optional[bool] = None


class TokenRequest(BaseModel):
    """An API token."""

    name: str = ""
    scopes: list[str] = Field(default_factory=list)
    expires_at: Optional[float] = None


@router.get("/notifications")
async def list_notifications(
    user: CurrentUser = Depends(current_user),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """The notifications."""
    notifications = services.notifications.list()
    return {"notifications": strip_object_ids(notifications), "count": len(notifications)}


@router.post("/notifications", status_code=201)
async def create_notification(
    payload: NotificationRequest,
    user: CurrentUser = Depends(require_role("operator")),
    services: Services = Depends(get_services),
    csrf: None = Depends(enforce_csrf),
) -> dict[str, Any]:
    """Store a notification."""
    try:
        document = services.notifications.create(
            name=payload.name,
            kind=payload.kind,
            target=payload.target,
            events=payload.events,
            secret=payload.secret,
            filters=payload.filters,
            enabled=payload.enabled,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    services.audit.record(
        action="notification.create",
        actor=user.username,
        target_type="notification",
        target_id=document["notification_id"],
        detail={"events": document["events"]},
    )
    return strip_object_ids(document)


@router.patch("/notifications/{notification_id}")
async def update_notification(
    notification_id: str,
    payload: NotificationUpdate,
    user: CurrentUser = Depends(require_role("operator")),
    services: Services = Depends(get_services),
    csrf: None = Depends(enforce_csrf),
) -> dict[str, Any]:
    """Change a notification."""
    changes: dict[str, Any] = {}
    if payload.name:
        changes["name"] = payload.name
    if payload.target:
        changes["target"] = payload.target
    if payload.events:
        changes["events"] = payload.events
    if payload.filters:
        changes["filters"] = payload.filters
    if payload.secret:
        changes["secret"] = payload.secret
    if payload.enabled is not None:
        changes["enabled"] = payload.enabled
    try:
        changed = services.notifications.update(notification_id, changes)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not changed:
        raise HTTPException(status_code=404, detail="the notification does not exist")
    document = services.notifications.get(notification_id)
    return strip_object_ids(document)


@router.delete("/notifications/{notification_id}")
async def delete_notification(
    notification_id: str,
    user: CurrentUser = Depends(require_role("operator")),
    services: Services = Depends(get_services),
    csrf: None = Depends(enforce_csrf),
) -> dict[str, Any]:
    """Remove a notification."""
    if not services.notifications.delete(notification_id):
        raise HTTPException(status_code=404, detail="the notification does not exist")
    services.audit.record(
        action="notification.delete",
        actor=user.username,
        target_type="notification",
        target_id=notification_id,
    )
    return {"deleted": notification_id}


@router.get("/notifications/{notification_id}/deliveries")
async def list_deliveries(
    notification_id: str,
    user: CurrentUser = Depends(current_user),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """The deliveries of a notification, newest first."""
    if services.notifications.get(notification_id) is None:
        raise HTTPException(status_code=404, detail="the notification does not exist")
    deliveries = services.notifications.deliveries(notification_id)
    return {"deliveries": strip_object_ids(deliveries), "count": len(deliveries)}


@router.post("/tokens", status_code=201)
async def create_token(
    payload: TokenRequest,
    user: CurrentUser = Depends(require_role("operator")),
    services: Services = Depends(get_services),
    csrf: None = Depends(enforce_csrf),
) -> dict[str, Any]:
    """Create an API token.

    The plaintext is in this answer and nowhere else: it is not stored,
    and it cannot be recovered afterwards.
    """
    document, plaintext = services.tokens.create(
        name=payload.name,
        scopes=payload.scopes,
        user_id=user.user_id,
        expires_at=payload.expires_at,
    )
    services.audit.record(
        action="token.create",
        actor=user.username,
        target_type="token",
        target_id=document["token_id"],
        detail={"scopes": document["scopes"]},
    )
    return {
        "token_id": document["token_id"],
        "name": document["name"],
        "scopes": document["scopes"],
        "prefix": document["prefix"],
        "created_at": document["created_at"],
        "expires_at": document["expires_at"],
        "token": plaintext,
    }


@router.get("/tokens")
async def list_tokens(
    user: CurrentUser = Depends(current_user),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """The API tokens, without their secrets."""
    tokens = services.tokens.list()
    return {"tokens": strip_object_ids(tokens), "count": len(tokens)}


@router.delete("/tokens/{token_id}")
async def revoke_token(
    token_id: str,
    user: CurrentUser = Depends(require_role("operator")),
    services: Services = Depends(get_services),
    csrf: None = Depends(enforce_csrf),
) -> dict[str, Any]:
    """Revoke an API token.  It stops working at once."""
    if not services.tokens.revoke(token_id):
        raise HTTPException(status_code=404, detail="the token does not exist")
    services.audit.record(
        action="token.revoke",
        actor=user.username,
        target_type="token",
        target_id=token_id,
    )
    return {"revoked": token_id}
