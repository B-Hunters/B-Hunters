"""The schedules.

A schedule is a scan that happens on its own: every night, every hour,
every Monday.  The runner claims the schedules whose time has come and
enqueues the same job the API enqueues, so a scheduled scan and a
requested scan are the same thing.

The claim is atomic.  Two runners that both find a due schedule
produce exactly one scan between them: the loser tries the next
schedule.
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

router = APIRouter(prefix="/schedules", tags=["schedules"])


class ScheduleRequest(BaseModel):
    """A schedule."""

    name: str = ""
    template: dict[str, Any] = Field(default_factory=dict)
    cron: str = ""
    timezone: str = "UTC"
    enabled: bool = True


class ScheduleUpdate(BaseModel):
    """A change to a schedule."""

    name: str = ""
    template: dict[str, Any] = Field(default_factory=dict)
    cron: str = ""
    timezone: str = ""
    enabled: Optional[bool] = None


@router.get("")
async def list_schedules(
    user: CurrentUser = Depends(current_user),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """The schedules, the ones that run next first."""
    schedules = services.schedules.list()
    return {"schedules": strip_object_ids(schedules), "count": len(schedules)}


@router.post("", status_code=201)
async def create_schedule(
    payload: ScheduleRequest,
    user: CurrentUser = Depends(require_role("operator")),
    services: Services = Depends(get_services),
    csrf: None = Depends(enforce_csrf),
) -> dict[str, Any]:
    """Store a schedule."""
    if not payload.cron.strip():
        raise HTTPException(status_code=400, detail="a schedule needs a cron expression")
    try:
        document = services.schedules.create(
            name=payload.name,
            template=payload.template,
            cron=payload.cron,
            timezone=payload.timezone,
            enabled=payload.enabled,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    services.audit.record(
        action="schedule.create",
        actor=user.username,
        target_type="schedule",
        target_id=document["schedule_id"],
        detail={"cron": document["cron"]},
    )
    return strip_object_ids(document)


@router.get("/{schedule_id}")
async def get_schedule(
    schedule_id: str,
    user: CurrentUser = Depends(current_user),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """One schedule."""
    document = services.schedules.get(schedule_id)
    if document is None:
        raise HTTPException(status_code=404, detail="the schedule does not exist")
    return strip_object_ids(document)


@router.patch("/{schedule_id}")
async def update_schedule(
    schedule_id: str,
    payload: ScheduleUpdate,
    user: CurrentUser = Depends(require_role("operator")),
    services: Services = Depends(get_services),
    csrf: None = Depends(enforce_csrf),
) -> dict[str, Any]:
    """Change a schedule.  A new cron expression moves its next run."""
    changes: dict[str, Any] = {}
    if payload.name:
        changes["name"] = payload.name
    if payload.template:
        changes["template"] = payload.template
    if payload.cron:
        changes["cron"] = payload.cron
    if payload.timezone:
        changes["timezone"] = payload.timezone
    if payload.enabled is not None:
        changes["enabled"] = payload.enabled
    try:
        changed = services.schedules.update(schedule_id, changes)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not changed:
        raise HTTPException(status_code=404, detail="the schedule does not exist")
    document = services.schedules.get(schedule_id)
    return strip_object_ids(document)


@router.delete("/{schedule_id}")
async def delete_schedule(
    schedule_id: str,
    user: CurrentUser = Depends(require_role("operator")),
    services: Services = Depends(get_services),
    csrf: None = Depends(enforce_csrf),
) -> dict[str, Any]:
    """Remove a schedule."""
    if not services.schedules.delete(schedule_id):
        raise HTTPException(status_code=404, detail="the schedule does not exist")
    services.audit.record(
        action="schedule.delete",
        actor=user.username,
        target_type="schedule",
        target_id=schedule_id,
    )
    return {"deleted": schedule_id}


@router.post("/{schedule_id}/run", status_code=202)
async def run_schedule_now(
    schedule_id: str,
    user: CurrentUser = Depends(require_role("operator")),
    services: Services = Depends(get_services),
    csrf: None = Depends(enforce_csrf),
) -> dict[str, Any]:
    """Run a schedule now, without waiting for its next run."""
    document = services.schedules.get(schedule_id)
    if document is None:
        raise HTTPException(status_code=404, detail="the schedule does not exist")
    from ...scan_factory import create_scan_from_template

    record = create_scan_from_template(
        services,
        template=document.get("template") or {},
        name=f"{document.get('name', 'the schedule')} (run now)",
    )
    scan_id = record.scan_id
    services.jobs.enqueue(
        kind="scan",
        payload={"scan_id": scan_id, "target_key": getattr(record, "target_key", "")},
        max_attempts=services.settings.job_max_attempts,
    )
    services.scans.set_status(scan_id, "queued")
    services.schedules.record_run(schedule_id, scan_id)
    return {"scan_id": scan_id, "schedule_id": schedule_id}
