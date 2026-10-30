"""The triage of the issues.

A finding belongs to the scan that found it.  An issue is the durable
thing behind the finding: it carries the triage state, the observation
state and the history, and it is what the operator works on.

Everything here acts on the issue, not on the occurrence.  The same
problem found by a later scan of the same target is the same issue, so
marking it fixed in one scan marks it fixed in every scan that sees it
after that.
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

router = APIRouter(prefix="/issues", tags=["issues"])


class TriageRequest(BaseModel):
    """The triage state of an issue."""

    status: str = Field(description="open, in_progress, fixed, risk_accepted, ...")
    assignee: str = ""
    tags: list[str] = Field(default_factory=list)
    due_at: Optional[float] = None
    duplicate_of: str = ""
    note: str = ""


class BulkTriageRequest(BaseModel):
    """The triage of a selection of issues."""

    issue_ids: list[str] = Field(default_factory=list)
    status: str = ""
    assignee: str = ""
    tags: list[str] = Field(default_factory=list)
    note: str = ""


class CommentRequest(BaseModel):
    """A comment on an issue."""

    body: str = ""
    scan_id: str = ""
    finding_id: str = ""


@router.get("")
async def list_issues(
    target_key: str = "",
    triage_status: str = "",
    severity: str = "",
    limit: int = 100,
    offset: int = 0,
    user: CurrentUser = Depends(current_user),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """The issues, the most recently seen first."""
    issues = services.issues.list(
        target_key=target_key,
        triage_status=triage_status,
        severity=severity,
        limit=limit,
        offset=offset,
    )
    return {"issues": strip_object_ids(issues), "count": len(issues)}


@router.get("/{issue_id}")
async def get_issue(
    issue_id: str,
    user: CurrentUser = Depends(current_user),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """One issue."""
    issue = services.issues.get(issue_id)
    if issue is None:
        raise HTTPException(status_code=404, detail="the issue does not exist")
    return strip_object_ids(issue)


@router.get("/{issue_id}/history")
async def issue_history(
    issue_id: str,
    user: CurrentUser = Depends(current_user),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """The scans that saw the issue, and the changes of its state."""
    issue = services.issues.get(issue_id)
    if issue is None:
        raise HTTPException(status_code=404, detail="the issue does not exist")
    return {
        "issue_id": issue_id,
        "scans": strip_object_ids(services.issues.history(issue_id)),
        "events": strip_object_ids(services.issues.events_for(issue_id)),
        "first_seen_at": issue.get("first_seen_at"),
        "last_seen_at": issue.get("last_seen_at"),
    }


@router.post("/{issue_id}/triage")
async def triage_issue(
    issue_id: str,
    payload: TriageRequest,
    user: CurrentUser = Depends(require_role("operator")),
    services: Services = Depends(get_services),
    csrf: None = Depends(enforce_csrf),
) -> dict[str, Any]:
    """Set the triage state of an issue."""
    try:
        services.issues.set_triage(
            issue_id,
            status=payload.status,
            assignee=payload.assignee,
            tags=payload.tags,
            due_at=payload.due_at,
            duplicate_of=payload.duplicate_of,
            note=payload.note,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="the issue does not exist") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    services.audit.record(
        action="issue.triage",
        actor=user.username,
        target_type="issue",
        target_id=issue_id,
        detail={"status": payload.status, "assignee": payload.assignee},
    )
    issue = services.issues.get(issue_id)
    return strip_object_ids(issue)


@router.post("/bulk")
async def triage_issues_in_bulk(
    payload: BulkTriageRequest,
    user: CurrentUser = Depends(require_role("operator")),
    services: Services = Depends(get_services),
    csrf: None = Depends(enforce_csrf),
) -> dict[str, Any]:
    """Set the triage state of a selection of issues.

    The same issue is updated across every scan: the triage lives on the
    issue, so a selection made in one scan's table is the selection in
    the next one too.
    """
    if not payload.issue_ids:
        raise HTTPException(status_code=400, detail="no issue was selected")
    changed: list[str] = []
    missing: list[str] = []
    for issue_id in payload.issue_ids:
        try:
            services.issues.set_triage(
                issue_id,
                status=payload.status or "open",
                assignee=payload.assignee,
                tags=payload.tags,
                note=payload.note,
            )
        except KeyError:
            missing.append(issue_id)
            continue
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        changed.append(issue_id)
    services.audit.record(
        action="issue.triage.bulk",
        actor=user.username,
        target_type="issue",
        target_id="",
        detail={"changed": len(changed), "status": payload.status},
    )
    return {"changed": changed, "missing": missing, "count": len(changed)}


@router.get("/{issue_id}/comments")
async def list_comments(
    issue_id: str,
    user: CurrentUser = Depends(current_user),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """The comments of an issue, oldest first."""
    if services.issues.get(issue_id) is None:
        raise HTTPException(status_code=404, detail="the issue does not exist")
    comments = services.comments.list_for_issue(issue_id)
    return {"comments": strip_object_ids(comments), "count": len(comments)}


@router.post("/{issue_id}/comments", status_code=201)
async def add_comment(
    issue_id: str,
    payload: CommentRequest,
    user: CurrentUser = Depends(require_role("operator")),
    services: Services = Depends(get_services),
    csrf: None = Depends(enforce_csrf),
) -> dict[str, Any]:
    """Comment on an issue."""
    if services.issues.get(issue_id) is None:
        raise HTTPException(status_code=404, detail="the issue does not exist")
    try:
        comment = services.comments.add(
            issue_id=issue_id,
            scan_id=payload.scan_id,
            finding_id=payload.finding_id,
            author=user.username,
            body=payload.body,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    services.audit.record(
        action="issue.comment",
        actor=user.username,
        target_type="issue",
        target_id=issue_id,
        detail={"comment_id": comment["comment_id"]},
    )
    return strip_object_ids(comment)
