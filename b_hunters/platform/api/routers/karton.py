"""Karton monitoring.

The endpoints here read the *real* Karton state through the installed
``karton-core`` API (``KartonState`` / ``KartonQueue``) rather than
re-implementing it.  When the Karton backend is not reachable the endpoint
reports that fact explicitly instead of returning fabricated numbers.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from ..deps import CurrentUser, Services, current_user, get_services

router = APIRouter(prefix="/karton", tags=["karton"])

log = logging.getLogger(__name__)

#: A worker that has not sent a heartbeat within this window is considered stale.
STALE_AFTER_SECONDS = 300.0


def _karton_state(services: Services):
    """Build a KartonState from the platform's Karton configuration.

    ``Producer`` expects a :class:`karton.core.Config` object rather than a
    path, so the path is loaded into a Config first.
    """
    from karton.core import Config, Producer
    from karton.core.inspect import KartonState

    config = Config(path=services.settings.karton_config_path)
    producer = Producer(config=config, identity=services.settings.karton_identity)
    return KartonState(producer.backend), producer


def _safe_last_update(queue: Any) -> float:
    """The last update of a queue, or zero when it has seen no task.

    Karton's accessor raises ``ValueError`` on an empty task list, which
    would turn a queue that has simply not been used into a 500.
    """
    try:
        return float(queue.last_update)
    except (ValueError, TypeError):
        return 0.0


def _queue_snapshot(name: str, queue: Any, now: float) -> dict[str, Any]:
    pending = list(queue.pending_tasks)
    started = [task for task in pending if "started" in str(task.status).lower()]
    crashed = list(queue.crashed_tasks)
    ages = [max(0.0, now - float(task.last_update)) for task in pending]
    return {
        "queue": name,
        "online_consumers": queue.online_consumers_count,
        "pending_tasks": len(pending),
        "started_tasks": len(started),
        "crashed_tasks": len(crashed),
        "oldest_task_age_seconds": round(max(ages), 2) if ages else 0.0,
        # A queue that has not seen a task yet has no last update; the
        # upstream accessor raises on an empty task list.
        "last_update": _safe_last_update(queue),
        "pending": [
            {
                "uid": task.uid,
                "status": str(task.status),
                "age_seconds": round(max(0.0, now - float(task.last_update)), 2),
                "type": task.headers.get("type", ""),
                "stage": task.headers.get("stage", ""),
                "root_uid": task.root_uid,
                "priority": str(task.priority),
            }
            for task in pending[:200]
        ],
        "crashed": [
            {
                "uid": task.uid,
                "status": str(task.status),
                "type": task.headers.get("type", ""),
                "stage": task.headers.get("stage", ""),
                "error": (task.error or [])[-1] if task.error else "",
            }
            for task in crashed[:100]
        ],
    }


@router.get("/state")
async def karton_state(
    user: CurrentUser = Depends(current_user),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """Return the live Karton queue and consumer state."""
    try:
        state, _producer = _karton_state(services)
    except Exception as exc:
        return {
            "available": False,
            "error": f"{type(exc).__name__}: {exc}",
            "queues": [],
            "workers": [],
            "checked_at": time.time(),
        }

    now = time.time()
    queues = [_queue_snapshot(name, queue, now) for name, queue in state.queues.items()]
    queues.sort(key=lambda item: item["queue"])

    workers = [
        {
            "queue": item["queue"],
            "online_consumers": item["online_consumers"],
            "status": "online" if item["online_consumers"] else "offline",
            "pending_tasks": item["pending_tasks"],
            "crashed_tasks": item["crashed_tasks"],
        }
        for item in queues
    ]

    return {
        "available": True,
        "checked_at": now,
        "queues": queues,
        "workers": workers,
        "totals": {
            "queues": len(queues),
            "online_workers": sum(1 for w in workers if w["status"] == "online"),
            "pending_tasks": sum(q["pending_tasks"] for q in queues),
            "crashed_tasks": sum(q["crashed_tasks"] for q in queues),
            "oldest_task_age_seconds": max((q["oldest_task_age_seconds"] for q in queues), default=0.0),
        },
    }


@router.get("/analyses")
async def karton_analyses(
    limit: int = Query(default=50, ge=1, le=500),
    user: CurrentUser = Depends(current_user),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """Return the Karton analysis trees, which map to scan task graphs."""
    try:
        state, _producer = _karton_state(services)
    except Exception as exc:
        return {"available": False, "error": str(exc), "analyses": []}

    analyses = []
    for root_uid, analysis in list(state.analyses.items())[:limit]:
        analyses.append(
            {
                "root_uid": root_uid,
                "is_done": analysis.is_done,
                "pending_queues": list(analysis.pending_queues.keys()),
                "pending_tasks": len(analysis.pending_tasks),
                "crashed_tasks": len(analysis.crashed_tasks),
                "last_update": analysis.last_update,
            }
        )
    return {"available": True, "analyses": analyses, "count": len(analyses)}


@router.get("/tasks/{root_uid}")
async def karton_analysis(
    root_uid: str,
    user: CurrentUser = Depends(current_user),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """Return one Karton analysis tree in full."""
    try:
        state, _producer = _karton_state(services)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Karton is not available: {exc}") from exc

    analysis = state.get_analysis(root_uid)
    if analysis is None:
        raise HTTPException(status_code=404, detail="the analysis does not exist")

    return {
        "root_uid": root_uid,
        "is_done": analysis.is_done,
        "pending_queues": list(analysis.pending_queues.keys()),
        "tasks": [
            {
                "uid": task.uid,
                "status": str(task.status),
                "type": task.headers.get("type", ""),
                "stage": task.headers.get("stage", ""),
                "origin": task.headers.get("origin", ""),
                "last_update": task.last_update,
                "error": (task.error or [])[-1] if task.error else "",
            }
            for task in analysis.pending_tasks
        ],
        "crashed_tasks": [
            {
                "uid": task.uid,
                "status": str(task.status),
                "error": (task.error or [])[-1] if task.error else "",
            }
            for task in analysis.crashed_tasks
        ],
    }
