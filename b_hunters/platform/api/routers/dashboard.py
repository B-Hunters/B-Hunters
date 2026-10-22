"""The overview dashboard endpoint and the real-time event stream."""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from ...db.repositories import SCAN_STATUSES
from ..deps import CurrentUser, Services, current_user, get_services

router = APIRouter(tags=["dashboard"])

#: How often the SSE stream polls the event store.
POLL_INTERVAL_SECONDS = 0.75


@router.get("/dashboard")
async def dashboard(
    user: CurrentUser = Depends(current_user),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """Aggregate the platform metrics shown on the overview dashboard.

    Every number here is derived from the database or from the live Karton
    state.  Nothing is fabricated.
    """
    scan_counts: dict[str, int] = dict.fromkeys(SCAN_STATUSES, 0)
    for record in services.scans.list(limit=1000):
        scan_counts[record.status] = scan_counts.get(record.status, 0) + 1

    severity_counts = services.findings.severity_counts()
    open_findings = sum(
        count
        for status, count in _verification_counts(services).items()
        if status in {"unverified", "likely"}
        for count in [count]
    )

    active_agents = services.agents.list_active(stale_after=300.0)
    recent_scans = services.scans.list(limit=10)

    karton_snapshot = await _karton_snapshot(services)

    tool_health = await _tool_health(services)

    provider_health = await _provider_health(services)

    recent_errors = [
        event
        for event in services.events.recent(limit=200)
        if event.get("kind") in {"scanner.error", "scan.failed", "agent.failed"}
    ][:15]

    failed_calls, total_calls = services.tool_calls.failure_rate()

    return {
        "scans": {
            "total": sum(scan_counts.values()),
            "by_status": scan_counts,
            "running": scan_counts.get("running", 0),
            "queued": scan_counts.get("queued", 0),
            "completed": scan_counts.get("completed", 0),
            "failed": scan_counts.get("failed", 0),
        },
        "findings": {
            "total": services.findings.count(),
            "by_severity": severity_counts,
            "open": open_findings,
            "by_verification": _verification_counts(services),
            "by_class": services.findings.class_counts(),
        },
        "agents": {
            "active_count": len(active_agents),
            "items": [
                {
                    "scan_id": item.get("scan_id"),
                    "role": item.get("role"),
                    "status": item.get("status"),
                    "task_id": item.get("task_id"),
                    "conclusion": (item.get("conclusion") or "")[:200],
                    "last_seen_at": item.get("last_seen_at"),
                }
                for item in active_agents
            ],
            # The raw documents carry a BSON ObjectId, which the JSON
            # encoder cannot represent; the summaries above are built from
            # explicit keys so they are always serialisable.
        },
        "karton": karton_snapshot,
        "tools": tool_health,
        "providers": provider_health,
        "tool_calls": {
            "total": total_calls,
            "failed": failed_calls,
            "failure_rate": round(failed_calls / total_calls, 4) if total_calls else 0.0,
        },
        "recent_scans": [scan.public() for scan in recent_scans],
        "recent_errors": [
            {
                "seq": event.get("seq"),
                "kind": event.get("kind"),
                "at": event.get("at"),
                "scan_id": event.get("scan_id"),
                "payload": event.get("payload"),
            }
            for event in recent_errors
        ],
        "generated_at": time.time(),
    }


def _verification_counts(services: Services) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in services.findings.list(limit=5000):
        status = finding.get("verification_status", "unverified")
        counts[status] = counts.get(status, 0) + 1
    return counts


async def _karton_snapshot(services: Services) -> dict[str, Any]:
    try:
        from karton.core import Config, Producer
        from karton.core.inspect import KartonState

        producer = Producer(
            config=Config(path=services.settings.karton_config_path),
            identity=services.settings.karton_identity,
        )
        state = KartonState(producer.backend)
        queues = list(state.queues.values())
        now = time.time()
        pending = sum(len(queue.pending_tasks) for queue in queues)
        crashed = sum(len(queue.crashed_tasks) for queue in queues)
        online = sum(1 for queue in queues if queue.online_consumers_count)
        ages = [max(0.0, now - float(task.last_update)) for queue in queues for task in queue.pending_tasks]
        return {
            "available": True,
            "queues": len(queues),
            "online_consumers": online,
            "pending_tasks": pending,
            "crashed_tasks": crashed,
            "oldest_task_age_seconds": round(max(ages), 2) if ages else 0.0,
            "detail": [
                {
                    "queue": name,
                    "online_consumers": queue.online_consumers_count,
                    "pending": len(queue.pending_tasks),
                    "crashed": len(queue.crashed_tasks),
                }
                for name, queue in sorted(state.queues.items())
            ],
        }
    except Exception as exc:
        return {"available": False, "error": f"{type(exc).__name__}: {exc}"}


async def _tool_health(services: Services) -> dict[str, Any]:
    try:
        from ...scanners.fingerprint_adapter import service_fingerprint_executor
        from ...scanners.native import (
            dependency_analysis_executor,
            graphql_analysis_executor,
            openapi_discovery_executor,
            secret_scan_executor,
            security_headers_executor,
            tls_configuration_executor,
        )
        from ...scanners.registry import build_default_registry

        registry = build_default_registry(
            {
                "security_headers": security_headers_executor,
                "service_fingerprint": service_fingerprint_executor,
                "tls_configuration": tls_configuration_executor,
                "secret_scan": secret_scan_executor,
                "openapi_discovery": openapi_discovery_executor,
                "graphql_analysis": graphql_analysis_executor,
                "dependency_analysis": dependency_analysis_executor,
            }
        )
        return await registry.health(include_disabled=True)
    except Exception as exc:
        return {"total": 0, "by_status": {}, "adapters": [], "error": str(exc)}


async def _provider_health(services: Services) -> list[dict[str, Any]]:
    from ...agents.provider import Provider, ProviderConfig

    results: list[dict[str, Any]] = []
    for document in services.providers.list():
        config = ProviderConfig(
            name=document.get("name", ""),
            base_url=document.get("base_url", ""),
            api_key=document.get("api_key", ""),
            model=document.get("model", ""),
            timeout_seconds=float(document.get("timeout_seconds", 30.0)),
        )
        provider = Provider(config)
        try:
            health = await provider.health_check()
        finally:
            await provider.aclose()
        results.append(health)
    return results


@router.get("/scans/{scan_id}/stream")
async def scan_stream(
    scan_id: str,
    request: Request,
    last_event_id: int = Query(default=0, alias="last_event_id"),
    user: CurrentUser = Depends(current_user),
    services: Services = Depends(get_services),
) -> StreamingResponse:
    """Stream the scan events over server-sent events.

    The stream is resumable: the client sends the last sequence number it
    saw (either as ``last_event_id`` or in the ``Last-Event-ID`` header)
    and the server replays everything it missed before streaming new
    events.
    """
    if services.scans.get(scan_id) is None:
        raise HTTPException(status_code=404, detail="the scan does not exist")

    header_id = request.headers.get("last-event-id")
    if header_id:
        try:
            last_event_id = max(last_event_id, int(header_id))
        except (TypeError, ValueError):
            pass

    async def event_source() -> AsyncIterator[bytes]:
        cursor = last_event_id
        # Send an immediate comment so proxies establish the stream.
        yield b": connected\n\n"
        idle_rounds = 0
        while True:
            if await request.is_disconnected():
                break
            events = services.events.list_after(scan_id, after_seq=cursor, limit=200)
            if events:
                idle_rounds = 0
                for event in events:
                    cursor = int(event.get("seq", cursor))
                    payload = json.dumps(
                        {
                            "seq": event.get("seq"),
                            "kind": event.get("kind"),
                            "at": event.get("at"),
                            "actor": event.get("actor"),
                            "payload": event.get("payload", {}),
                        },
                        default=str,
                    )
                    yield (
                        f"id: {event.get('seq')}\nevent: {event.get('kind', 'message')}\ndata: {payload}\n\n"
                    ).encode()
            else:
                idle_rounds += 1
                if idle_rounds % 20 == 0:
                    # A periodic comment keeps intermediaries from timing out.
                    yield b": keepalive\n\n"
            await asyncio.sleep(POLL_INTERVAL_SECONDS)

    return StreamingResponse(
        event_source(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
