"""Tools that let agents inspect what has already been discovered.

These tools are read-only views over the platform's own database: the
findings, assets and events produced by the deterministic scanner workers.
Agents use them to avoid redoing work and to ground their hypotheses in
real observations.
"""

from __future__ import annotations

from typing import Any, Optional

from ..gateway import ToolContext, ToolError

LIST_FINDINGS_SCHEMA = {
    "type": "object",
    "properties": {
        "severity": {
            "type": "array",
            "items": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
            "default": [],
        },
        "vuln_class": {"type": "string", "default": ""},
        "host": {"type": "string", "default": ""},
        "verification_status": {"type": "string", "default": ""},
        "limit": {"type": "integer", "default": 50, "maximum": 500},
    },
    "additionalProperties": False,
}


def list_findings(
    severity: Optional[list[str]] = None,
    vuln_class: str = "",
    host: str = "",
    verification_status: str = "",
    limit: int = 50,
    *,
    context: ToolContext,
) -> dict[str, Any]:
    """List findings already recorded for this scan."""
    repo = context.metadata.get("findings_repository")
    if repo is None:
        raise ToolError("the findings repository is not available in this context")
    findings = repo.list(
        context.scan_id,
        severity=severity or (),
        verification_status=(verification_status,) if verification_status else (),
        vuln_class=vuln_class,
        host=host,
        limit=limit,
    )
    return {
        "count": len(findings),
        "findings": [
            {
                "finding_id": item.get("finding_id"),
                "title": item.get("title"),
                "vuln_class": item.get("vuln_class"),
                "severity": item.get("severity"),
                "host": item.get("host"),
                "path": item.get("path"),
                "confidence": item.get("confidence"),
                "verification_status": item.get("verification_status"),
                "detected_by": item.get("detected_by"),
            }
            for item in findings
        ],
    }


LIST_ASSETS_SCHEMA = {
    "type": "object",
    "properties": {
        "kind": {
            "type": "string",
            "enum": ["", "url", "route", "host", "technology", "javascript"],
            "default": "",
        },
        "limit": {"type": "integer", "default": 100, "maximum": 1000},
    },
    "additionalProperties": False,
}


def list_assets(kind: str = "", limit: int = 100, *, context: ToolContext) -> dict[str, Any]:
    """List assets discovered so far for this scan."""
    assets = context.metadata.get("assets") or {}
    selected = assets.get(kind, []) if kind else []
    if not isinstance(selected, list):
        selected = []
    return {"kind": kind or "all", "count": len(selected), "assets": selected[:limit]}


LIST_EVENTS_SCHEMA = {
    "type": "object",
    "properties": {
        "limit": {"type": "integer", "default": 40, "maximum": 200},
        "kind": {"type": "string", "default": ""},
    },
    "additionalProperties": False,
}


def list_events(kind: str = "", limit: int = 40, *, context: ToolContext) -> dict[str, Any]:
    """List recent scan events (worker output, agent messages, errors)."""
    repo = context.metadata.get("events_repository")
    if repo is None:
        raise ToolError("the events repository is not available in this context")
    events = repo.recent(limit=limit, scan_id=context.scan_id)
    if kind:
        events = [event for event in events if event.get("kind") == kind]
    return {
        "count": len(events),
        "events": [
            {
                "seq": event.get("seq"),
                "kind": event.get("kind"),
                "at": event.get("at"),
                "payload": event.get("payload"),
            }
            for event in events
        ],
    }


TOOL_HEALTH_SCHEMA = {
    "type": "object",
    "properties": {"include_disabled": {"type": "boolean", "default": False}},
    "additionalProperties": False,
}


def list_tool_health(include_disabled: bool = False, *, context: ToolContext) -> dict[str, Any]:
    """Report the health of the registered scanner adapters."""
    registry = context.metadata.get("scanner_registry")
    if registry is None:
        raise ToolError("the scanner registry is not available in this context")
    return registry.health(include_disabled=include_disabled)
