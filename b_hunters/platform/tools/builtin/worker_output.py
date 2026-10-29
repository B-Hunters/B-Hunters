"""The output of the scanner workers, for an agent that wants to scan further.

The crawlers find the surface; the scanners test it.  A role that wants
to test what a crawler found asks for it here, instead of reading the
legacy documents.
"""

from __future__ import annotations

from typing import Any

from ..gateway import ToolContext, ToolError

LIST_WORKER_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "worker": {
            "type": "string",
            "description": "Only the items of this worker, for example B-Hunters-Katana.",
        },
        "kind": {
            "type": "string",
            "description": (
                "Only the items of this kind: url, path, secret, port, technology, finding or screenshot."
            ),
        },
        "limit": {
            "type": "integer",
            "default": 100,
            "description": "How many items to return.",
        },
    },
    "additionalProperties": False,
}


def list_worker_output(
    worker: str = "",
    kind: str = "",
    limit: int = 100,
    *,
    context: ToolContext,
) -> dict[str, Any]:
    """List what the scanner workers produced for this scan."""
    repository = context.metadata.get("worker_output_repository")
    if repository is None:
        raise ToolError("the worker output repository is not available in this context")
    items = repository.list_for_scan(context.scan_id, worker=worker, kind=kind, limit=limit)
    return {
        "count": len(items),
        "items": [
            {
                "worker": item.get("worker", ""),
                "kind": item.get("kind", ""),
                "value": item.get("value", ""),
            }
            for item in items
        ],
    }
