"""The tools that let an agent confirm a blind finding.

A blind vulnerability — an SSRF, a blind XSS, a command injection that
answers on another host — cannot be confirmed by looking at the
response.  It is confirmed by the target reaching back.

An agent asks this tool for a callback address, puts it in the request
it is testing, and then asks what came back.  A finding that was a
guess becomes a finding that was reproduced.

The address is the platform's own callback service: the operator's
traffic is not the business of a public out-of-band service.
"""

from __future__ import annotations

from typing import Any

from ..gateway import ToolContext, ToolError

CREATE_CALLBACK_SCHEMA = {
    "type": "object",
    "properties": {
        "label": {
            "type": "string",
            "description": "What the callback is for, e.g. 'the ssrf in the image url'.",
        },
    },
    "required": ["label"],
    "additionalProperties": False,
}

LIST_CALLBACKS_SCHEMA = {
    "type": "object",
    "properties": {
        "label": {
            "type": "string",
            "description": "Only the callbacks of this label.",
        },
        "limit": {"type": "integer", "default": 50, "maximum": 200},
    },
    "additionalProperties": False,
}


def _repository(context: ToolContext) -> Any:
    repository = context.metadata.get("callbacks_repository")
    if repository is None:
        raise ToolError("the callback service is not available in this context")
    return repository


def create_callback(label: str = "", *, context: ToolContext) -> dict[str, Any]:
    """Create a callback address to watch.

    The address is unique and unguessable.  Put it in the request you
    are testing — a URL parameter, an image source, a header — and then
    call list_callbacks to see whether the target reached back.
    """
    repository = _repository(context)
    base_url = str(context.metadata.get("callback_base_url", "") or "")
    token = repository.create_token(label=label, scan_id=context.scan_id)
    address = f"{base_url}/cb/{token['token']}" if base_url else f"/cb/{token['token']}"
    return {
        "token": token["token"],
        "label": token["label"],
        "url": address,
        "expires_at": token["expires_at"],
        "instruction": (
            "Use the url in the request you are testing, then call list_callbacks "
            "to see whether the target reached back. A finding that a callback "
            "confirms is a finding that reproduces."
        ),
    }


def list_callbacks(label: str = "", limit: int = 50, *, context: ToolContext) -> dict[str, Any]:
    """List the callbacks this scan received.

    A callback is the target reaching back: the evidence that a blind
    finding reproduces.
    """
    repository = _repository(context)
    hits = repository.list_for_scan(context.scan_id)
    if label:
        hits = [hit for hit in hits if str(hit.get("label", "")) == label]
    hits = hits[: max(1, min(int(limit), 200))]
    return {
        "count": len(hits),
        "callbacks": [
            {
                "label": hit.get("label", ""),
                "method": hit.get("method", ""),
                "path": hit.get("path", ""),
                "source": hit.get("source", ""),
                "at": hit.get("at", 0),
                "count": hit.get("count", 1),
                "body": str(hit.get("body", ""))[:1000],
                "headers": hit.get("headers", {}),
            }
            for hit in hits
        ],
    }
