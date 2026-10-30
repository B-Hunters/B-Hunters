"""The access-control comparison tool.

The agent asks for one url twice — once as the primary identity and
once as the secondary one — and the tool puts the two answers side by
side.  A difference is the evidence of an object-level authorisation
flaw.
"""

from __future__ import annotations

from typing import Any

from ...agents.access_control import compare_two_identities
from ..gateway import ToolContext

COMPARE_ACCESS_SCHEMA = {
    "type": "object",
    "properties": {
        "url": {
            "type": "string",
            "description": "The url to ask for as both identities.",
        },
        "method": {"type": "string", "default": "GET"},
    },
    "required": ["url"],
    "additionalProperties": False,
}


async def compare_access(
    url: str,
    method: str = "GET",
    *,
    context: ToolContext,
) -> dict[str, Any]:
    """Ask for one url as two identities and describe the difference.

    The scan needs two identities for this to work: the primary one and
    a second one.  With one identity there is nothing to compare, and
    the tool says so rather than returning an empty answer.
    """
    primary = context.metadata.get("primary_auth") or {}
    secondary = context.metadata.get("secondary_auth") or {}
    if not primary or not secondary:
        return {
            "compared": False,
            "reason": (
                "the scan names one identity; an access-control comparison needs two, "
                "so that the same request can be made as somebody else"
            ),
        }

    from .http import ScopedHttpClient

    async with ScopedHttpClient(context) as client:

        async def requester(target: str, *, method: str = "GET", headers=None, timeout=20.0):
            return await client.request(method, target, headers=headers, timeout=timeout)

        finding = await compare_two_identities(
            url=url,
            primary=primary,
            secondary=secondary,
            request=requester,
            primary_name=str(context.metadata.get("primary_identity_name", "the primary identity")),
            secondary_name=str(context.metadata.get("secondary_identity_name", "the second identity")),
            method=method,
        )
    if finding is None:
        return {
            "compared": True,
            "difference": False,
            "url": url,
            "summary": "both identities received the same answer, so there is no difference",
        }
    return {"compared": True, "difference": True, "finding": finding}
