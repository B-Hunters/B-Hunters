"""The access-control comparison.

An object-level authorisation flaw is not visible to a single session:
the request that is refused to you is the request that is allowed to
somebody else, and the only way to see the difference is to make the
same request twice with two different sessions.

The comparison asks for the same url as the primary identity and as the
secondary one, and puts both answers side by side.  When they differ,
that difference is the evidence: the first identity reaches something
the second one does not.

There is one operator, so the two identities are two accounts of the
operator's own — a test account and a second test account.  The
comparison is only meaningful when the two accounts are meant to be
different, and the finding says which account saw what.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any, Optional

log = logging.getLogger(__name__)

#: The response headers that carry a body.
LENGTH_HEADERS = ("content-length", "x-total-count", "x-result-count")


async def request_with(
    url: str,
    auth: dict[str, Any],
    *,
    request: Callable[..., Any],
    method: str = "GET",
    timeout: float = 20.0,
) -> dict[str, Any]:
    """Make one request as a given identity.

    The auth payload is the one the identity repository builds: the
    cookies and the headers of the session.  The values never appear
    in the finding.
    """
    headers = dict(auth.get("headers", {}) or {})
    cookies = dict(auth.get("cookies", {}) or {})
    if cookies:
        headers["Cookie"] = "; ".join(f"{name}={value}" for name, value in cookies.items())
    try:
        response = await request(url, method=method, headers=headers, timeout=timeout)
    except Exception as exc:
        return {
            "url": url,
            "status": 0,
            "error": f"{type(exc).__name__}: {exc}",
            "length": 0,
            "body_excerpt": "",
        }
    body = str(response.get("body", "") or "")
    return {
        "url": url,
        "status": int(response.get("status", 0) or 0),
        "error": str(response.get("error", "") or ""),
        "length": int(response.get("length", 0) or len(body)),
        "body_excerpt": body[:400],
    }


def compare_responses(
    *,
    url: str,
    primary: dict[str, Any],
    secondary: dict[str, Any],
    primary_name: str = "the primary identity",
    secondary_name: str = "the secondary identity",
) -> Optional[dict[str, Any]]:
    """Compare the two answers and describe the difference.

    Returns ``None`` when the two answers agree: two sessions that see
    the same thing are not evidence of anything.
    """
    if primary.get("status", 0) != secondary.get("status", 0):
        kind = "status"
    elif primary.get("length", 0) != secondary.get("length", 0):
        kind = "length"
    else:
        return None

    first = primary_name if primary.get("status", 0) > secondary.get("status", 0) else secondary_name
    second = secondary_name if first == primary_name else primary_name
    return {
        "title": f"Two sessions see different things at {url}",
        "vuln_class": "access_control",
        "severity": "medium",
        "url": url,
        "summary": (
            f"{primary_name} received {primary.get('status', 0)} and "
            f"{secondary_name} received {secondary.get('status', 0)} for the same request. "
            f"The difference is in the {kind}."
        ),
        "evidence": [
            {
                "kind": "response",
                "identity": primary_name,
                "status": primary.get("status", 0),
                "length": primary.get("length", 0),
                "excerpt": str(primary.get("body_excerpt", ""))[:200],
            },
            {
                "kind": "response",
                "identity": secondary_name,
                "status": secondary.get("status", 0),
                "length": secondary.get("length", 0),
                "excerpt": str(secondary.get("body_excerpt", ""))[:200],
            },
        ],
        "remediation": (
            "The resource has to be checked against the identity of the session that "
            "asked for it, not against whether the session exists."
        ),
        "difference": kind,
        "sees_more": first,
        "sees_less": second,
    }


async def compare_two_identities(
    *,
    url: str,
    primary: dict[str, Any],
    secondary: dict[str, Any],
    request: Callable[..., Any],
    primary_name: str = "the primary identity",
    secondary_name: str = "the secondary identity",
    method: str = "GET",
) -> Optional[dict[str, Any]]:
    """Ask for one url as two identities and describe the difference."""
    first = await request_with(url, primary, request=request, method=method)
    second = await request_with(url, secondary, request=request, method=method)
    return compare_responses(
        url=url,
        primary=first,
        secondary=second,
        primary_name=primary_name,
        secondary_name=secondary_name,
    )
