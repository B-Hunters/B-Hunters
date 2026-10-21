"""Scoped HTTP tooling for agents.

Every request made through these tools goes through the scan's
:class:`~b_hunters.platform.security.scope.ScopeEnforcer`, so an agent
cannot reach a host that the operator did not authorise - not even by
following a redirect or by resolving a hostname that points at loopback.
"""

from __future__ import annotations

import hashlib
from typing import Any, Optional

import httpx

from ...security.redact import redact_body, redact_headers, redact_url
from ..gateway import ToolContext, ToolError, ToolScopeError

MAX_BODY_BYTES = 4 * 1024 * 1024


class ScopedHttpClient:
    """An HTTP client that cannot escape the authorised scope."""

    def __init__(self, context: ToolContext, *, follow_redirects: bool = True) -> None:
        self.context = context
        self.follow_redirects = follow_redirects
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> ScopedHttpClient:
        self._client = httpx.AsyncClient(
            follow_redirects=False,
            timeout=httpx.Timeout(30.0),
            limits=httpx.Limits(max_connections=8, max_keepalive_connections=4),
            headers={"User-Agent": "B-Hunters-Agent/1.0"},
            verify=False,
        )
        return self

    async def __aexit__(self, *exc_info) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: str | bytes | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """Perform one scope-checked request, following redirects manually."""
        scope = self.context.scope
        if scope is None:
            raise ToolScopeError("no scope policy is attached to this context")

        chain: list[str] = []
        current_method = (method or "GET").upper()
        current_url = url
        current_headers = dict(headers or {})
        current_body = body

        for _hop in range(scope.policy.max_redirects + 1):
            decision = scope.evaluate_url(current_url, method=current_method)
            if not decision.allowed:
                raise ToolScopeError(f"scope violation: {decision.reason}")

            if not scope.acquire_slot(timeout=timeout or 30.0):
                raise ToolError("scan concurrency or duration budget exhausted")
            if not scope.throttle(decision.host, timeout=timeout or 30.0):
                scope.release_slot()
                raise ToolError("request rate limit exceeded")

            try:
                response = await self._client.request(
                    current_method,
                    current_url,
                    headers=current_headers,
                    content=current_body,
                    timeout=httpx.Timeout(timeout or scope.policy.timeout),
                )
            finally:
                scope.release_slot()

            chain.append(current_url)

            if response.status_code in (301, 302, 303, 307, 308) and self.follow_redirects:
                location = response.headers.get("location")
                if not location:
                    break
                next_url = _absolute(current_url, location)
                redirect_decision = scope.evaluate_url(next_url, method=current_method)
                if not redirect_decision.allowed:
                    raise ToolScopeError(
                        f"redirect to '{redact_url(next_url)}' would leave the authorised scope: "
                        f"{redirect_decision.reason}"
                    )
                if response.status_code == 303:
                    current_method = "GET"
                    current_body = None
                    current_headers.pop("Content-Type", None)
                current_url = next_url
                continue
            break

        return _render_response(response, chain)

    async def get(self, url: str, **kwargs) -> dict[str, Any]:
        return await self.request("GET", url, **kwargs)

    async def head(self, url: str, **kwargs) -> dict[str, Any]:
        return await self.request("HEAD", url, **kwargs)

    async def post(self, url: str, **kwargs) -> dict[str, Any]:
        return await self.request("POST", url, **kwargs)


def _absolute(base: str, location: str) -> str:
    from urllib.parse import urljoin

    return urljoin(base, location)


def _render_response(response: httpx.Response, chain: list[str]) -> dict[str, Any]:
    raw = response.content or b""
    truncated = len(raw) > MAX_BODY_BYTES
    body_bytes = raw[:MAX_BODY_BYTES]
    content_type = response.headers.get("content-type", "")
    text = body_bytes.decode(response.encoding or "utf-8", errors="replace")
    return {
        "status_code": response.status_code,
        "reason": response.reason_phrase,
        "url": redact_url(str(response.url)),
        "final_url": redact_url(str(response.url)),
        "redirect_chain": [redact_url(u) for u in chain],
        "headers": redact_headers(dict(response.headers)),
        "content_type": content_type,
        "body_length": len(raw),
        "body_truncated": truncated,
        "body": redact_body(text, content_type),
        "elapsed_ms": int(response.elapsed.total_seconds() * 1000) if response.elapsed else 0,
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


# ----------------------------------------------------------------------
# Tool handlers
# ----------------------------------------------------------------------
HTTP_REQUEST_SCHEMA = {
    "type": "object",
    "properties": {
        "url": {"type": "string", "description": "Absolute URL to request."},
        "method": {
            "type": "string",
            "enum": ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"],
            "description": "HTTP method. Non-safe methods need explicit permission.",
            "default": "GET",
        },
        "headers": {
            "type": "object",
            "description": "Additional request headers.",
            "additionalProperties": {"type": "string"},
            "default": {},
        },
        "body": {"type": "string", "description": "Request body.", "default": ""},
        "timeout": {"type": "number", "description": "Timeout in seconds.", "default": 20},
    },
    "required": ["url"],
    "additionalProperties": False,
}


async def http_request(
    url: str,
    method: str = "GET",
    headers: dict | None = None,
    body: str = "",
    timeout: float = 20.0,
    *,
    context: ToolContext,
) -> dict[str, Any]:
    """Perform an HTTP request against an in-scope target."""
    async with ScopedHttpClient(context) as client:
        return await client.request(
            (method or "GET").upper(),
            url,
            headers=headers,
            body=body.encode("utf-8") if body else None,
            timeout=timeout,
        )


COMPARE_SCHEMA = {
    "type": "object",
    "properties": {
        "url_a": {"type": "string"},
        "url_b": {"type": "string"},
        "headers_a": {"type": "object", "additionalProperties": {"type": "string"}, "default": {}},
        "headers_b": {"type": "object", "additionalProperties": {"type": "string"}, "default": {}},
        "method": {"type": "string", "default": "GET"},
    },
    "required": ["url_a", "url_b"],
    "additionalProperties": False,
}


async def compare_responses(
    url_a: str,
    url_b: str,
    headers_a: dict | None = None,
    headers_b: dict | None = None,
    method: str = "GET",
    *,
    context: ToolContext,
) -> dict[str, Any]:
    """Compare two responses to detect authorisation differences."""
    async with ScopedHttpClient(context) as client:
        first = await client.request((method or "GET").upper(), url_a, headers=headers_a)
        second = await client.request((method or "GET").upper(), url_b, headers=headers_b)

    body_a = str(first.get("body", ""))
    body_b = str(second.get("body", ""))
    return {
        "a": {
            "url": first.get("url"),
            "status": first.get("status_code"),
            "length": first.get("body_length"),
        },
        "b": {
            "url": second.get("url"),
            "status": second.get("status_code"),
            "length": second.get("body_length"),
        },
        "same_status": first.get("status_code") == second.get("status_code"),
        "same_body": body_a == body_b,
        "body_similarity": _similarity(body_a, body_b),
        "length_delta": int(first.get("body_length", 0)) - int(second.get("body_length", 0)),
        "header_diff": _header_diff(first.get("headers", {}), second.get("headers", {})),
        "verdict": _compare_verdict(first, second, body_a, body_b),
    }


def _similarity(a: str, b: str) -> float:
    import difflib

    if not a and not b:
        return 1.0
    return round(difflib.SequenceMatcher(None, a[:20000], b[:20000]).ratio(), 4)


def _header_diff(a: dict, b: dict) -> dict[str, Any]:
    keys = set(a) | set(b)
    return {k: {"a": a.get(k), "b": b.get(k)} for k in sorted(keys) if a.get(k) != b.get(k)}


def _compare_verdict(first: dict, second: dict, body_a: str, body_b: str) -> str:
    status_a = first.get("status_code")
    status_b = second.get("status_code")
    if status_a != status_b:
        return (
            f"different status codes ({status_a} vs {status_b}); the lower-privileged request "
            "is not being rejected"
        )
    if body_a != body_b and _similarity(body_a, body_b) > 0.95:
        return "same status but bodies differ; verify that the response is not leaking data"
    if status_a == 200 and status_b == 200 and body_a == body_b:
        return "identical responses; this does not by itself prove an access control flaw"
    return "responses are comparable; no clear authorisation difference detected"
