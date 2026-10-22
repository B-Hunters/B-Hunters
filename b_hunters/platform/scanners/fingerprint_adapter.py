"""The service fingerprinting adapter.

For every in-scope URL the adapter identifies the services that are
running, their versions, and the signals the identification is based on.
The result is persisted per URL, so that a scan accumulates a service
inventory that can be queried later.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from typing import Any, Optional
from urllib.parse import urljoin

import httpx

from ..security.scope import ScopeEnforcer
from .base import ScanRequest, ScanResult
from .fingerprint import (
    FAVICON_PATHS,
    Fingerprint,
    Service,
    detect_from_body,
    detect_from_cookies,
    detect_from_favicon,
    detect_from_headers,
    detect_from_meta,
    detect_from_tls,
    favicon_hash,
    title_of,
)

#: How many known paths are probed per target.  The probe set is small and
#: fixed, so the request count stays predictable.
MAX_PATH_PROBES = 6

#: The body is truncated before it is analysed.
MAX_BODY_BYTES = 512 * 1024


async def _get(
    client: httpx.AsyncClient,
    url: str,
    scope: Optional[ScopeEnforcer],
    *,
    timeout: float = 15.0,
) -> Optional[httpx.Response]:
    """A scope-checked GET."""
    if scope is not None:
        decision = scope.evaluate_url(url)
        if not decision.allowed:
            return None
    try:
        return await client.get(url, timeout=timeout)
    except Exception:
        return None


async def _tls_details(host: str, port: int) -> dict[str, str]:
    """The certificate issuer and subject."""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: _tls_details_blocking(context, host, port))
    except Exception:
        return {}


def _tls_details_blocking(context: ssl.SSLContext, host: str, port: int) -> dict[str, str]:
    with socket.create_connection((host, port), timeout=8) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            certificate = tls.getpeercert() or {}
            return {
                "issuer": _flatten_name(certificate.get("issuer", ())),
                "subject": _flatten_name(certificate.get("subject", ())),
                "not_after": str(certificate.get("notAfter", "")),
                "version": tls.version() or "",
            }


def _flatten_name(name: Any) -> str:
    parts = []
    for item in name or ():
        for key, value in item:
            parts.append(f"{key}={value}")
    return ", ".join(parts)


async def fingerprint_url(
    url: str,
    *,
    scope: Optional[ScopeEnforcer] = None,
    timeout: float = 15.0,
) -> Fingerprint:
    """Identify the services running on one URL."""
    from urllib.parse import urlparse

    parts = urlparse(url)
    fingerprint = Fingerprint(url=url, host=parts.netloc)

    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=httpx.Timeout(timeout),
        verify=False,  # noqa: S501 - an invalid certificate is a finding
        headers={"User-Agent": "B-Hunters-Fingerprint/1.0"},
    ) as client:
        response = await _get(client, url, scope, timeout=timeout)
        if response is None:
            fingerprint.error = "the target did not answer within the scope and the timeout"
            return fingerprint

        fingerprint.status_code = response.status_code

        # The headers of every hop, not just the final response: a session
        # cookie is often set on the redirect.
        chain = [*response.history, response]
        collected: dict[str, str] = {}
        cookies: list[str] = []
        for hop in chain:
            for key, value in hop.headers.items():
                collected.setdefault(key.lower(), value)
            raw = hop.headers.get("set-cookie", "")
            if raw:
                cookies.append(raw)
        fingerprint.headers = collected
        fingerprint.server = collected.get("server", "")

        body = response.text[:MAX_BODY_BYTES]
        fingerprint.title = title_of(body)
        fingerprint.cookies = detect_from_cookies(" ; ".join(cookies), fingerprint.services)

        detect_from_headers(collected, fingerprint.services)
        detect_from_meta(body, fingerprint.services)
        detect_from_body(body, fingerprint.services)

        # The favicon.
        for path in FAVICON_PATHS:
            favicon_url = urljoin(url, path)
            favicon = await _get(client, favicon_url, scope, timeout=timeout)
            if favicon is not None and favicon.content and favicon.status_code < 400:
                fingerprint.favicon_hash = favicon_hash(favicon.content)
                detect_from_favicon(fingerprint.favicon_hash, fingerprint.services)
                break

        # A small, bounded set of known paths.
        #
        # A path only identifies a stack when the response *differs* from
        # the baseline.  A single-page application answers 200 with the
        # same document for every path, so the status on its own would
        # "detect" whichever stack the probe list happens to mention.
        from .fingerprint import PATH_SIGNATURES

        baseline = _signature(response.text)
        for path, signature in PATH_SIGNATURES[:MAX_PATH_PROBES]:
            probe = await _get(client, urljoin(url, path), scope, timeout=timeout)
            if probe is None:
                continue
            probe_signature = _signature(probe.text)
            distinct = probe_signature != baseline
            fingerprint.probes.append(
                {
                    "path": path,
                    "status_code": probe.status_code,
                    "distinct": distinct,
                }
            )
            if probe.status_code < 400 and distinct:
                _add_service(
                    fingerprint.services,
                    Service(
                        name=signature.product,
                        category=signature.category,
                        confidence=signature.confidence,
                        source=f"path:{path}",
                        evidence=(
                            f"{path} answered HTTP {probe.status_code} with a document "
                            "that differs from the site root"
                        )[:300],
                    ),
                )

    if parts.scheme == "https":
        fingerprint.tls = await _tls_details(parts.hostname or "", parts.port or 443)
        detect_from_tls(fingerprint.tls, fingerprint.services)

    return fingerprint


def _signature(body: str) -> tuple[int, str]:
    """A cheap signature of a response body.

    Two responses with the same length and the same hash are the same
    document.
    """
    import hashlib

    encoded = body.encode("utf-8", errors="replace")
    return len(encoded), hashlib.sha256(encoded).hexdigest()[:16]


def _add_service(services: list[Service], service: Service) -> None:
    from .fingerprint import _add

    _add(services, service)


async def service_fingerprint_executor(request: ScanRequest) -> ScanResult:
    """Fingerprint every in-scope URL and report the services found."""
    scope: Optional[ScopeEnforcer] = request.scope
    timeout = float(request.options.get("timeout", 15.0))
    items: list[dict[str, Any]] = []

    for url in request.targets:
        fingerprint = await fingerprint_url(url, scope=scope, timeout=timeout)
        items.append(fingerprint.to_dict())

    return ScanResult(
        scanner="service_fingerprint",
        ok=True,
        kind="service",
        items=items,
        metadata={"targets_fingerprinted": len(request.targets)},
    )
