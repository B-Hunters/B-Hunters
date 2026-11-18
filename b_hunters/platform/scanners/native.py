"""In-process scanner adapters.

These cover capabilities that the existing B-Hunters modules do not
implement at all:

* security response header evaluation,
* TLS configuration inspection,
* credential detection with redaction,
* OpenAPI specification discovery and checking,
* GraphQL introspection and review,
* dependency analysis against the OSV database,
* asset collection: every URL the target serves.

Every adapter that touches the network does so through the scan's
:class:`~b_hunters.platform.security.scope.ScopeEnforcer`, so the same
scope rules apply to a native adapter as to a Karton worker.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import socket
import ssl
import subprocess
from collections import deque
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import urljoin, urlsplit

from ..assets import classify, is_external, normalise_url
from ..security.redact import redact_text
from ..security.scope import ScopeEnforcer
from .base import ScanRequest, ScanResult
from .routes import as_urls, extract

# The GraphQL adapter lives in its own module because it carries the
# introspection query and the database error signature patterns.
from .graphql_adapter import (  # noqa: F401
    detect_database_error,
    graphql_analysis_executor,
)

log = logging.getLogger(__name__)

# ----------------------------------------------------------------------
# Asset collection limits
# ----------------------------------------------------------------------
#: The most assets one scan records.

#: The status codes that mean the target has refused the scan.
#:
#: A 403 is an edge that has said no.  Asking again is the traffic that
#: turns a refusal into a block, and a scan that keeps going against a
#: refusal is a scan that is not being careful.
REFUSAL_STATUS_CODES = frozenset({403, 401, 406})
ASSET_LIMIT = 2000
#: How far from a seed the crawler walks.
MAX_ASSET_DEPTH = 3
#: How many bytes of one response are read.  The inventory holds
#: metadata only, so a body is read to find its references and no
#: further.
MAX_ASSET_BYTES = 256 * 1024

# ----------------------------------------------------------------------
# Security headers
# ----------------------------------------------------------------------
#: Header name -> (recommended value predicate, severity when missing, description)
SECURITY_HEADERS = {
    "strict-transport-security": (
        lambda v: "max-age" in v.lower(),
        "low",
        "HSTS is not set, so a downgrade to plain HTTP is possible",
    ),
    "content-security-policy": (
        lambda v: bool(v.strip()),
        "medium",
        "No Content-Security-Policy is set, so there is no browser-side mitigation for XSS",
    ),
    "x-content-type-options": (
        lambda v: v.strip().lower() == "nosniff",
        "low",
        "X-Content-Type-Options is missing or is not 'nosniff'",
    ),
    "x-frame-options": (
        lambda v: v.strip().lower() in {"deny", "sameorigin"},
        "medium",
        "X-Frame-Options is missing, so the page can be framed for clickjacking",
    ),
    "referrer-policy": (
        lambda v: bool(v.strip()),
        "low",
        "Referrer-Policy is not set, so referrers leak full URLs to third parties",
    ),
    "permissions-policy": (
        lambda v: bool(v.strip()),
        "info",
        "Permissions-Policy is not set",
    ),
}

#: Headers that should never be present.
DANGEROUS_HEADERS = {
    "server": ("info", "The Server header discloses the server implementation"),
    "x-powered-by": ("info", "The X-Powered-By header discloses the application stack"),
}


async def security_headers_executor(request: ScanRequest) -> ScanResult:
    """Evaluate the security response headers of every in-scope target."""
    import httpx

    scope: Optional[ScopeEnforcer] = request.scope
    items: list[dict[str, Any]] = []
    errors: list[str] = []

    for target in request.targets:
        url = target if "://" in target else f"https://{target}"
        try:
            if scope is not None:
                decision = scope.evaluate_url(url)
                if not decision.allowed:
                    errors.append(f"{url}: {decision.reason}")
                    continue
            timeout = request.options.get("timeout", 15.0)
            async with httpx.AsyncClient(follow_redirects=True, timeout=timeout, verify=False) as client:
                response = await client.get(url)
        except Exception as exc:
            errors.append(f"{url}: {type(exc).__name__}: {exc}")
            continue

        headers = {k.lower(): v for k, v in response.headers.items()}
        findings: list[dict[str, Any]] = []
        for name, (predicate, severity, description) in SECURITY_HEADERS.items():
            value = headers.get(name)
            if value is None:
                findings.append(
                    {
                        "title": f"Missing {name} header",
                        "vuln_class": "security_misconfiguration",
                        "severity": severity,
                        "summary": description,
                        "remediation": f"Send a {name} header with an appropriate value.",
                        "host": urlsplit(url).hostname or "",
                        "affected_url": url,
                        "evidence": [{"kind": "response_headers", "excerpt": f"{name} is absent"}],
                        # The fingerprint of a finding is the class, the
                        # host, the path and the parameter.  Without the
                        # name of the header every missing header of a
                        # target has the same fingerprint, and only the
                        # first one is ever reported.
                        "extra_key": f"header:{name}",
                    }
                )
            elif not predicate(value):
                findings.append(
                    {
                        "title": f"Improper {name} header",
                        "vuln_class": "security_misconfiguration",
                        "severity": severity,
                        "summary": f"{description} (current value: {value})",
                        "remediation": f"Correct the {name} header value.",
                        "host": urlsplit(url).hostname or "",
                        "affected_url": url,
                        "evidence": [{"kind": "response_headers", "excerpt": f"{name}: {value}"}],
                        "extra_key": f"header:{name}",
                    }
                )

        for name, (severity, description) in DANGEROUS_HEADERS.items():
            if name in headers:
                findings.append(
                    {
                        "title": f"Information disclosure via {name} header",
                        "vuln_class": "security_misconfiguration",
                        "severity": severity,
                        "summary": description,
                        "remediation": f"Remove the {name} header from the response.",
                        "host": urlsplit(url).hostname or "",
                        "affected_url": url,
                        "evidence": [{"kind": "response_headers", "excerpt": f"{name}: {headers[name]}"}],
                    }
                )

        items.append(
            {
                "url": url,
                "status": response.status_code,
                "headers_present": sorted(headers),
                "findings": findings,
            }
        )

    return ScanResult(
        scanner="security_headers",
        ok=not errors,
        error="; ".join(errors[:5]),
        kind="finding",
        items=items,
        metadata={"targets_checked": len(request.targets), "failures": errors[:10]},
    )


# ----------------------------------------------------------------------
# TLS configuration
# ----------------------------------------------------------------------
async def tls_configuration_executor(request: ScanRequest) -> ScanResult:
    """Inspect the TLS configuration of every in-scope HTTPS target.

    A plain HTTP target is not a failure of the target: there is no TLS
    session to inspect.  Such a target is skipped, because a handshake
    against an HTTP server only produces a misleading
    ``WRONG_VERSION_NUMBER`` error.
    """
    items: list[dict[str, Any]] = []
    errors: list[str] = []

    for target in request.targets:
        host = target
        port = 443
        if "://" in target:
            parts = urlsplit(target)
            host = parts.hostname or ""
            port = parts.port or 443
            if parts.scheme.lower() != "https":
                continue
        if not host:
            continue

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls:
                    version = tls.version()
                    cipher = tls.cipher()
                    cert = tls.getpeercert(binary_form=False)
        except Exception as exc:
            errors.append(f"{host}:{port}: {type(exc).__name__}: {exc}")
            continue

        expiry = ""
        issuer = ""
        subject = ""
        if isinstance(cert, dict):
            expiry = str(cert.get("notAfter", ""))
            issuer = _flatten_name(cert.get("issuer", ()))
            subject = _flatten_name(cert.get("subject", ()))

        findings: list[dict[str, Any]] = []
        if version in {"TLSv1", "TLSv1.1", "SSLv3"}:
            findings.append(
                {
                    "title": f"Obsolete TLS version negotiated ({version})",
                    "vuln_class": "tls_configuration",
                    "severity": "medium",
                    "summary": f"The server negotiated {version}, which is deprecated.",
                    "remediation": "Disable TLS 1.0/1.1 and require TLS 1.2 or newer.",
                    "host": host,
                    "evidence": [{"kind": "tls_handshake", "excerpt": version}],
                }
            )
        if expiry:
            try:
                from datetime import datetime, timezone

                expiry_dt = datetime.strptime(expiry, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                if expiry_dt < datetime.now(timezone.utc):
                    findings.append(
                        {
                            "title": "Expired TLS certificate",
                            "vuln_class": "tls_configuration",
                            "severity": "medium",
                            "summary": f"The certificate expired on {expiry}.",
                            "remediation": "Renew and deploy a valid certificate.",
                            "host": host,
                            "evidence": [{"kind": "tls_certificate", "excerpt": expiry}],
                        }
                    )
            except ValueError:
                pass

        items.append(
            {
                "host": host,
                "port": port,
                "tls_version": version,
                "cipher": cipher[0] if cipher else "",
                "certificate_expiry": expiry,
                "certificate_issuer": issuer,
                "certificate_subject": subject,
                "findings": findings,
            }
        )

    return ScanResult(
        scanner="tls_configuration",
        ok=not errors,
        error="; ".join(errors[:5]),
        kind="finding",
        items=items,
        metadata={"targets_checked": len(request.targets)},
    )


def _flatten_name(name: Any) -> str:
    parts = []
    for item in name or ():
        for key, value in item:
            parts.append(f"{key}={value}")
    return ", ".join(parts)


# ----------------------------------------------------------------------
# Secret detection
# ----------------------------------------------------------------------
#: Patterns for credentials in source files and JavaScript.
SECRET_PATTERNS: list[tuple[str, str, str]] = [
    ("aws_access_key_id", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", "high"),
    (
        "aws_secret_access_key",
        r"(?i)aws_secret_access_key\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]",
        "critical",
    ),
    ("google_api_key", r"\bAIza[0-9A-Za-z_\-]{35}\b", "high"),
    ("github_token", r"\bgh[pousr]_[A-Za-z0-9]{16,}\b", "critical"),
    ("slack_token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", "high"),
    ("stripe_key", r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b", "critical"),
    ("jwt_token", r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", "medium"),
    ("private_key_block", r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "critical"),
    ("basic_auth_url", r"\b[a-z][a-z0-9+.\-]*://[^/\s:@]+:[^/\s@]+@", "medium"),
    ("password_assignment", r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"\s]{6,64})['\"]", "medium"),
    (
        "api_key_assignment",
        r"(?i)\b(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{12,120})['\"]",
        "high",
    ),
]

#: Assignments that look like secrets but are configuration.
SECRET_FALSE_POSITIVE_KEYS = (
    "example",
    "changeme",
    "your-",
    "your_",
    "placeholder",
    "dummy",
    "sample",
    "test",
    "xxxxx",
    "<",
    "${",
    "process.env",
    "os.environ",
)


async def secret_scan_executor(request: ScanRequest) -> ScanResult:
    """Scan supplied files and JavaScript assets for credentials."""
    items: list[dict[str, Any]] = []
    sources: list[tuple[str, str]] = []

    for seed in request.seeds:
        if await asyncio.to_thread(os.path.isfile, seed):
            content = await asyncio.to_thread(_read_text_file, seed)
            if content is not None:
                sources.append((os.path.basename(seed), content))
        elif seed.startswith(("http://", "https://")):
            body = await _fetch_text(seed, request)
            if body:
                sources.append((seed, body))

    for name, content in sources:
        hits: list[dict[str, Any]] = []
        for label, pattern, severity in SECRET_PATTERNS:
            regex = re.compile(pattern)
            for match in regex.finditer(content):
                line = content[: match.start()].count("\n") + 1
                excerpt = match.group(0)
                if any(marker in excerpt.lower() for marker in SECRET_FALSE_POSITIVE_KEYS):
                    continue
                hits.append(
                    {
                        "kind": label,
                        "severity": severity,
                        "file": name,
                        "line": line,
                        # The value is redacted: only enough to locate it.
                        "excerpt": redact_text(excerpt)[:120],
                    }
                )
        if hits:
            items.append({"source": name, "findings": hits})

    return ScanResult(
        scanner="secret_scan",
        ok=True,
        kind="secret",
        items=items,
        metadata={"sources_scanned": len(sources)},
    )


async def _fetch_text(url: str, request: ScanRequest) -> str:
    """Fetch *url* and return its body, or nothing when it cannot be read."""
    document = await _fetch_document(url, request, limit=4 * 1024 * 1024)
    if not document.allowed or document.error:
        return ""
    return document.text


@dataclass
class FetchedDocument:
    """What one scope-checked request returned.

    The body is read to look at it, never to store it.
    """

    #: Whether the scope allowed the request.
    allowed: bool = False
    #: Why the scope refused it.
    reason: str = ""
    #: The failure of the request itself.
    error: str = ""
    status_code: int = 0
    content_type: str = ""
    #: The number of bytes read, which is capped at the read limit.
    size_bytes: int = 0
    #: The body, which the caller must not store.
    text: str = ""


async def _fetch_document(url: str, request: ScanRequest, *, limit: int = MAX_ASSET_BYTES) -> FetchedDocument:
    """Perform one scope-checked ``GET`` and return its metadata and body.

    Every request this module makes goes through this helper, so the
    scope policy, the rate limit and the concurrency budget are
    enforced in one place.  Only ``GET`` is ever issued, and at most
    *limit* bytes of the body are read.
    """
    import httpx

    scope: Optional[ScopeEnforcer] = request.scope
    reserved = False
    if scope is not None:
        decision = scope.evaluate_url(url)
        if not decision.allowed:
            return FetchedDocument(allowed=False, reason=decision.reason)
        if not await _reserve_slot(scope, decision.host):
            return FetchedDocument(allowed=False, reason="the scan budget is exhausted")
        reserved = True

    timeout = 20.0
    try:
        timeout = float(request.options.get("timeout", 20.0) or 20.0)
    except (TypeError, ValueError):
        timeout = 20.0
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=timeout, verify=False) as client:
            async with client.stream("GET", url) as response:
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) >= limit:
                        break
                status_code = response.status_code
                content_type = response.headers.get("content-type", "").strip()
                encoding = response.encoding or "utf-8"
    except Exception as exc:
        return FetchedDocument(allowed=True, error=f"{type(exc).__name__}: {exc}")
    finally:
        if reserved and scope is not None:
            _release_slot(scope)

    read = bytes(body[:limit])
    return FetchedDocument(
        allowed=True,
        status_code=status_code,
        content_type=content_type,
        size_bytes=len(read),
        text=read.decode(encoding, errors="replace"),
    )


async def _reserve_slot(scope: Any, host: str) -> bool:
    """Apply the enforcer's rate limit and its concurrency budget.

    The enforcer is the only place that knows the scan's limits.  A
    scope that does not implement them - a test double - is not
    throttled.
    """
    throttle = getattr(scope, "throttle", None)
    if callable(throttle):
        await asyncio.to_thread(throttle, host)
    acquire = getattr(scope, "acquire_slot", None)
    if callable(acquire):
        return bool(await asyncio.to_thread(acquire, 30.0))
    return True


def _release_slot(scope: Any) -> None:
    """Give the concurrency slot back to the enforcer."""
    release = getattr(scope, "release_slot", None)
    if callable(release):
        release()


# ----------------------------------------------------------------------
# OpenAPI discovery
# ----------------------------------------------------------------------
OPENAPI_COMMON_PATHS = (
    "/openapi.json",
    "/swagger.json",
    "/api-docs",
    "/api/openapi.json",
    "/api/swagger.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/docs/openapi.json",
    "/docs/swagger.json",
)


async def openapi_discovery_executor(request: ScanRequest) -> ScanResult:
    """Discover and parse an OpenAPI specification for each target."""
    from ..tools.builtin.parsing import analyze_openapi

    items: list[dict[str, Any]] = []
    for target in request.targets:
        base = target if "://" in target else f"https://{target}"
        found: list[dict[str, Any]] = []
        for candidate_path in OPENAPI_COMMON_PATHS:
            url = urljoin(base.rstrip("/") + "/", candidate_path.lstrip("/"))
            body = await _fetch_text(url, request)
            if not body or "openapi" not in body[:5000] and "swagger" not in body[:5000]:
                continue
            try:
                summary = analyze_openapi(body)
            except Exception as exc:
                found.append({"url": url, "error": str(exc)})
                continue
            found.append({"url": url, **summary})
            break
        items.append({"target": base, "specifications": found})

    return ScanResult(
        scanner="openapi_discovery",
        ok=True,
        kind="url",
        items=items,
        metadata={"targets_checked": len(request.targets)},
    )


# ----------------------------------------------------------------------
# GraphQL analysis
# ----------------------------------------------------------------------
# The GraphQL adapter lives in its own module because it carries the
# introspection query and the error-signature patterns.

# ----------------------------------------------------------------------
# Dependency analysis
# ----------------------------------------------------------------------
PY_REQUIREMENT_RE = re.compile(
    r"^\s*([A-Za-z0-9_.\-\[\]]+)\s*(?:\[[^\]]*\])?\s*(==|>=|<=|~=|!=)\s*([0-9][^;\s#]*)", re.M
)
NPM_REQUIREMENT_RE = re.compile(r'"([A-Za-z0-9@/._\-]+)"\s*:\s*"[~^]?([0-9][^"]*)"')


async def dependency_analysis_executor(request: ScanRequest) -> ScanResult:
    """Check dependency manifests against the OSV advisory database.

    When the ``osv-scanner`` binary is not installed the adapter reports
    that it is unavailable rather than pretending to have checked
    anything.
    """
    binary = shutil.which("osv-scanner")
    manifests: list[str] = []
    for seed in request.seeds:
        is_file = await asyncio.to_thread(os.path.isfile, seed)
        if is_file and os.path.basename(seed) in {
            "requirements.txt",
            "package-lock.json",
            "Pipfile.lock",
            "poetry.lock",
            "go.mod",
            "Cargo.lock",
        }:
            manifests.append(seed)

    if not manifests:
        return ScanResult(
            scanner="dependency_analysis",
            ok=True,
            kind="finding",
            items=[],
            metadata={"skipped": "no dependency manifest was supplied"},
        )

    if not binary:
        return ScanResult(
            scanner="dependency_analysis",
            ok=False,
            error="osv-scanner is not installed in this worker image",
            kind="finding",
            items=[],
            metadata={"manifests": manifests, "skipped": "tool not installed"},
        )

    items: list[dict[str, Any]] = []
    for manifest in manifests:
        try:
            stdout = await asyncio.to_thread(_run_osv_scanner, binary, manifest)
        except Exception as exc:
            items.append({"manifest": manifest, "error": str(exc)})
            continue
        try:
            payload = json.loads(stdout or "{}")
        except ValueError:
            payload = {"raw": (stdout or "")[:5000]}
        items.append({"manifest": manifest, "result": payload})

    return ScanResult(
        scanner="dependency_analysis",
        ok=True,
        kind="finding",
        items=items,
        metadata={"manifests": manifests},
    )


# ----------------------------------------------------------------------
# Asset collection
# ----------------------------------------------------------------------
#: The attributes that carry a reference to another URL.
REFERENCE_ATTRIBUTE_RE = re.compile(r"""(?i)\b(?:href|src)\s*=\s*["']([^"']+)["']""")
#: The target of a ``fetch()`` call.
FETCH_TARGET_RE = re.compile(r"""(?i)\bfetch\s*\(\s*["']([^"']+)["']""")
#: The target of an ``XMLHttpRequest.open()`` call.
XHR_TARGET_RE = re.compile(
    r"""(?i)\.open\s*\(\s*["'](?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s*["']\s*,\s*["']([^"']+)["']"""
)
#: The schemes that are not a URL to fetch.
NON_HTTP_SCHEMES = ("javascript:", "mailto:", "tel:", "data:", "about:", "blob:")


async def asset_crawl_executor(request: ScanRequest) -> ScanResult:
    """Crawl the target and record every URL it serves.

    The crawler walks the target the way a browser does: it follows the
    links the pages carry, it records the references the scripts make,
    and it never leaves the origin it started from.  A reference to
    another host is recorded as an external reference and is never
    fetched.

    Only metadata is recorded.  A body is read to find the references
    and is never stored.
    """
    assets: dict[str, dict[str, Any]] = {}
    routes: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    authorized = _authorized_hosts(request)
    seen: set[str] = set()
    queue: deque[tuple[str, str, int, str]] = deque()

    for raw in _crawl_seeds(request, authorized):
        url = normalise_url(raw)
        if not url or url in seen:
            continue
        seen.add(url)
        queue.append((raw, url, 0, ""))

    fetched = 0
    #: The hosts that have refused the scan.  A host that answers 403 has
    #: said no; the crawl stops asking it, rather than becoming the
    #: traffic that gets it blocked for good.
    refused: set[str] = set()
    while queue:
        if len(assets) >= ASSET_LIMIT:
            break
        raw, url, depth, discovered_from = queue.popleft()
        item = assets.setdefault(url, _asset_item(url, depth=depth, discovered_from=discovered_from))

        if is_external(url, authorized):
            # The target itself is not covered by the authorised scope.
            # It is recorded, but the scope decides whether it is fetched.
            item["scope"] = "external"

        host = urlsplit(url).hostname or ""
        if host in refused:
            # The host has already refused.  The reference is recorded
            # and nothing more is asked of it.
            continue

        document = await _fetch_document(raw, request)
        if not document.allowed:
            # The scope refused it.  The reference stays in the inventory
            # without a status, and nothing was fetched.
            continue
        if document.error:
            errors.append(f"{url}: {document.error}")
            continue

        fetched += 1
        item["status_code"] = document.status_code
        item["content_type"] = document.content_type
        item["size_bytes"] = document.size_bytes
        item["kind"] = classify(content_type=document.content_type, url=url)
        item["preview"] = f"{document.status_code} {url}"

        if document.status_code in REFUSAL_STATUS_CODES and host:
            # The target's edge has refused the scan.  Everything else on
            # this host would be refused too, and asking again is the
            # traffic that turns a refusal into a block.
            refused.add(host)
            errors.append(f"{url}: the target refused the scan ({document.status_code})")
            item["refused"] = True

        # The routes a bundle names are not links a crawler follows: they
        # are strings inside the script.  The body is in hand, so they are
        # read out of it here, while it is read for the references.
        if item["kind"] == "js":
            for route in extract(document.text):
                for route_url in as_urls(route, _origin(url)):
                    routes.setdefault(
                        route_url,
                        {
                            "value": route_url,
                            "kind": "api",
                            "scope": "first_party",
                            "status_code": 0,
                            "content_type": "",
                            "size_bytes": 0,
                            "depth": item["depth"] + 1,
                            "discovered_from": url,
                            "preview": route.path,
                        },
                    )

        for reference in _extract_references(document.text):
            if len(assets) >= ASSET_LIMIT:
                break
            child = _resolve(raw, reference)
            if not child:
                continue
            child_url = normalise_url(child)
            if not child_url or child_url in seen:
                continue
            seen.add(child_url)
            child_item = _asset_item(child_url, depth=depth + 1, discovered_from=url)
            assets[child_url] = child_item
            if is_external(child_url, authorized):
                # A reference the scan is not authorised to fetch is
                # recorded, never fetched.
                #
                # The test is the scope, not the origin: a scan that
                # covers ``*.example.com`` is authorised for every
                # subdomain of it, including one the page it was found
                # on does not share an origin with.  Treating a
                # cross-origin reference as third-party on its own
                # stopped the crawl at the apex of a domain and left
                # the whole site unfetched.
                child_item["scope"] = "external"
                continue
            if depth + 1 <= MAX_ASSET_DEPTH:
                queue.append((child, child_url, depth + 1, url))

    return ScanResult(
        scanner="asset_crawl",
        ok=not errors,
        error="; ".join(errors[:5]),
        kind="url",
        items=list(assets.values()) + list(routes.values()),
        metadata={
            "assets": len(assets),
            "fetched": fetched,
            "external": sum(1 for item in assets.values() if item["scope"] == "external"),
            "targets_checked": len(request.targets),
            "max_depth": MAX_ASSET_DEPTH,
            "api_routes": len(routes),
        },
    )


def _origin(url: str) -> str:
    """The scheme and the host of a URL.

    A route is a path on the origin the bundle was served from, so the
    origin is what the route is joined to.
    """
    parts = urlsplit(url)
    if not parts.scheme or not parts.netloc:
        return ""
    return f"{parts.scheme}://{parts.netloc}"


def _asset_item(url: str, *, depth: int, discovered_from: str) -> dict[str, Any]:
    """One row of the asset inventory, before the URL has been fetched."""
    return {
        "value": url,
        "kind": classify(url=url),
        "scope": "first_party",
        "status_code": 0,
        "content_type": "",
        "size_bytes": 0,
        "depth": depth,
        "discovered_from": discovered_from,
        "preview": url,
    }


def _extract_references(text: str) -> list[str]:
    """Return the URLs a body refers to."""
    found: list[str] = []
    for pattern in (REFERENCE_ATTRIBUTE_RE, FETCH_TARGET_RE, XHR_TARGET_RE):
        for match in pattern.finditer(text):
            found.append(match.group(1))
    return found


def _resolve(base: str, reference: str) -> str:
    """Resolve *reference* against the page it was found on."""
    text = (reference or "").strip()
    if not text or text.startswith("#"):
        return ""
    if text.lower().startswith(NON_HTTP_SCHEMES):
        return ""
    try:
        return urljoin(base, text)
    except ValueError:
        return ""


def _is_cross_origin(url: str, base: str) -> bool:
    """Return ``True`` when *url* is on another origin than *base*."""
    try:
        first = urlsplit(url)
        second = urlsplit(base)
        return (first.scheme.lower(), first.hostname or "", first.port) != (
            second.scheme.lower(),
            second.hostname or "",
            second.port,
        )
    except ValueError:
        return True


def _authorized_hosts(request: ScanRequest) -> list[str]:
    """The hosts the crawler treats as first-party.

    The scope policy names them.  A scope that names none - a test
    double - leaves the scan's own targets as the authorised surface.
    """
    policy = getattr(request.scope, "policy", None)
    hosts = [
        str(host).strip().lower()
        for host in (getattr(policy, "authorized_hosts", ()) or ())
        if str(host).strip()
    ]
    if hosts:
        return hosts

    hosts = []
    for target in request.targets:
        url = target if "://" in target else f"https://{target}"
        host = (urlsplit(url).hostname or "").lower()
        if host and host not in hosts:
            hosts.append(host)
    return hosts


def _crawl_seeds(request: ScanRequest, authorized: list[str]) -> list[str]:
    """The URLs the crawl starts from.

    The scan targets are the seeds.  A URL among the operator's own
    seeds joins them when it is in scope.
    """
    seeds: list[str] = []
    for target in request.targets:
        text = (target or "").strip()
        if not text:
            continue
        seeds.append(text if "://" in text else f"https://{text}")
    for seed in request.seeds:
        text = (seed or "").strip()
        if not text.startswith(("http://", "https://")):
            continue
        if is_external(normalise_url(text), authorized):
            continue
        seeds.append(text)
    return seeds


def _read_text_file(path: str, limit: int = 4 * 1024 * 1024) -> str | None:
    """Read a text file, returning ``None`` when it cannot be read."""
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read(limit)
    except OSError:
        return None


def _run_osv_scanner(binary: str, manifest: str, timeout: int = 300) -> str:
    """Run the OSV scanner over one manifest and return its stdout."""
    process = subprocess.run(  # noqa: S603
        [binary, "--format", "json", manifest],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return process.stdout
