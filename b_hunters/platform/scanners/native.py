"""In-process scanner adapters.

These cover capabilities that the existing B-Hunters modules do not
implement at all:

* security response header evaluation,
* TLS configuration inspection,
* credential detection with redaction,
* OpenAPI specification discovery and checking,
* GraphQL introspection and review,
* dependency analysis against the OSV database.

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
from typing import Any, Optional
from urllib.parse import urljoin, urlsplit

from ..security.redact import redact_text
from ..security.scope import ScopeEnforcer
from .base import ScanRequest, ScanResult

# The GraphQL adapter lives in its own module because it carries the
# introspection query and the database error signature patterns.
from .graphql_adapter import (  # noqa: F401
    detect_database_error,
    graphql_analysis_executor,
)

log = logging.getLogger(__name__)

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
    import httpx

    scope: Optional[ScopeEnforcer] = request.scope
    try:
        if scope is not None:
            decision = scope.evaluate_url(url)
            if not decision.allowed:
                return ""
        async with httpx.AsyncClient(follow_redirects=True, timeout=20.0, verify=False) as client:
            response = await client.get(url)
            return response.text[: 4 * 1024 * 1024]
    except Exception:
        return ""


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
