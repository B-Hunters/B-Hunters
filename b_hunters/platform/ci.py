"""The CI entry point.

A pipeline needs to ask the platform to scan something and to fail when
the answer is bad.  That is what this does: it creates a scan, starts
it, waits for it, prints the findings and answers with an exit code the
pipeline can act on.

The exit code is the whole point.  ``--fail-on high`` means the command
fails when a high finding exists, and the pipeline then does whatever it
does about a high finding.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from typing import Any, Optional

#: The severities, worst first.
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

#: How often the scan is polled while it runs.
POLL_SECONDS = 5.0

#: The states a scan is in when it has finished, one way or another.
FINISHED_STATES = ("completed", "failed", "cancelled")


def severity_rank(severity: str) -> int:
    """Where a severity sits, worst first."""
    try:
        return SEVERITY_ORDER.index(str(severity or "").strip().lower())
    except ValueError:
        return len(SEVERITY_ORDER)


def at_least(severity: str, threshold: str) -> bool:
    """Whether a severity is at least as bad as the threshold."""
    if not threshold:
        return False
    return severity_rank(severity) <= severity_rank(threshold)


def default_request(base_url: str, token: str) -> Callable[..., tuple[int, Any]]:
    """The HTTP caller the command uses.

    It uses the standard library, so the command works in a pipeline
    that has nothing but Python.
    """
    import urllib.error
    import urllib.request

    def request(method: str, path: str, body: Optional[dict[str, Any]] = None) -> tuple[int, Any]:
        url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
        if not url.lower().startswith(("http://", "https://")):
            return 0, {"detail": "the platform address must be an http or https address"}
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)  # noqa: S310
        req.add_header("Authorization", f"Bearer {token}")
        req.add_header("Accept", "application/json")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=60) as response:  # noqa: S310
                raw = response.read().decode()
                return int(response.status), (json.loads(raw) if raw else {})
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode()
            try:
                return int(exc.code), json.loads(raw)
            except ValueError:
                return int(exc.code), {"detail": raw}
        except urllib.error.URLError as exc:
            return 0, {"detail": str(exc)}

    return request


def ci_scan(
    *,
    target: str,
    base_url: str = "http://localhost:8000/api/v1",
    token: str = "",
    wait: bool = True,
    fail_on: str = "high",
    profile: str = "standard",
    name: str = "",
    test_environment: bool = False,
    timeout_seconds: int = 3600,
    poll_seconds: float = POLL_SECONDS,
    request: Optional[Callable[..., tuple[int, Any]]] = None,
    log: Callable[[str], None] = print,
) -> int:
    """Scan a target from a pipeline.

    Returns the exit code: zero when nothing was found at or above the
    threshold, one when there was, and two when the scan itself could
    not be run.
    """
    caller = request or default_request(base_url, token)

    status, created = caller(
        "POST",
        "/scans",
        {
            "name": name or f"ci scan of {target}",
            "description": "a scan started from the command line",
            "targets": {"urls": [target], "authorized_hosts": [_host_of(target)]},
            "profile": profile,
            # The scope.  A target on a private network — a laboratory,
            # an internal service — is refused unless the caller says
            # that the target is a test environment, and then it is
            # allowed.  The flag is the operator's to set, not the
            # command's to assume.
            "test_environment": bool(test_environment),
        },
    )
    if status not in (200, 201):
        log(f"could not create the scan: {created.get('detail', created)}")
        return 2
    scan_id = str(created.get("scan_id", ""))
    if not scan_id:
        log("the platform did not return a scan id")
        return 2

    status, started = caller("POST", f"/scans/{scan_id}/start")
    if status not in (200, 202):
        log(f"could not start the scan: {started.get('detail', started)}")
        return 2

    if wait:
        status, finished = _wait(caller, scan_id, timeout_seconds, poll_seconds, log)
        if status != 200:
            log("the scan could not be read")
            return 2
        if str(finished.get("status", "")) != "completed":
            log(f"the scan ended as '{finished.get('status', 'unknown')}'")
            return 2

    status, findings = caller("GET", f"/findings?scan_id={scan_id}")
    if status != 200:
        log(f"could not read the findings: {findings.get('detail', findings)}")
        return 2

    rows = _rows(findings)
    for row in rows:
        log(
            f"  [{str(row.get('severity', 'info')):>8}] {str(row.get('title', ''))} "
            f"({row.get('vuln_class', '')})"
        )

    bad = [row for row in rows if at_least(str(row.get("severity", "")), fail_on)]
    if bad:
        log(f"{len(bad)} finding(s) at or above '{fail_on}'")
        return 1
    log(f"no finding at or above '{fail_on}'")
    return 0


def _wait(
    caller: Callable[..., tuple[int, Any]],
    scan_id: str,
    timeout_seconds: int,
    poll_seconds: float,
    log: Callable[[str], None],
) -> tuple[int, Any]:
    """Wait for the scan to finish."""
    deadline = time.monotonic() + max(1, timeout_seconds)
    while time.monotonic() < deadline:
        status, payload = caller("GET", f"/scans/{scan_id}")
        if status != 200:
            return status, payload
        if str(payload.get("status", "")) in FINISHED_STATES:
            return status, payload
        time.sleep(poll_seconds)
    return 200, {"status": "timeout"}


def _rows(payload: Any) -> list[dict[str, Any]]:
    """The findings of an answer.

    The endpoint returns them under ``items``; the older shape used
    ``findings``.  Anything that is not a finding is ignored, so a
    shape the command does not know produces an empty list rather than
    a crash.
    """
    if isinstance(payload, dict):
        rows = payload.get("items")
        if rows is None:
            rows = payload.get("findings")
    elif isinstance(payload, list):
        rows = payload
    else:
        rows = None
    if not isinstance(rows, list):
        return []
    return [row for row in rows if isinstance(row, dict)]


def _host_of(target: str) -> str:
    """The host of a target url."""
    from urllib.parse import urlsplit

    try:
        return urlsplit(target).hostname or ""
    except ValueError:
        return ""
