"""The error ledger: a failure the platform can name, and one it cannot.

A scan that probes a target fails requests.  A 404, a refused connection
and a timeout are what a scanner produces when it works; they are not
defects in the platform and they are not findings.  A traceback, an
exception with no explanation, or a tool that produced neither output
nor error is a different thing: something the platform cannot account
for.

The ledger classifies every failure so that the two can be told apart.
The verification of a scan asks it one question — is there an
unexplained error — because a literal "no errors at all" would fail
every scan that did any work.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any

#: The classes a failure can have.  ``crash`` and ``unexplained`` are
#: the two that mean the platform itself did something it cannot
#: account for.
ERROR_CLASSES = (
    "http_status",
    "connection",
    "timeout",
    "dns",
    "scope",
    "permission",
    "unknown_tool",
    "budget",
    "crash",
    "unexplained",
)

#: The classes that fail a scan.  Everything else is an expected
#: outcome of probing a target.
FAILING_CLASSES = ("crash", "unexplained")

_HTTP_STATUS = re.compile(
    r"\bhttp(?:/\d(?:\.\d)?)?\s*(\d{3})\b|"
    r"\b(?:status|status code|code|error)\D{0,12}\b([1-5]\d{2})\b|"
    r"\breturned\s+([1-5]\d{2})\b|"
    r"\b([1-5]\d{2})\s+(?:Not Found|Forbidden|Unauthorized|Unauthorised|Bad Request|"
    r"Internal Server Error|Service Unavailable|Too Many Requests)\b",
    re.IGNORECASE,
)
_CONNECTION = re.compile(
    r"connection (?:refused|reset|aborted|closed|error)|"
    r"could not connect|failed to connect|broken pipe|network is unreachable",
    re.IGNORECASE,
)
_TIMEOUT = re.compile(r"timed? ?out|timeout|deadline exceeded", re.IGNORECASE)
_DNS = re.compile(
    r"could not be resolved|name or service not known|nodename nor servname|"
    r"temporary failure in name resolution|no such host|dns",
    re.IGNORECASE,
)
_SCOPE = re.compile(
    r"out of scope|not in scope|not authorised|not authorized|scope refused|"
    r"outside the authorised scope|outside the authorized scope",
    re.IGNORECASE,
)
_PERMISSION = re.compile(
    r"permission denied|not permitted|forbidden|unauthorised|unauthorized", re.IGNORECASE
)
_UNKNOWN_TOOL = re.compile(r"unknown tool|no such tool|tool .* not found", re.IGNORECASE)
_BUDGET = re.compile(r"budget|exhausted|ran out of", re.IGNORECASE)
_TRACEBACK = re.compile(
    r"traceback \(most recent call last\)|^\s+File \"",
    re.IGNORECASE | re.MULTILINE,
)
_EXCEPTION = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*(?:Error|Exception))\b")

#: The exception classes a platform handles on purpose.  An exception
#: outside this list is a defect in the platform: the code raised
#: something nobody planned for.
EXPECTED_EXCEPTIONS = frozenset(
    {
        "TimeoutError",
        "ConnectionError",
        "ConnectionRefusedError",
        "ConnectionResetError",
        "BrokenPipeError",
        "PermissionError",
        "FileNotFoundError",
        "NotADirectoryError",
        "IsADirectoryError",
        "OSError",
        "IOError",
        "HTTPError",
        "URLError",
        "socket.timeout",
        "socket.gaierror",
    }
)


def classify_error(text: str, status: str = "") -> str:
    """Classify a failure.

    The order matters: a traceback that mentions a timeout is still a
    crash, and an exception the platform never planned for is a crash
    even when the message names a familiar cause.  The platform has to
    explain the failure itself.
    """
    message = str(text or "")

    if _TRACEBACK.search(message):
        return "crash"

    exception = _EXCEPTION.search(message)
    if exception and exception.group(1) not in EXPECTED_EXCEPTIONS:
        return "crash"

    http = _HTTP_STATUS.search(message)
    if http or (status and status.isdigit()):
        return "http_status"
    if _CONNECTION.search(message):
        return "connection"
    if _TIMEOUT.search(message):
        return "timeout"
    if _DNS.search(message):
        return "dns"
    if _SCOPE.search(message):
        return "scope"
    if _UNKNOWN_TOOL.search(message):
        return "unknown_tool"
    if _PERMISSION.search(message):
        return "permission"
    if _BUDGET.search(message):
        return "budget"

    return "unexplained"


class ErrorLedger:
    """Every failure of a scan, classified."""

    def __init__(self) -> None:
        self._entries: list[dict[str, Any]] = []

    def add(self, source: str, detail: str, status: str = "") -> None:
        """Record one failure."""
        self._entries.append(
            {
                "source": source,
                "detail": str(detail or "")[:2000],
                "status": status,
                "class": classify_error(detail, status),
            }
        )

    def entries(self) -> list[dict[str, Any]]:
        """Every recorded failure."""
        return list(self._entries)

    def counts(self) -> dict[str, int]:
        """How many failures there are per class."""
        counts = dict.fromkeys(ERROR_CLASSES, 0)
        for entry in self._entries:
            counts[entry["class"]] = counts.get(entry["class"], 0) + 1
        return counts

    def unexplained(self) -> list[dict[str, Any]]:
        """The failures the platform cannot explain."""
        return [entry for entry in self._entries if entry["class"] in FAILING_CLASSES]

    def verdict(self) -> dict[str, Any]:
        """Whether the scan can be called clean.

        The verdict is ``fail`` when a failure has no explanation: a
        scan that hit a hundred expected 404s is fine, and a scan that
        swallowed a traceback is not.
        """
        counts = self.counts()
        failing = sum(counts.get(name, 0) for name in FAILING_CLASSES)
        return {
            "unexplained": counts.get("unexplained", 0),
            "crash": counts.get("crash", 0),
            "failing": failing,
            "by_class": counts,
            "total": len(self._entries),
            "verdict": "fail" if failing else "pass",
        }


#: The kinds of scan event that record a failure, and where the failure
#: came from.
FAILURE_EVENTS = {
    "scanner.error": "scanner",
    "worker.error": "worker",
    "tool.record_failed": "tool_call",
}


def ledger_from_records(
    *,
    tool_calls: Sequence[Any] = (),
    events: Sequence[Any] = (),
    tasks: Sequence[Any] = (),
) -> ErrorLedger:
    """The ledger of the failures a scan recorded.

    The records are the ones the platform keeps: the tool calls that
    failed, the scanner and the worker errors of the scan and the tasks
    that failed.  A scan that is read long after it ended still gets a
    verdict, and the verdict is the one the scan recorded when it
    finished.
    """
    ledger = ErrorLedger()
    for call in tool_calls:
        if not isinstance(call, dict):
            continue
        if str(call.get("status", "")) != "error":
            continue
        ledger.add("tool_call", str(call.get("error", "") or ""))
    for event in events:
        if not isinstance(event, dict):
            continue
        source = FAILURE_EVENTS.get(str(event.get("kind", "") or ""))
        if source is None:
            continue
        payload = event.get("payload") or {}
        ledger.add(source, str(payload.get("error", "") or ""))
    for task in tasks:
        if not isinstance(task, dict):
            continue
        if str(task.get("status", "")) != "failed":
            continue
        ledger.add("task", str(task.get("error", "") or ""))
    return ledger
