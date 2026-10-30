"""The participation of the tools in a scan.

The scan records what every tool did: the tasks a worker consumed, the
findings it produced and the tasks that crashed, and the outcome of
every native adapter.  This endpoint turns those facts into the table
the console shows, with a reason for every tool that did not take part.

The reasons are decided by the facts of the scan, not guessed when the
table is read:

``not connected``
    the identity was absent from the online-consumer snapshot taken at
    the start of the scan;
``never dispatched``
    it was connected, but consumed no task for this scan;
``ran, found nothing``
    it consumed at least one task and produced no finding;
``errored``
    it consumed at least one task and had at least one crashed task;
``ran``
    it consumed at least one task and produced findings.

A tool that ran and found nothing is reported as having run and found
nothing.  It is never reported as absent, and it is never reported as a
failure.

The same rule governs the agents: a role that never started is reported
as a role that never started, and a role that was cut off by the
deadline is reported as ``wall_clock``.  Neither of them is ever
reported as a success.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Sequence
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from ...agents.orchestrator import ScanProfile
from ...agents.roles import builtin_roles
from ...agents.schemas import stop_reason_for
from ...errors import ledger_from_records
from ...scanners.worker_output import WORKER_IDENTITIES
from ..deps import CurrentUser, Services, current_user, get_services

router = APIRouter(prefix="/scans", tags=["assets"])

#: The status of a role that never ran.  It is neither a success nor a
#: failure: the role was planned and nothing happened.
NOT_STARTED = "not_started"

#: The most items one page of the transcript returns.
MAX_TRANSCRIPT_ITEMS = 200

#: The most bytes one page of the transcript returns.
MAX_TRANSCRIPT_BYTES = 2 * 1024 * 1024

#: The most rows one collection of the transcript is read from.
MAX_TRANSCRIPT_ROWS = 5000

#: The most failures one answer of the integrity endpoint lists.
MAX_INTEGRITY_ENTRIES = 200


@router.get("/{scan_id}/participation")
async def scan_participation(
    scan_id: str,
    user: CurrentUser = Depends(current_user),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """Which tools took part in the scan, and why the others did not."""
    scan = services.scans.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="the scan does not exist")
    return participation_report(services, scan)


@router.get("/{scan_id}/agents/report")
async def scan_agent_report(
    scan_id: str,
    user: CurrentUser = Depends(current_user),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """What every planned agent role did in the scan."""
    scan = services.scans.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="the scan does not exist")
    return agent_report(services, scan)


@router.get("/{scan_id}/transcript")
async def scan_transcript(
    scan_id: str,
    role: str = "",
    task_id: str = "",
    cursor: str = "",
    limit: int = 100,
    user: CurrentUser = Depends(current_user),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """The transcript of a scan, of one role or of one task.

    The messages and the tool calls are merged into one stream in the
    order they happened.  The page holds at most 200 items and 2 MB;
    ``next_cursor`` points at the rest and ``truncated`` says that
    there is more.
    """
    scan = services.scans.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="the scan does not exist")
    return transcript_page(
        services,
        scan_id,
        role=role,
        task_id=task_id,
        cursor=cursor,
        limit=limit,
    )


@router.get("/{scan_id}/integrity")
async def scan_integrity(
    scan_id: str,
    user: CurrentUser = Depends(current_user),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """The error ledger of the scan and its verdict.

    The ledger is recomputed from the records the scan kept, so the
    verdict can be read long after the scan ended and checked again.
    """
    scan = services.scans.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="the scan does not exist")
    return integrity_report(services, scan)


# ----------------------------------------------------------------------
# The participation
# ----------------------------------------------------------------------
def participation_report(services: Services, scan: Any) -> dict[str, Any]:
    """The participation of the tools of one scan.

    The workers and the native adapters are counted separately and the
    coverage line counts both, so a reader can tell how much of the
    platform took part in the scan.
    """
    workers = _worker_rows(services, scan.scan_id)
    adapters = _adapter_rows(services, scan)
    return {
        "scan_id": scan.scan_id,
        "workers": workers,
        "native_adapters": adapters,
        "coverage": _coverage(workers, adapters),
        "health": _health(workers),
    }


# ----------------------------------------------------------------------
# The agents
# ----------------------------------------------------------------------
def agent_report(services: Services, scan: Any) -> dict[str, Any]:
    """The outcome of every planned role of one scan.

    One row per role.  The row is built from the task the role ran: its
    status, the reason it stopped, the rounds it took, the tool calls it
    made, the tokens it spent and its conclusion.  The findings it
    raised are counted from the stored findings, and the confirmed ones
    are the findings a judge confirmed.

    A role that was planned but never ran is reported as
    ``not_started``: it did not succeed and it did not fail, and saying
    anything else would be a lie.
    """
    tasks = [
        task for task in services.tasks.list_for_scan(scan.scan_id) if str(task.get("kind", "")) == "agent"
    ]
    by_role: dict[str, list[dict[str, Any]]] = {}
    for task in tasks:
        role = str(task.get("agent_role", "") or "")
        if not role:
            continue
        by_role.setdefault(role, []).append(task)

    roles = list(dict.fromkeys(_planned_roles(scan) + sorted(by_role)))
    rows = [_role_row(services, scan.scan_id, role, by_role.get(role, [])) for role in roles]

    stop_reasons: dict[str, int] = {}
    for row in rows:
        reason = row["stop_reason"]
        stop_reasons[reason] = stop_reasons.get(reason, 0) + 1

    return {
        "scan_id": scan.scan_id,
        "roles": rows,
        "stop_reasons": stop_reasons,
        "built_in_roles": len(builtin_roles()),
        "planned_roles": len(rows),
    }


def _planned_roles(scan: Any) -> list[str]:
    """The roles the scan planned.

    A scan that stores no profile runs the default one, which is what
    the runner builds from the same document.
    """
    profile_data = (scan.definition or {}).get("profile") or {}
    profile = ScanProfile.from_dict(profile_data) if profile_data else ScanProfile.default()
    return [str(role) for role in profile.agent_roles]


def _role_row(
    services: Services,
    scan_id: str,
    role: str,
    tasks: list[dict[str, Any]],
) -> dict[str, Any]:
    """One row per role: what it did and what it found."""
    results = [task.get("result") or {} for task in tasks]
    finished = [result for result in results if isinstance(result, dict) and result]
    last = finished[-1] if finished else {}

    status = str(last.get("status", "") or "")
    stop_reason = str(last.get("stop_reason", "") or "")
    if not finished:
        # The role has a task but no result: it never finished.  What
        # the task itself says is the truth here.
        task_status = str((tasks[-1] if tasks else {}).get("status", "") or "")
        if task_status in ("", "pending", "ready"):
            status = NOT_STARTED
            stop_reason = NOT_STARTED
        else:
            status = task_status
            stop_reason = stop_reason_for(task_status)

    raised, confirmed = _findings_of_role(services, scan_id, role)
    conclusion = str(last.get("conclusion", "") or "")
    return {
        "role": role,
        "tasks": len(tasks),
        "status": status,
        "stop_reason": stop_reason,
        "rounds": sum(int(result.get("rounds", 0) or 0) for result in finished),
        "tool_calls": sum(int(result.get("tool_calls_used", 0) or 0) for result in finished),
        "tokens": sum(int(result.get("tokens_used", 0) or 0) for result in finished),
        "findings_raised": raised,
        "findings_confirmed": confirmed,
        "conclusion": conclusion[:400],
    }


def _findings_of_role(services: Services, scan_id: str, role: str) -> tuple[int, int]:
    """The findings a role raised, and the ones that were confirmed."""
    if not role:
        return 0, 0
    raised = services.findings.list(scan_id, detected_by=role, limit=2000)
    confirmed = services.findings.list(
        scan_id,
        detected_by=role,
        verification_status=("confirmed",),
        limit=2000,
    )
    return len(raised), len(confirmed)


# ----------------------------------------------------------------------
# The integrity
# ----------------------------------------------------------------------
def integrity_report(services: Services, scan: Any) -> dict[str, Any]:
    """The error ledger of a scan and its verdict.

    The ledger is read back from the records the scan kept: the tool
    calls that failed, the scanner and the worker errors and the tasks
    that failed.  The verdict is ``fail`` only when a failure has no
    explanation.
    """
    ledger = ledger_from_records(
        tool_calls=services.tool_calls.list_for_scan(scan.scan_id, limit=5000),
        events=services.events.list_after(scan.scan_id, 0, limit=2000),
        tasks=services.tasks.list_for_scan(scan.scan_id),
    )
    verdict = ledger.verdict()
    stored = _stored_integrity(services, scan.scan_id)
    return {
        "scan_id": scan.scan_id,
        "verdict": verdict["verdict"],
        "unexplained": verdict["unexplained"],
        "crash": verdict["crash"],
        "by_class": verdict["by_class"],
        "total": verdict["total"],
        "entries": ledger.entries()[:MAX_INTEGRITY_ENTRIES],
        "entries_count": len(ledger.entries()),
        # What the scan recorded when it ended.
        "stored": stored,
    }


def _stored_integrity(services: Services, scan_id: str) -> dict[str, Any]:
    """The verdict the scan recorded when it ended."""
    document = services.db.collection("platform_scans").find_one({"scan_id": scan_id}) or {}
    stored = document.get("integrity") or {}
    return stored if isinstance(stored, dict) else {}


# ----------------------------------------------------------------------
# The transcript
# ----------------------------------------------------------------------
def transcript_page(
    services: Services,
    scan_id: str,
    *,
    role: str = "",
    task_id: str = "",
    cursor: str = "",
    limit: int = 100,
) -> dict[str, Any]:
    """One page of the transcript of a scan.

    The messages and the tool calls are read oldest first and merged
    into one stream, so that the reader sees what happened and in
    which order.  The cursor points at the last item of the page, and
    the flag says whether there is more to read.
    """
    items = _transcript_items(services, scan_id, role=role, task_id=task_id)
    start = _cursor_position(items, cursor)
    page, truncated = _page_of(items, start, limit)
    return {
        "scan_id": scan_id,
        "messages": [_without_id(item["document"]) for item in page if item["kind"] == "message"],
        "tool_calls": [_without_id(item["document"]) for item in page if item["kind"] == "tool_call"],
        "count": len(page),
        "next_cursor": _encode_cursor(page[-1]) if page and truncated else "",
        "truncated": truncated,
    }


def transcript_text(
    services: Services,
    scan_id: str,
    *,
    role: str = "",
    limit_bytes: int = MAX_TRANSCRIPT_BYTES,
) -> tuple[str, int]:
    """The transcript of a scan as text, with what did not fit.

    The text is cut at the byte budget and the number of the omitted
    bytes is returned, so that the report can say what it left out
    instead of pretending that it printed everything.
    """
    items = _transcript_items(services, scan_id, role=role)
    lines: list[str] = []
    size = 0
    omitted = 0
    for item in items:
        line = _transcript_line(item)
        encoded = len(line.encode("utf-8", errors="ignore"))
        if size + encoded > limit_bytes:
            omitted += encoded
            continue
        lines.append(line)
        size += encoded
    return "\n".join(lines), omitted


def transcript_appendix(
    services: Services,
    scan_id: str,
    *,
    roles: Sequence[str] = (),
    limit_bytes: int = MAX_TRANSCRIPT_BYTES,
) -> tuple[list[dict[str, Any]], int]:
    """The transcript of every role of a scan, with what did not fit.

    The budget is for the whole scan: a scan with twelve roles and a
    few hundred tool calls carries megabytes of text, and a report that
    printed all of it would be a document nobody could open.  The
    number of the omitted bytes is returned, so that the report can say
    what it left out and where the rest is.
    """
    entries: list[dict[str, Any]] = []
    remaining = max(0, int(limit_bytes))
    omitted_total = 0
    for role in roles:
        items = _transcript_items(services, scan_id, role=role)
        lines: list[str] = []
        size = 0
        omitted = 0
        for item in items:
            line = _transcript_line(item)
            encoded = len(line.encode("utf-8", errors="ignore"))
            if size + encoded > remaining:
                omitted += encoded
                continue
            lines.append(line)
            size += encoded
        remaining -= size
        omitted_total += omitted
        entries.append({"role": role, "text": "\n".join(lines), "omitted_bytes": omitted})
    return entries, omitted_total


def _transcript_items(
    services: Services,
    scan_id: str,
    *,
    role: str = "",
    task_id: str = "",
) -> list[dict[str, Any]]:
    """The messages and the tool calls of a scan, in the order they happened.

    The tool calls are stored newest first and the messages oldest
    first, so both are read by their time and merged: the reader gets
    one stream and not two lists that have to be put together by hand.
    """
    items: list[dict[str, Any]] = []

    message_query: dict[str, Any] = {"scan_id": scan_id}
    if task_id:
        message_query["task_id"] = task_id
    if role:
        message_query["sender_role"] = role
    for document in (
        services.db.collection("platform_messages")
        .find(message_query)
        .sort("at", 1)
        .limit(MAX_TRANSCRIPT_ROWS)
    ):
        items.append(
            {
                "kind": "message",
                "rank": 0,
                "at": _at_of(document),
                "ident": str(document.get("message_id", "") or ""),
                "document": document,
            }
        )

    call_query: dict[str, Any] = {"scan_id": scan_id}
    if task_id:
        call_query["task_id"] = task_id
    if role:
        call_query["agent_role"] = role
    for document in (
        services.db.collection("platform_tool_calls")
        .find(call_query)
        .sort("at", 1)
        .limit(MAX_TRANSCRIPT_ROWS)
    ):
        items.append(
            {
                "kind": "tool_call",
                "rank": 1,
                "at": _at_of(document),
                "ident": str(document.get("call_id", "") or ""),
                "document": document,
            }
        )

    items.sort(key=_sort_key)
    return items


def _sort_key(item: dict[str, Any]) -> tuple[float, int, str]:
    """The order of an item in the stream."""
    return (float(item["at"]), int(item["rank"]), str(item["ident"]))


def _at_of(document: dict[str, Any]) -> float:
    """When an item happened."""
    try:
        return float(document.get("at", 0) or 0)
    except (TypeError, ValueError):
        return 0.0


def _without_id(document: dict[str, Any]) -> dict[str, Any]:
    """A document without its BSON identifier, which JSON cannot carry."""
    return {key: value for key, value in document.items() if key != "_id"}


def _item_size(item: dict[str, Any]) -> int:
    """How many bytes an item of the stream takes."""
    try:
        return len(json.dumps(item["document"], default=str).encode("utf-8", errors="ignore"))
    except (TypeError, ValueError):  # pragma: no cover - defensive
        return 0


def _page_of(
    items: list[dict[str, Any]],
    start: int,
    limit: int,
) -> tuple[list[dict[str, Any]], bool]:
    """The items of one page, and whether there are more."""
    count = max(1, min(int(limit), MAX_TRANSCRIPT_ITEMS))
    page: list[dict[str, Any]] = []
    size = 0
    for item in items[start:]:
        if len(page) >= count:
            break
        item_size = _item_size(item)
        if page and size + item_size > MAX_TRANSCRIPT_BYTES:
            break
        page.append(item)
        size += item_size
    return page, start + len(page) < len(items)


def _cursor_position(items: list[dict[str, Any]], cursor: str) -> int:
    """Where the page that follows the cursor starts."""
    key = _decode_cursor(cursor)
    if key is None:
        return 0
    for index, item in enumerate(items):
        if _sort_key(item) > key:
            return index
    return len(items)


def _encode_cursor(item: dict[str, Any]) -> str:
    """The cursor that points at one item of the stream."""
    raw = f"{_sort_key(item)[0]!r}|{_sort_key(item)[1]}|{_sort_key(item)[2]}"
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii").rstrip("=")


def _decode_cursor(cursor: str) -> tuple[float, int, str] | None:
    """The item a cursor points at, or nothing when it is unreadable."""
    if not cursor:
        return None
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
        at, rank, ident = raw.split("|", 2)
        return (float(at), int(rank), ident)
    except (ValueError, TypeError, UnicodeDecodeError):
        return None


def _transcript_line(item: dict[str, Any]) -> str:
    """One item of the transcript as a line of text."""
    document = item["document"]
    if item["kind"] == "message":
        role = str(document.get("sender_role", "") or "")
        kind = str(document.get("kind", "") or "")
        text = str(document.get("hypothesis", "") or "")
        return f"[{role}] {kind}: {text}"
    tool = str(document.get("tool", "") or "")
    status = str(document.get("status", "") or "")
    output = str(document.get("output", "") or document.get("output_summary", "") or "")
    return f"[{document.get('agent_role', '')}] tool {tool} ({status}):\n{output}"


# ----------------------------------------------------------------------
# The workers
# ----------------------------------------------------------------------
def _worker_rows(services: Services, scan_id: str) -> list[dict[str, Any]]:
    """One row per worker the platform knows.

    A worker with no row was not connected when the scan started: the
    snapshot of the online consumers is what says so.
    """
    runs = {str(row.get("worker", "")): row for row in services.worker_runs.list_for_scan(scan_id)}
    items = services.worker_output.counts_for_scan(scan_id)
    versions = _expected_versions(services)

    identities = list(WORKER_IDENTITIES)
    for identity in sorted(runs):
        if identity not in identities:
            identities.append(identity)

    rows: list[dict[str, Any]] = []
    for identity in identities:
        run = runs.get(identity) or {}
        tasks = int(run.get("tasks", 0) or 0)
        rows.append(
            {
                "worker": identity,
                "participated": tasks > 0,
                "reason": _reason_for(run),
                "tasks": tasks,
                "items": int(items.get(identity, 0)),
                "findings": int(run.get("findings", 0) or 0),
                "crashed_tasks": int(run.get("crashed_tasks", 0) or 0),
                "expected_version": str(run.get("expected_version") or versions.get(identity, "")),
                "connected_at_scan_start": bool(run.get("connected")),
            }
        )
    return rows


def _reason_for(run: dict[str, Any]) -> str:
    """Why a worker took part or did not.

    The facts decide: the tasks it consumed, the findings it produced
    and the tasks that crashed.
    """
    if not run:
        return "not connected"
    tasks = int(run.get("tasks", 0) or 0)
    if tasks <= 0:
        return "never dispatched" if run.get("connected") else "not connected"
    if int(run.get("crashed_tasks", 0) or 0) > 0:
        return "errored"
    if int(run.get("findings", 0) or 0) > 0:
        return "ran"
    return "ran, found nothing"


def _expected_versions(services: Services) -> dict[str, str]:
    """The version the platform expects of every worker.

    The workers do not report their version, so this is what the
    platform expects - not what a worker says it is.
    """
    versions: dict[str, str] = {}
    for spec in services.scanner_registry_specs():
        identity = str(getattr(spec, "karton_identity", "") or "")
        if identity:
            versions[identity] = str(getattr(spec, "version", ""))
    return versions


# ----------------------------------------------------------------------
# The native adapters
# ----------------------------------------------------------------------
def _adapter_rows(services: Services, scan: Any) -> list[dict[str, Any]]:
    """One row per native adapter of the platform.

    The status comes from the outcome the scan recorded: an adapter
    that ran and failed is a failure, an adapter that ran and found
    nothing succeeded, and an adapter the profile does not ask for was
    not selected.
    """
    selected = _selected_scanners(scan)
    outcomes = _scanner_outcomes(services, scan.scan_id)

    rows: list[dict[str, Any]] = []
    for spec in services.scanner_registry_specs():
        if str(getattr(spec, "kind", "")) != "native":
            continue
        name = str(getattr(spec, "name", ""))
        outcome = outcomes.get(name) or {}
        if name not in selected:
            status = "not selected"
        elif not outcome:
            status = "not run"
        elif outcome.get("ok"):
            status = "succeeded"
        else:
            status = "failed"
        rows.append(
            {
                "name": name,
                "version": str(getattr(spec, "version", "")),
                "status": status,
                "participated": status in ("succeeded", "failed"),
                "items": int(outcome.get("items", 0) or 0),
                "findings": len(services.findings.list(scan.scan_id, detected_by=name, limit=2000)),
            }
        )
    return rows


def _selected_scanners(scan: Any) -> set[str]:
    """The adapters the scan asked for.

    A scan that stores no profile runs the default one, which is what
    the runner builds from the same document.
    """
    profile_data = (scan.definition or {}).get("profile") or {}
    profile = ScanProfile.from_dict(profile_data) if profile_data else ScanProfile.default()
    return set(profile.scanners)


def _scanner_outcomes(services: Services, scan_id: str) -> dict[str, dict[str, Any]]:
    """What each native adapter did, as the scan recorded it."""
    outcomes: dict[str, dict[str, Any]] = {}
    cursor = services.db.collection("platform_scan_events").find(
        {"scan_id": scan_id, "kind": "scanner.completed"}
    )
    for event in cursor:
        payload = event.get("payload") or {}
        name = str(payload.get("scanner", ""))
        if not name:
            continue
        outcomes[name] = {
            "ok": bool(payload.get("ok")),
            "items": int(payload.get("items", 0) or 0),
            "error": str(payload.get("error", "") or ""),
        }
    return outcomes


# ----------------------------------------------------------------------
# The coverage and the health line
# ----------------------------------------------------------------------
def _coverage(workers: list[dict[str, Any]], adapters: list[dict[str, Any]]) -> dict[str, Any]:
    """The coverage line: what took part and what did not."""
    workers_total = len(workers)
    workers_participated = sum(1 for row in workers if row["participated"])
    workers_not_connected = sum(1 for row in workers if row["reason"] == "not connected")
    adapters_total = len(adapters)
    adapters_participated = sum(1 for row in adapters if row["participated"])

    total = workers_total + adapters_total
    participated = workers_participated + adapters_participated
    not_connected = workers_not_connected
    did_not = max(0, total - participated - not_connected)

    return {
        "workers": {
            "total": workers_total,
            "participated": workers_participated,
            "did_not": max(0, workers_total - workers_participated - workers_not_connected),
            "not_connected": workers_not_connected,
        },
        "native_adapters": {
            "total": adapters_total,
            "participated": adapters_participated,
            "did_not": max(0, adapters_total - adapters_participated),
            "not_selected": sum(1 for row in adapters if row["status"] == "not selected"),
        },
        "line": (
            f"{workers_total} workers and {adapters_total} native adapters: "
            f"{participated} participated, {did_not} did not, "
            f"{not_connected} was not connected"
        ),
    }


def _health(workers: list[dict[str, Any]]) -> dict[str, Any]:
    """The worker health line: who was there and which version is expected."""
    return {
        "online_at_scan_start": [row["worker"] for row in workers if row["connected_at_scan_start"]],
        "not_connected": [row["worker"] for row in workers if row["reason"] == "not connected"],
        "expected_versions": {row["worker"]: row["expected_version"] for row in workers},
        # The workers do not report a version: this is the one the
        # platform expects of them.
        "version_label": "expected",
    }


@router.get("/{scan_id}/diff")
async def scan_diff(
    scan_id: str,
    against: str = "",
    user: CurrentUser = Depends(current_user),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """Compare a scan with an earlier one.

    The earlier scan is the one given by ``against``; without it, the
    last completed scan of the same target that asked the same question
    is used.  Two scans that did not ask the same question are not
    comparable, and the diff says so rather than claiming a difference
    that is not there.
    """
    from ...diffing import compare, comparison_key, is_comparable

    repository = services.issues
    current = services.scans.get(scan_id)
    if current is None:
        raise HTTPException(status_code=404, detail="the scan does not exist")

    baseline = None
    if against:
        baseline = services.scans.get(against)
        if baseline is None:
            raise HTTPException(status_code=404, detail="the scan to compare with does not exist")
    else:
        for candidate in services.scans.list(limit=200):
            if candidate.scan_id == scan_id:
                continue
            if candidate.status != "completed":
                continue
            if comparison_key(_as_dict(candidate)) != comparison_key(_as_dict(current)):
                continue
            baseline = candidate
            break

    comparable, reason = is_comparable(_as_dict(current), _as_dict(baseline) if baseline else None)
    current_issues = repository.list(target_key=_target_key(current))
    baseline_issues = repository.list(target_key=_target_key(baseline)) if baseline else []

    result = compare(
        current=_as_dict(current),
        baseline=_as_dict(baseline) if baseline else None,
        issues_current=current_issues,
        issues_baseline=baseline_issues,
        comparable=comparable,
        reason=reason,
    )
    result["scan_id"] = scan_id
    result["against"] = baseline.scan_id if baseline else ""
    return result


def _as_dict(record: Any) -> dict[str, Any]:
    """A scan record as a mapping."""
    if record is None:
        return {}
    if isinstance(record, dict):
        return record
    return {
        "scan_id": getattr(record, "scan_id", ""),
        "status": getattr(record, "status", ""),
        "phase": getattr(record, "phase", ""),
        "definition": getattr(record, "definition", {}) or {},
        "scope": getattr(record, "scope", {}) or {},
    }


def _target_key(record: Any) -> str:
    """The target key of a scan."""
    return str(getattr(record, "target_key", "") or "")
