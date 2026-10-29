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
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from ...agents.orchestrator import ScanProfile
from ...scanners.worker_output import WORKER_IDENTITIES
from ..deps import CurrentUser, Services, current_user, get_services

router = APIRouter(prefix="/scans", tags=["assets"])


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

    workers = _worker_rows(services, scan_id)
    adapters = _adapter_rows(services, scan)
    return {
        "scan_id": scan_id,
        "workers": workers,
        "native_adapters": adapters,
        "coverage": _coverage(workers, adapters),
        "health": _health(workers),
    }


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
