"""Benchmark API endpoints."""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from ...bench.lab import LabManager
from ...bench.manifest import default_manifests
from ...bench.runner import BenchmarkRunConfig, BenchmarkRunner
from ...bench.scoring import summarise_for_humans
from ..deps import (
    CurrentUser,
    Services,
    current_user,
    enforce_csrf,
    get_services,
    require_role,
    strip_object_id,
)

router = APIRouter(prefix="/benchmarks", tags=["benchmarks"])


class RunRequest(BaseModel):
    applications: list[str] = Field(default_factory=list)
    provider: str = ""
    profile: str = "standard"
    start_lab: bool = False
    notes: str = ""


@router.get("")
async def list_benchmarks(
    user: CurrentUser = Depends(current_user),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """List the benchmark manifests."""
    manifests = [manifest.to_dict() for manifest in default_manifests()]
    return {"items": manifests, "count": len(manifests)}


@router.get("/lab")
async def lab_status(
    user: CurrentUser = Depends(require_role("operator")),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """Report the state of the vulnerable application laboratory."""
    manager = LabManager()
    return manager.status().to_dict()


@router.post("/lab/up")
async def lab_up(
    request: Request,
    applications: list[str] = Body(default=[]),
    user: CurrentUser = Depends(require_role("admin")),
    services: Services = Depends(get_services),
    csrf: None = Depends(enforce_csrf),
) -> dict[str, Any]:
    """Start the vulnerable application laboratory."""
    manager = LabManager()
    try:
        result = manager.up(applications or None)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    services.audit.record(
        action="bench.lab_up",
        actor=user.username,
        detail={"applications": applications},
        ip_address=request.client.host if request.client else "",
    )
    return result


@router.post("/lab/down")
async def lab_down(
    request: Request,
    user: CurrentUser = Depends(require_role("admin")),
    services: Services = Depends(get_services),
    csrf: None = Depends(enforce_csrf),
) -> dict[str, Any]:
    """Stop and remove the vulnerable application laboratory."""
    manager = LabManager()
    result = manager.down()
    services.audit.record(
        action="bench.lab_down",
        actor=user.username,
        ip_address=request.client.host if request.client else "",
    )
    return result


@router.get("/runs")
async def list_runs(
    limit: int = 50,
    user: CurrentUser = Depends(current_user),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """List the recorded benchmark runs."""
    runs = services.db.collection("platform_benchmark_runs").find({}).sort("started_at", -1).limit(limit)
    return {
        "items": [
            {
                "run_id": run.get("run_id"),
                "benchmark_id": run.get("benchmark_id"),
                "status": run.get("status"),
                "started_at": run.get("started_at"),
                "finished_at": run.get("finished_at"),
                "summary": run.get("summary", {}),
            }
            for run in runs
        ]
    }


@router.get("/runs/{run_id}")
async def get_run(
    run_id: str,
    user: CurrentUser = Depends(current_user),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """Return one benchmark run with its per-test results."""
    run = services.db.collection("platform_benchmark_runs").find_one({"run_id": run_id})
    if run is None:
        raise HTTPException(status_code=404, detail="the benchmark run does not exist")
    results = services.db.collection("platform_benchmark_results").find({"run_id": run_id}).sort("test_id", 1)
    return {
        "run_id": run_id,
        "benchmark_id": run.get("benchmark_id"),
        "status": run.get("status"),
        "started_at": run.get("started_at"),
        "finished_at": run.get("finished_at"),
        "summary": run.get("summary", {}),
        "results": [strip_object_id(item) for item in results],
        "text": summarise_for_humans(run.get("summary", {})),
    }


@router.post("/runs", status_code=status.HTTP_201_CREATED)
async def start_run(
    payload: RunRequest,
    request: Request,
    user: CurrentUser = Depends(require_role("operator")),
    services: Services = Depends(get_services),
    csrf: None = Depends(enforce_csrf),
) -> dict[str, Any]:
    """Start a benchmark run."""
    manager = LabManager()
    if payload.start_lab:
        try:
            manager.up(payload.applications or None)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    async def scan_creator(**kwargs: Any) -> dict[str, Any]:
        from bson import ObjectId

        services_container = services
        targets = kwargs.get("targets", [])
        target = targets[0] if targets else ""
        # The host *with* the port: the subdomain payload and the Domain
        # field have to be the same string, or a worker that derives the
        # status from the URL writes to a document that does not exist.
        host = target.split("://", 1)[-1].split("/", 1)[0]

        # The legacy documents the scanner workers write into, exactly as
        # subrecon creates them.  The legacy scan identifier is also the
        # platform's scan identifier, so the orchestrator, the workers and
        # the benchmark all correlate on one value.
        legacy = services.db
        scan_oid = ObjectId()
        report_oid = ObjectId()
        legacy.collection("scans").insert_one(
            {
                "_id": scan_oid,
                "Domain": host,
                "Type": "single",
                "Description": "benchmark run",
            }
        )
        legacy.collection("reports").insert_one(
            {
                "_id": report_oid,
                "Domain": host,
                "Ports": [],
                "Technology": {},
                "Vulns": {},
                "Paths": [],
                "Paths403": [],
                "Screenshot": "",
                "data": {},
            }
        )
        legacy.collection("domains").insert_one(
            {
                "Scanid": str(scan_oid),
                "Domain": host,
                "report_id": report_oid,
                "resolve": True,
                "active": True,
                "status": {"processing": [], "finished": [], "failed": []},
            }
        )

        # The platform's own record of the same scan.
        record = services_container.scans.create(
            {
                "scan_id": str(scan_oid),
                "name": kwargs.get("name", "benchmark"),
                "status": "queued",
                "created_by": kwargs.get("created_by", user.username),
                "definition": {
                    "targets": kwargs.get("targets", []),
                    "profile": {"name": kwargs.get("profile", "standard")},
                    "benchmark": True,
                },
                "scope": {
                    "authorized_hosts": kwargs.get("authorized_hosts", []),
                    "allow_private_network": kwargs.get("allow_private_network", True),
                    "allow_state_changing": kwargs.get("allow_state_changing", False),
                },
            }
        )
        return {
            "scan_id": str(scan_oid),
            "report_id": report_oid,
            "platform_scan_id": record.scan_id,
        }

    runner = BenchmarkRunner(database=services.db, lab=manager, scan_creator=scan_creator)
    config = BenchmarkRunConfig(
        applications=payload.applications,
        provider=payload.provider,
        profile=payload.profile,
        started_by=user.username,
        notes=payload.notes,
    )
    try:
        outcome = await runner.run(config)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    run = services.db.collection("platform_benchmark_runs").insert_one(
        {
            "run_id": f"run-{int(time.time() * 1000)}",
            "benchmark_id": config.benchmark_id,
            "status": "completed",
            "started_at": outcome["started_at"],
            "finished_at": outcome["finished_at"],
            "summary": outcome["summary"],
            "started_by": user.username,
        }
    )
    run_id = run.inserted_id
    services.db.collection("platform_benchmark_results").insert_many(
        [dict(result, run_id=run_id) for result in outcome["results"]]
    )
    services.audit.record(
        action="bench.run",
        actor=user.username,
        target_type="benchmark_run",
        target_id=str(run_id),
        detail={"applications": payload.applications},
        ip_address=request.client.host if request.client else "",
    )
    return {
        "run_id": str(run_id),
        "summary": outcome["summary"],
        "text": summarise_for_humans(outcome["summary"]),
    }
