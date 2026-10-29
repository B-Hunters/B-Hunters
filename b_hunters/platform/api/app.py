"""The FastAPI application.

Every route below ``/api/v1`` requires an authenticated session except the
login endpoint and the static frontend assets.  The frontend itself is
served from ``b_hunters/web`` and its protected views redirect to the login
screen when the session is missing.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from ..settings import Settings, get_settings
from .deps import Services, get_services, set_services
from .routers import admin, assets, auth, benchmarks, dashboard, findings, karton, scans

log = logging.getLogger(__name__)

WEB_ROOT = Path(__file__).resolve().parent.parent.parent / "web"


def create_app(
    settings: Settings | None = None,
    services: Services | None = None,
) -> FastAPI:
    """Build the FastAPI application."""
    settings = settings or get_settings()
    if services is not None:
        set_services(services)

    app = FastAPI(
        title="B-Hunters Platform",
        description=(
            "Authenticated API for the B-Hunters application security platform: "
            "scans, findings, agents, Karton monitoring and benchmarking."
        ),
        version="1.2.0",
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(settings.cors_origins),
            allow_credentials=True,
            allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
            allow_headers=["Content-Type", settings.csrf_header_name, "Last-Event-ID"],
        )

    @app.on_event("startup")
    async def _startup() -> None:  # pragma: no cover - exercised by the server
        container = get_services()
        try:
            container.ensure_indexes()
        except Exception as exc:
            log.error("could not create the database indexes: %s", exc)

    prefix = settings.api_prefix
    app.include_router(auth.router, prefix=prefix)
    app.include_router(scans.router, prefix=prefix)
    app.include_router(assets.router, prefix=prefix)
    app.include_router(findings.router, prefix=prefix)
    app.include_router(karton.router, prefix=prefix)
    app.include_router(admin.router, prefix=prefix)
    app.include_router(dashboard.router, prefix=prefix)
    app.include_router(benchmarks.router, prefix=prefix)

    @app.get(f"{prefix}/health", tags=["system"])
    async def health() -> dict[str, Any]:
        """Liveness and readiness probe."""
        container = get_services()
        database_ok = container.db.ping()
        return {
            "status": "ok" if database_ok else "degraded",
            "database": database_ok,
            "environment": settings.environment,
            "version": app.version,
        }

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> JSONResponse:
        container = get_services()
        ok = container.db.ping()
        return JSONResponse(status_code=200 if ok else 503, content={"status": "ok" if ok else "degraded"})

    @app.get("/readyz", include_in_schema=False)
    async def readyz() -> JSONResponse:
        container = get_services()
        ok = container.db.ping()
        return JSONResponse(
            status_code=200 if ok else 503,
            content={"ready": ok, "database": ok, "environment": settings.environment},
        )

    # ------------------------------------------------------------------
    # Frontend
    # ------------------------------------------------------------------
    if WEB_ROOT.exists():
        app.mount(
            "/static",
            StaticFiles(directory=str(WEB_ROOT)),
            name="static",
        )

        @app.get("/", include_in_schema=False)
        async def index() -> Any:
            index_file = WEB_ROOT / "index.html"
            if index_file.exists():
                return FileResponse(str(index_file))
            return RedirectResponse("/api/docs")

        @app.get("/favicon.ico", include_in_schema=False)
        async def favicon() -> Any:
            icon = WEB_ROOT / "favicon.svg"
            if icon.exists():
                return FileResponse(str(icon), media_type="image/svg+xml")
            return JSONResponse(status_code=404, content={"detail": "no icon"})

    return app


app = create_app()
