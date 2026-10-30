"""The callback service.

This is the only part of the platform that is exposed to the outside
world, so it is deliberately narrow: it answers on one path — the path
of a live token — and on nothing else.  Every other path is a 404, so
it cannot be used as a general proxy or as a place to store something.

The service writes into the same database as the rest of the platform,
so an agent can ask for a token, use the address that belongs to it,
and then ask what came back.
"""

from __future__ import annotations

from typing import Any, Optional

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse

from .db.callbacks import CallbackRepository
from .settings import get_settings

#: The body that answers a callback.  It has to say something the
#: target can carry, and it has to say what it is, so that the person
#: reading the target's log knows the callback came from here.
CALLBACK_BODY = "B-Hunters callback\n"

#: The most bytes of a request body that are read.
MAX_REQUEST_BYTES = 64 * 1024


def create_callback_app(repository: CallbackRepository) -> FastAPI:
    """Build the callback service around a repository."""
    app = FastAPI(title="B-Hunters callbacks", docs_url=None, redoc_url=None)

    @app.get("/cb/{token}")
    @app.post("/cb/{token}")
    async def receive(token: str, request: Request) -> Any:
        """Record a callback and answer it.

        The path that is not a live token is not answered at all: the
        service does not confirm that a token exists.
        """
        if not repository.token_is_live(token):
            return PlainTextResponse("not found", status_code=404)

        body = b""
        try:
            body = await request.body()
        except Exception:  # pragma: no cover - a body that will not arrive
            body = b""
        if len(body) > MAX_REQUEST_BYTES:
            body = body[:MAX_REQUEST_BYTES]

        record = repository.record(
            token=token,
            method=request.method,
            path=request.url.path,
            headers=dict(request.headers),
            body=body,
            source=request.client.host if request.client else "",
        )
        if record is None:
            return PlainTextResponse("not found", status_code=404)
        return PlainTextResponse(CALLBACK_BODY)

    @app.get("/readyz", include_in_schema=False)
    async def readyz() -> Any:
        """The health check of the service."""
        return PlainTextResponse("ok")

    @app.get("/")
    async def root() -> Any:
        """The service answers on the callback path only."""
        return PlainTextResponse("B-Hunters callback service", status_code=404)

    return app


def build_app(settings: Optional[Any] = None) -> FastAPI:
    """Build the callback service with its own database."""
    from .db.client import Database

    settings = settings or get_settings()
    database = Database(settings)
    return create_callback_app(CallbackRepository(database))
