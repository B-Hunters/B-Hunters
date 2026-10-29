"""API dependencies: authentication, authorization and shared services."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Optional

from fastapi import Depends, Header, HTTPException, Request, status

from ..db.assets import WorkerRunRepository
from ..db.client import Database, get_database
from ..db.issues import IssueRepository
from ..db.jobs import JobRepository, TargetLockRepository
from ..db.repositories import (
    AgentDefinitionRepository,
    AgentStateRepository,
    AuditRepository,
    EventRepository,
    FindingRepository,
    MessageRepository,
    ProviderRepository,
    ScanRepository,
    ServiceRepository,
    SessionRepository,
    TaskRepository,
    ToolCallRepository,
    UserRepository,
)
from ..db.worker_output_repository import WorkerOutputRepository
from ..security.secrets import SecretBox
from ..security.sessions import (
    Session,
    requires_csrf,
    verify_csrf,
)
from ..settings import Settings, get_settings

ROLE_ADMIN = "admin"
ROLE_OPERATOR = "operator"
ROLE_VIEWER = "viewer"

ROLE_RANK = {ROLE_ADMIN: 3, ROLE_OPERATOR: 2, ROLE_VIEWER: 1}


@dataclass
class CurrentUser:
    """The authenticated caller."""

    user_id: str
    username: str
    role: str
    session: Optional[Session] = None

    @property
    def is_admin(self) -> bool:
        return self.role == ROLE_ADMIN

    def can(self, minimum: str) -> bool:
        return ROLE_RANK.get(self.role, 0) >= ROLE_RANK.get(minimum, 99)


class Services:
    """Container for the repositories and long-lived helpers."""

    def __init__(self, database: Optional[Database] = None, settings: Optional[Settings] = None) -> None:
        self.settings = settings or get_settings()
        self.db = database or get_database(self.settings)
        self.users = UserRepository(self.db)
        self.sessions = SessionRepository(self.db)
        self.audit = AuditRepository(self.db)
        self.scans = ScanRepository(self.db)
        self.events = EventRepository(self.db)
        self.tasks = TaskRepository(self.db)
        self.agents = AgentStateRepository(self.db)
        self.messages = MessageRepository(self.db)
        self.tool_calls = ToolCallRepository(self.db)
        #: The durable issues the findings belong to.
        self.issues = IssueRepository(self.db)
        self.findings = FindingRepository(self.db, issues=self.issues)
        #: The encryption of the stored credentials.  ``None`` when the
        #: deployment has not configured a key yet.  It is built before
        #: the providers, because the providers encrypt with it.
        self.secret_box = SecretBox.from_settings(self.settings)
        self.providers = ProviderRepository(self.db, secret_box=self.secret_box)
        self.agent_definitions = AgentDefinitionRepository(self.db)
        self.services = ServiceRepository(self.db)
        #: What the scanner workers produced, saved per scan.
        self.worker_output = WorkerOutputRepository(self.db)
        #: What every worker did in a scan: the tasks it consumed, the
        #: findings it produced and the tasks that crashed.
        self.worker_runs = WorkerRunRepository(self.db)
        #: The durable queue the runner takes its jobs from.
        self.jobs = JobRepository(self.db)
        #: One scan per target at a time.
        self.locks = TargetLockRepository(self.db)

    def ensure_indexes(self) -> None:
        self.db.ensure_indexes()

    def scanner_registry_specs(self) -> list[Any]:
        """Return the declarative specs of the available scanner adapters."""
        from ..scanners.registry import default_all_adapters

        return default_all_adapters()


_services: Optional[Services] = None


def get_services() -> Services:
    """Return the process-wide service container."""
    global _services
    if _services is None:
        _services = Services()
    return _services


def strip_object_id(document: dict[str, Any] | None) -> dict[str, Any]:
    """Return a copy of a MongoDB document without its ``_id``.

    Raw documents carry a BSON ``ObjectId``, which the JSON encoder cannot
    represent.  Every endpoint that returns repository output strips it
    rather than leaking an unserialisable value into the response.
    """
    if not document:
        return {}
    return {key: value for key, value in document.items() if key != "_id"}


def set_services(services: Optional[Services]) -> None:
    """Replace the service container (used by tests)."""
    global _services
    _services = services


def get_session_from_request(request: Request, services: Services) -> Optional[Session]:
    """Look up the session referenced by the request's cookie."""
    cookie_name = services.settings.session_cookie_name
    session_id = request.cookies.get(cookie_name)
    if not session_id:
        return None
    document = services.sessions.get(session_id)
    if not document:
        return None
    if float(document.get("expires_at", 0)) <= time.time():
        services.sessions.delete(session_id)
        return None
    services.sessions.touch(session_id)
    return Session(
        session_id=session_id,
        user_id=document.get("user_id", ""),
        username=document.get("username", ""),
        role=document.get("role", ROLE_VIEWER),
        csrf_token=document.get("csrf_token", ""),
        created_at=float(document.get("created_at", 0)),
        expires_at=float(document.get("expires_at", 0)),
        last_seen_at=float(document.get("last_seen_at", 0)),
        ip_address=document.get("ip_address", ""),
        user_agent=document.get("user_agent", ""),
    )


async def current_user(
    request: Request,
    services: Services = Depends(get_services),
) -> CurrentUser:
    """FastAPI dependency that resolves the authenticated user."""
    session = get_session_from_request(request, services)
    if session is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="authentication required")
    return CurrentUser(user_id=session.user_id, username=session.username, role=session.role, session=session)


async def optional_user(
    request: Request,
    services: Services = Depends(get_services),
) -> Optional[CurrentUser]:
    """Resolve the user when present, without requiring it."""
    session = get_session_from_request(request, services)
    if session is None:
        return None
    return CurrentUser(user_id=session.user_id, username=session.username, role=session.role, session=session)


def require_role(minimum: str) -> Callable[..., Any]:
    """Build a dependency that enforces a minimum role."""

    async def dependency(user: CurrentUser = Depends(current_user)) -> CurrentUser:
        if not user.can(minimum):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"the '{minimum}' role is required for this operation",
            )
        return user

    return dependency


async def enforce_csrf(
    request: Request,
    services: Services = Depends(get_services),
    x_csrf_token: Optional[str] = Header(default=None, alias="X-CSRF-Token"),
) -> None:
    """Enforce CSRF protection on unsafe methods."""
    if not requires_csrf(request.method):
        return
    session = get_session_from_request(request, services)
    if session is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="authentication required")
    provided = x_csrf_token
    if provided is None:
        provided = request.headers.get(services.settings.csrf_header_name)
    if not verify_csrf(session.csrf_token, provided):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="missing or invalid CSRF token")
