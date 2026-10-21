"""Authentication endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from ...security.passwords import validate_password_strength, verify_password
from ...security.sessions import (
    LoginThrottle,
    build_session,
    clear_session_cookies,
    generate_session_id,
    session_to_dict,
    set_session_cookies,
)
from ..deps import CurrentUser, Services, current_user, get_services

router = APIRouter(prefix="/auth", tags=["auth"])

#: Shared login throttle.  A multi-node deployment should also share the
#: counters through the database.
_throttle = LoginThrottle()


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)


class LoginResponse(BaseModel):
    username: str
    role: str
    csrf_token: str
    expires_at: float


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=256)


@router.post("/login", response_model=LoginResponse)
async def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    services: Services = Depends(get_services),
) -> LoginResponse:
    """Authenticate a user and start a session."""
    settings = services.settings
    ip_address = request.client.host if request.client else ""
    username = payload.username.strip().lower()

    if _throttle.is_locked(username, ip_address):
        remaining = _throttle.remaining_lockout(username, ip_address)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"too many failed login attempts; try again in {remaining}s",
        )

    user = services.users.get_by_username(username)
    if user is None or not user.get("active", True):
        # Hash anyway so that a missing user is not faster than a wrong password.
        verify_password(payload.password, None)
        _throttle.register_failure(username, ip_address)
        services.audit.record(
            action="auth.login",
            actor=username,
            detail={"reason": "unknown or inactive user"},
            ip_address=ip_address,
            outcome="failure",
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials")

    if not verify_password(payload.password, user.get("password_hash")):
        attempts = _throttle.register_failure(username, ip_address)
        services.audit.record(
            action="auth.login",
            actor=username,
            detail={"attempts": attempts},
            ip_address=ip_address,
            outcome="failure",
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials")

    _throttle.register_success(username, ip_address)
    session = build_session(
        session_id=generate_session_id(),
        user_id=user["user_id"],
        username=user["username"],
        role=user.get("role", "viewer"),
        ttl_seconds=settings.session_ttl_seconds,
        ip_address=ip_address,
        user_agent=request.headers.get("user-agent", ""),
    )
    services.sessions.create(session_to_dict(session))
    services.users.record_login(user["user_id"])
    services.audit.record(
        action="auth.login",
        actor=user["username"],
        target_type="session",
        target_id=session.session_id[:12],
        ip_address=ip_address,
        outcome="success",
    )

    set_session_cookies(
        response,
        session,
        cookie_name=settings.session_cookie_name,
        csrf_cookie_name=settings.csrf_cookie_name,
        secure=settings.session_cookie_secure,
        samesite=settings.cookie_samesite,
    )
    return LoginResponse(
        username=session.username,
        role=session.role,
        csrf_token=session.csrf_token,
        expires_at=session.expires_at,
    )


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    user: CurrentUser = Depends(current_user),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """End the current session."""
    settings = services.settings
    session_id = request.cookies.get(settings.session_cookie_name)
    if session_id:
        services.sessions.delete(session_id)
    services.audit.record(
        action="auth.logout",
        actor=user.username,
        ip_address=request.client.host if request.client else "",
    )
    clear_session_cookies(
        response,
        cookie_name=settings.session_cookie_name,
        csrf_cookie_name=settings.csrf_cookie_name,
        secure=settings.session_cookie_secure,
        samesite=settings.cookie_samesite,
    )
    return {"status": "logged_out"}


@router.get("/me")
async def me(user: CurrentUser = Depends(current_user)) -> dict[str, Any]:
    """Return the authenticated identity."""
    return {
        "user_id": user.user_id,
        "username": user.username,
        "role": user.role,
        "csrf_token": user.session.csrf_token if user.session else "",
    }


@router.post("/password")
async def change_password(
    payload: PasswordChangeRequest,
    request: Request,
    response: Response,
    user: CurrentUser = Depends(current_user),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """Change the authenticated user's password."""
    document = services.users.get_by_id(user.user_id)
    if document is None:
        raise HTTPException(status_code=404, detail="the user no longer exists")
    if not verify_password(payload.current_password, document.get("password_hash")):
        services.audit.record(
            action="auth.password_change",
            actor=user.username,
            ip_address=request.client.host if request.client else "",
            outcome="failure",
        )
        raise HTTPException(status_code=403, detail="the current password is incorrect")

    problems = validate_password_strength(payload.new_password)
    if problems:
        raise HTTPException(status_code=400, detail="; ".join(problems))

    services.users.set_password(user.user_id, payload.new_password)
    services.sessions.delete_for_user(user.user_id)
    services.audit.record(
        action="auth.password_change",
        actor=user.username,
        ip_address=request.client.host if request.client else "",
    )
    clear_session_cookies(
        response,
        cookie_name=services.settings.session_cookie_name,
        csrf_cookie_name=services.settings.csrf_cookie_name,
        secure=services.settings.session_cookie_secure,
        samesite=services.settings.cookie_samesite,
    )
    return {"status": "password_changed", "reauthentication_required": True}
