"""Shared authentication and authorization dependencies."""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session as OrmSession

from app.config import get_settings
from app.core import sessions
from app.core.security import constant_time_equals
from app.db import get_db
from app.models.auth import User, UserSession
from app.models.enums import Role

MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def client_ip(request: Request) -> str | None:
    """nginx terminates every request, so X-Forwarded-For is trustworthy here:
    uvicorn only listens on the loopback interface."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()[:64]
    return request.client.host if request.client else None


@dataclass
class AuthContext:
    user: User
    session_record: UserSession


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)


def get_auth_context(
    request: Request, db: OrmSession = Depends(get_db)
) -> AuthContext:
    settings = get_settings()
    token = request.cookies.get(settings.cookie_name)
    if not token:
        raise _unauthorized("not authenticated")

    record = sessions.resolve_session(db, token)
    if record is None:
        raise _unauthorized("session expired or invalid")

    user = db.get(User, record.user_id)
    if user is None or not user.is_active:
        raise _unauthorized("account is not active")

    request.state.auth = AuthContext(user=user, session_record=record)
    return request.state.auth


def require_user(ctx: AuthContext = Depends(get_auth_context)) -> User:
    """Any authenticated user, read-only access."""
    return ctx.user


def check_csrf(request: Request, ctx: AuthContext) -> None:
    if request.method not in MUTATING_METHODS:
        return
    supplied = request.headers.get("x-csrf-token")
    if not supplied or not constant_time_equals(supplied, ctx.session_record.csrf_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="missing or invalid CSRF token",
        )


def require_user_csrf(
    request: Request, ctx: AuthContext = Depends(get_auth_context)
) -> User:
    """Authenticated user on a state-changing route."""
    check_csrf(request, ctx)
    return ctx.user


def require_writer(
    request: Request, ctx: AuthContext = Depends(get_auth_context)
) -> User:
    """Administrator or analyst: may change configuration and start runs."""
    if ctx.user.role not in (Role.ADMIN, Role.ANALYST):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="requires analyst or administrator role",
        )
    check_csrf(request, ctx)
    return ctx.user


def require_admin(
    request: Request, ctx: AuthContext = Depends(get_auth_context)
) -> User:
    """Administrator only: users, scopes, settings, destructive operations."""
    if ctx.user.role != Role.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="requires administrator role",
        )
    check_csrf(request, ctx)
    return ctx.user
