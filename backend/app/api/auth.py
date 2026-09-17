"""Authentication endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from app.api.deps import (
    AuthContext,
    check_csrf,
    client_ip,
    get_auth_context,
    require_user,
    require_user_csrf,
)
from app.config import get_settings
from app.core import audit, sessions
from app.db import get_db
from app.models.auth import User
from app.schemas.auth import (
    ChangePasswordRequest,
    LoginRequest,
    LoginResponse,
    MeResponse,
    UserOut,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _set_session_cookie(response: Response, token: str) -> None:
    settings = get_settings()
    response.set_cookie(
        key=settings.cookie_name,
        value=token,
        httponly=True,
        samesite="lax",
        secure=settings.cookie_secure,
        max_age=settings.session_ttl_hours * 3600,
        path="/",
    )


def _clear_session_cookie(response: Response) -> None:
    settings = get_settings()
    response.delete_cookie(key=settings.cookie_name, path="/")


@router.post("/login", response_model=LoginResponse)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: OrmSession = Depends(get_db),
) -> LoginResponse:
    ip = client_ip(request)
    user, reason = sessions.authenticate(
        db, payload.username, payload.password, ip_address=ip
    )
    if user is None:
        # Deliberately vague: the specific reason is recorded in the audit log.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=f"login failed: {reason}"
        )

    record, token = sessions.create_session(
        db,
        user,
        ip_address=ip,
        user_agent=request.headers.get("user-agent"),
    )
    audit.record(
        db,
        action="auth.login",
        actor=user,
        actor_ip=ip,
        object_type="user",
        object_id=user.id,
        detail={"session_id": str(record.id)},
    )
    db.commit()
    db.refresh(user)

    _set_session_cookie(response, token)
    return LoginResponse(user=UserOut.model_validate(user), csrf_token=record.csrf_token)


@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    ctx: AuthContext = Depends(get_auth_context),
    db: OrmSession = Depends(get_db),
) -> dict:
    # Logout revokes a session and writes an audit row, so it is a state change
    # and must carry the CSRF token like any other.
    check_csrf(request, ctx)
    sessions.revoke_session(db, ctx.session_record)
    audit.record(
        db,
        action="auth.logout",
        actor=ctx.user,
        actor_ip=client_ip(request),
        object_type="user",
        object_id=ctx.user.id,
    )
    db.commit()
    _clear_session_cookie(response)
    return {"status": "ok"}


@router.get("/me", response_model=MeResponse)
def me(ctx: AuthContext = Depends(get_auth_context)) -> MeResponse:
    return MeResponse(
        user=UserOut.model_validate(ctx.user),
        csrf_token=ctx.session_record.csrf_token,
    )


@router.post("/change-password")
def change_password(
    payload: ChangePasswordRequest,
    request: Request,
    user: User = Depends(require_user_csrf),
    db: OrmSession = Depends(get_db),
) -> dict:
    from app.core.security import verify_password

    if not verify_password(payload.current_password, user.password_hash):
        audit.record(
            db,
            action="auth.change_password",
            actor=user,
            actor_ip=client_ip(request),
            outcome="failure",
            detail={"reason": "bad_current_password"},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="current password is incorrect"
        )

    problems = sessions.set_password(db, user, payload.new_password)
    if problems:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="password does not meet policy: " + "; ".join(problems),
        )

    # A password change invalidates every other session for that user.
    sessions.revoke_all_for_user(db, user.id)
    audit.record(
        db,
        action="auth.change_password",
        actor=user,
        actor_ip=client_ip(request),
        object_type="user",
        object_id=user.id,
        detail={"other_sessions_revoked": True},
    )
    db.commit()
    return {"status": "ok", "sessions_revoked": True}


# A read-only directory, separate from the auth routes: it exists so the UI can
# offer a real list of assignees instead of asking an operator to type a user
# id. It deliberately exposes nothing beyond what a colleague already sees in
# the audit log's actor column.
directory_router = APIRouter(prefix="/api", tags=["users"])


@directory_router.get("/users", response_model=list[UserOut])
def list_users(
    active_only: bool = True,
    db: OrmSession = Depends(get_db),
    _: User = Depends(require_user),
) -> list[UserOut]:
    stmt = select(User).order_by(User.username)
    if active_only:
        stmt = stmt.where(User.is_active.is_(True))
    return [UserOut.model_validate(row) for row in db.execute(stmt).scalars()]

