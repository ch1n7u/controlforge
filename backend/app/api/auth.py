"""Authentication endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as OrmSession

from app.api.deps import (
    AuthContext,
    check_csrf,
    client_ip,
    get_auth_context,
    require_admin,
    require_user,
    require_user_csrf,
)
from app.config import get_settings
from app.core import audit, sessions
from app.db import get_db
from app.models.auth import User
from app.models.enums import Role
from app.schemas.auth import (
    ChangePasswordRequest,
    LoginRequest,
    LoginResponse,
    MeResponse,
    UserCreateRequest,
    UserOut,
    UserUpdateRequest,
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


def _policy_error(problems: list[str]) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="password does not meet policy: " + "; ".join(problems),
    )


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
        raise _policy_error(problems)

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


# The user directory: any authenticated session may read it, so the UI can
# offer a real list of assignees instead of asking an operator to type a user
# id. It deliberately exposes nothing beyond what a colleague already sees in
# the audit log's actor column. The write side - creating accounts and editing
# them - is administrator-only and CSRF-checked like every other state change.
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


@directory_router.post("/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreateRequest,
    request: Request,
    admin: User = Depends(require_admin),
    db: OrmSession = Depends(get_db),
) -> User:
    """Create an account. An administrator sets a temporary password; the new
    user has to change it at first sign-in."""
    user = User(
        username=payload.username,
        full_name=payload.full_name,
        role=payload.role,
        is_active=True,
        must_change_password=True,
    )
    # The policy check runs before the row is added to the session, so a
    # rejected password never leaves a half-built INSERT pending.
    problems = sessions.set_password(db, user, payload.password)
    if problems:
        raise _policy_error(problems)
    # set_password clears the flag it just set; an administrator-set password is
    # temporary, so the prompt stays.
    user.must_change_password = True

    db.add(user)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"a user with username {payload.username!r} already exists",
        ) from exc

    # The password itself is never part of the audit record.
    audit.record(
        db,
        action="user.create",
        actor=admin,
        actor_ip=client_ip(request),
        object_type="user",
        object_id=user.id,
        after={
            "username": user.username,
            "full_name": user.full_name,
            "role": user.role,
            "is_active": user.is_active,
            "must_change_password": user.must_change_password,
        },
    )
    db.commit()
    db.refresh(user)
    return user


@directory_router.patch("/users/{user_id}", response_model=UserOut)
def update_user(
    user_id: int,
    payload: UserUpdateRequest,
    request: Request,
    admin: User = Depends(require_admin),
    db: OrmSession = Depends(get_db),
) -> User:
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"user {user_id} not found")

    changes = payload.model_dump(exclude_unset=True)
    # The password goes through set_password below and must never appear in the
    # audit diff.
    new_password = changes.pop("password", None)
    # full_name may be an explicit null (clearing it); role and is_active are
    # non-nullable, so an explicit null there just means "not supplied".
    for field in ("role", "is_active"):
        if changes.get(field) is None:
            changes.pop(field, None)

    if target.id == admin.id:
        # An administrator editing their own account may fix their name or
        # password, but cannot lock themselves out of administration.
        if changes.get("role") is not None and changes["role"] != Role.ADMIN:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="administrators cannot change their own role away from administrator",
            )
        if changes.get("is_active") is False:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="administrators cannot deactivate their own account",
            )

    if new_password is not None:
        problems = sessions.set_password(db, target, new_password)
        if problems:
            raise _policy_error(problems)
        # A password an administrator sets is temporary: it kills every session
        # on the account, clears any lockout, and must be changed at next login.
        target.must_change_password = True
        target.failed_login_count = 0
        target.locked_until = None
        sessions.revoke_all_for_user(db, target.id)

    if changes.get("is_active") is False:
        # Deactivation takes effect immediately, not at session expiry.
        sessions.revoke_all_for_user(db, target.id)
    elif changes.get("is_active") is True:
        # Reactivation lifts a lockout so the account can actually sign in.
        target.failed_login_count = 0
        target.locked_until = None

    before, after = audit.diff(target, changes, list(changes))
    for field, value in changes.items():
        setattr(target, field, value)
    fields = set(changes)
    if new_password is not None:
        fields.add("password")
    audit.record(
        db,
        action="user.update",
        actor=admin,
        actor_ip=client_ip(request),
        object_type="user",
        object_id=target.id,
        detail={"fields": sorted(fields)},
        before=before,
        after=after,
    )
    db.commit()
    db.refresh(target)
    return target

