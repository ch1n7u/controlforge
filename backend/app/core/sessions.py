"""Server-side sessions: creation, resolution, throttled login and revocation."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from app.config import get_settings
from app.core import audit
from app.core.security import (
    check_password_policy,
    hash_password,
    needs_rehash,
    new_token,
    token_fingerprint,
    verify_password,
)
from app.models.auth import User, UserSession

logger = logging.getLogger("valtros.auth")

LOCKOUT_THRESHOLD = 5
LOCKOUT_MINUTES = 15


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def create_session(
    db: OrmSession,
    user: User,
    *,
    ip_address: str | None,
    user_agent: str | None,
) -> tuple[UserSession, str]:
    settings = get_settings()
    token = new_token()
    record = UserSession(
        user_id=user.id,
        token_hash=token_fingerprint(token),
        csrf_token=new_token(24),
        expires_at=utcnow() + timedelta(hours=settings.session_ttl_hours),
        last_seen_at=utcnow(),
        ip_address=ip_address,
        user_agent=(user_agent or "")[:400] or None,
    )
    db.add(record)
    db.flush()
    return record, token


def resolve_session(db: OrmSession, token: str) -> UserSession | None:
    """Return a live session for the token, or None. Applies idle timeout."""
    settings = get_settings()
    record = db.execute(
        select(UserSession).where(UserSession.token_hash == token_fingerprint(token))
    ).scalar_one_or_none()

    if record is None or record.revoked_at is not None:
        return None

    now = utcnow()
    if record.expires_at <= now:
        return None

    idle_deadline = record.last_seen_at + timedelta(minutes=settings.session_idle_timeout_minutes)
    if idle_deadline <= now:
        record.revoked_at = now
        logger.info("session %s revoked after idle timeout", record.id)
        return None

    record.last_seen_at = now
    return record


def revoke_session(db: OrmSession, record: UserSession) -> None:
    if record.revoked_at is None:
        record.revoked_at = utcnow()


def revoke_all_for_user(db: OrmSession, user_id: int) -> int:
    now = utcnow()
    sessions = db.execute(
        select(UserSession).where(
            UserSession.user_id == user_id, UserSession.revoked_at.is_(None)
        )
    ).scalars().all()
    for record in sessions:
        record.revoked_at = now
    return len(sessions)


def authenticate(
    db: OrmSession,
    username: str,
    password: str,
    *,
    ip_address: str | None = None,
) -> tuple[User | None, str]:
    """Verify credentials, applying lockout. Returns (user, reason-if-failed)."""
    user = db.execute(
        select(User).where(User.username == username)
    ).scalar_one_or_none()

    if user is None:
        # Still spend time verifying so a missing user is not faster than a wrong
        # password; keeps username enumeration by timing impractical.
        verify_password(password, hash_password("timing-equalizer"))
        audit.record(
            db,
            action="auth.login",
            actor_ip=ip_address,
            outcome="failure",
            detail={"username": username, "reason": "unknown_user"},
            commit=True,
        )
        return None, "invalid credentials"

    now = utcnow()
    if user.locked_until is not None and user.locked_until > now:
        audit.record(
            db,
            action="auth.login",
            actor=user,
            actor_ip=ip_address,
            outcome="failure",
            detail={"reason": "locked"},
            commit=True,
        )
        return None, "account temporarily locked"

    if not user.is_active:
        audit.record(
            db,
            action="auth.login",
            actor=user,
            actor_ip=ip_address,
            outcome="failure",
            detail={"reason": "inactive"},
            commit=True,
        )
        return None, "account is disabled"

    if not verify_password(password, user.password_hash):
        user.failed_login_count += 1
        locked = False
        if user.failed_login_count >= LOCKOUT_THRESHOLD:
            user.locked_until = now + timedelta(minutes=LOCKOUT_MINUTES)
            user.failed_login_count = 0
            locked = True
        audit.record(
            db,
            action="auth.login",
            actor=user,
            actor_ip=ip_address,
            outcome="failure",
            detail={"reason": "bad_password", "locked_out": locked},
            commit=True,
        )
        return None, "invalid credentials"

    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)

    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = now
    return user, ""


def set_password(db: OrmSession, user: User, new_password: str) -> list[str]:
    problems = check_password_policy(new_password)
    if problems:
        return problems
    user.password_hash = hash_password(new_password)
    user.must_change_password = False
    return []
