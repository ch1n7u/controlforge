"""Read-only access to the append-only audit trail.

Nothing here can change a row: the trail is written by
:mod:`app.core.audit` and this router only lists it. Filters match the stored
columns exactly, because that is what the values are - a free-text "contains"
search over an audit log invites the reader to believe a result set is complete
when it is not.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session as OrmSession

from app.api.deps import require_user
from app.db import get_db
from app.models.audit import AuditLog
from app.models.auth import User
from app.schemas.audit import AuditEntry, AuditListOut

router = APIRouter(prefix="/api", tags=["audit"])


@router.get("/audit", response_model=AuditListOut)
def list_audit(
    actor_user_id: int | None = None,
    action: str | None = Query(default=None, max_length=64),
    entity_type: str | None = Query(default=None, max_length=64),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: OrmSession = Depends(get_db),
    _: User = Depends(require_user),
) -> AuditListOut:
    """Entries, newest first. ``total`` counts the filtered set, not the page."""
    conditions = []
    if actor_user_id is not None:
        conditions.append(AuditLog.actor_user_id == actor_user_id)
    if action:
        conditions.append(AuditLog.action == action)
    if entity_type:
        conditions.append(AuditLog.object_type == entity_type)

    statement = select(AuditLog)
    counter = select(func.count()).select_from(AuditLog)
    for condition in conditions:
        statement = statement.where(condition)
        counter = counter.where(condition)

    rows = db.execute(
        statement.order_by(AuditLog.ts.desc(), AuditLog.id.desc()).limit(limit).offset(offset)
    ).scalars()
    return AuditListOut(
        items=[AuditEntry.from_row(row) for row in rows],
        total=db.execute(counter).scalar_one(),
    )
