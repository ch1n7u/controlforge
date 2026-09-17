"""The audit trail as the UI reads it.

The recorder writes the storage vocabulary (``actor_username``, ``object_type``,
``actor_ip``, ``correlation_id``); the API presents the frontend's names. The
mapping lives on :meth:`AuditEntry.from_row` so the shape and the translation
cannot drift apart.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel

from app.models.audit import AuditLog


def _summarise(action: str, object_type: str | None, object_id: str | None) -> str:
    """One predictable line: the action, then whatever object the row names.

    ``test.create · test 42`` where both parts exist, ``test.create · test`` or
    ``test.create · 42`` where only one does, and just the action when the row
    touched nothing named - never a dangling separator.
    """
    target = " ".join(part for part in (object_type, object_id) if part)
    return f"{action} · {target}" if target else action


class AuditEntry(BaseModel):
    id: int
    ts: datetime
    actor: str | None = None
    actor_user_id: int | None = None
    action: str
    entity_type: str | None = None
    entity_id: str | None = None
    summary: str
    detail: dict[str, Any] | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    request_id: str | None = None

    @classmethod
    def from_row(cls, row: AuditLog) -> "AuditEntry":
        return cls(
            id=row.id,
            ts=row.ts,
            actor=row.actor_username,
            actor_user_id=row.actor_user_id,
            action=row.action,
            entity_type=row.object_type,
            entity_id=row.object_id,
            summary=_summarise(row.action, row.object_type, row.object_id),
            detail=row.detail,
            ip_address=row.actor_ip,
            # User-Agent is not captured anywhere yet; the field stays in the
            # contract (and stays null) so the UI does not have to change when
            # it is.
            user_agent=None,
            request_id=row.correlation_id,
        )


class AuditListOut(BaseModel):
    """The ``{items, total}`` envelope the frontend paginates over."""

    items: list[AuditEntry]
    total: int
