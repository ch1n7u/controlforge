"""Append-only audit trail.

Every security-relevant action lands in the ``audit_log`` table and, as a second
copy, in a JSONL file. The application has no code path that updates or deletes
either one. Failures to write audit records are logged loudly but never break
the operation the user asked for -- except for authentication, where the caller
decides.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.audit import AuditLog
from app.models.auth import User

logger = logging.getLogger("controlforge.audit")
_write_lock = threading.Lock()


def _jsonl_path() -> str:
    return str(get_settings().audit_jsonl_path)


def _append_jsonl(record: dict[str, Any]) -> None:
    path = _jsonl_path()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        line = json.dumps(record, default=str, sort_keys=True)
        with _write_lock, open(path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    except OSError as exc:  # pragma: no cover - depends on host permissions
        logger.warning("could not append audit record to %s: %s", path, exc)


def record(
    session: Session,
    *,
    action: str,
    actor: User | None = None,
    actor_ip: str | None = None,
    object_type: str | None = None,
    object_id: str | int | None = None,
    outcome: str = "success",
    detail: dict[str, Any] | None = None,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
    correlation_id: str | None = None,
    commit: bool = False,
) -> AuditLog:
    entry = AuditLog(
        actor_user_id=actor.id if actor else None,
        actor_username=actor.username if actor else None,
        actor_ip=actor_ip,
        action=action,
        object_type=object_type,
        object_id=str(object_id) if object_id is not None else None,
        outcome=outcome,
        correlation_id=correlation_id,
        detail=detail,
        before=before,
        after=after,
    )
    session.add(entry)
    if commit:
        session.commit()
        session.refresh(entry)

    _append_jsonl(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "actor": actor.username if actor else None,
            "actor_ip": actor_ip,
            "object_type": object_type,
            "object_id": str(object_id) if object_id is not None else None,
            "outcome": outcome,
            "correlation_id": correlation_id,
            "detail": detail,
        }
    )
    return entry


def diff(before: Any, after: Any, fields: list[str]) -> tuple[dict, dict]:
    """Build before/after snapshots limited to the given fields.

    Accepts both ORM rows and plain mappings, because callers pass whichever
    they have: the loaded object for the old state, the validated request body
    for the new one.
    """

    def pick(obj: Any) -> dict:
        if obj is None:
            return {}
        if isinstance(obj, Mapping):
            return {field: obj[field] for field in fields if field in obj}
        return {
            field: getattr(obj, field, None)
            for field in fields
            if hasattr(obj, field)
        }

    return pick(before), pick(after)
