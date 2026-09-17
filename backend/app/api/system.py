"""Platform settings.

Every key has a schema (see :mod:`app.schemas.settings`), so a bad value is a
readable 400 instead of a row of JSON the runner quietly ignores. Writes are
admin-only and audited; the change that matters most - the kill switch - is
visible in the audit log with who flipped it and when.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from app.api.deps import client_ip, require_admin, require_user
from app.core import audit
from app.db import get_db
from app.models.auth import User
from app.models.registry import Setting
from app.schemas.settings import (
    SETTING_KEYS,
    SettingOut,
    SettingUpdate,
    defaults,
    validate_value,
)

router = APIRouter(prefix="/api", tags=["settings"])


def _read(db: OrmSession, key: str) -> Setting | None:
    return db.execute(select(Setting).where(Setting.key == key)).scalar_one_or_none()


@router.get("/settings", response_model=list[SettingOut])
def list_settings(
    db: OrmSession = Depends(get_db), _: User = Depends(require_user)
) -> list[SettingOut]:
    """Every known key, with its stored value or the default it would fall back to."""
    stored = {row.key: row for row in db.execute(select(Setting)).scalars()}
    fallback = defaults()

    out: list[SettingOut] = []
    for key in SETTING_KEYS:
        row = stored.get(key)
        if row is None:
            out.append(
                SettingOut(
                    key=key,
                    value=fallback[key],
                    updated_at=datetime.now(timezone.utc),
                    updated_by_user_id=None,
                    is_default=True,
                )
            )
        else:
            out.append(SettingOut.model_validate(row))
    return out


@router.get("/settings/{key}", response_model=SettingOut)
def get_setting(
    key: str, db: OrmSession = Depends(get_db), _: User = Depends(require_user)
) -> SettingOut:
    if key not in SETTING_KEYS:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"unknown setting {key!r} (known: {', '.join(SETTING_KEYS)})",
        )
    row = _read(db, key)
    if row is None:
        return SettingOut(
            key=key,
            value=defaults()[key],
            updated_at=datetime.now(timezone.utc),
            updated_by_user_id=None,
            is_default=True,
        )
    return SettingOut.model_validate(row)


@router.put("/settings/{key}", response_model=SettingOut)
def put_setting(
    key: str,
    payload: SettingUpdate,
    request: Request,
    user: User = Depends(require_admin),
    db: OrmSession = Depends(get_db),
) -> SettingOut:
    """Replace a setting's value wholesale.

    Replacing rather than merging: half of an old configuration surviving under
    a new one is how you end up with a kill switch that is both on and off.
    """
    if key not in SETTING_KEYS:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"unknown setting {key!r} (known: {', '.join(SETTING_KEYS)})",
        )
    try:
        value = validate_value(key, payload.value)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    row = _read(db, key)
    before = {"value": row.value} if row is not None else None
    if row is None:
        row = Setting(key=key, value=value, updated_by_user_id=user.id)
        db.add(row)
    else:
        row.value = value
        row.updated_by_user_id = user.id

    audit.record(
        db,
        action="setting.update",
        actor=user,
        actor_ip=client_ip(request),
        object_type="setting",
        object_id=key,
        before=before,
        after={"value": value},
    )
    db.commit()
    db.refresh(row)
    return SettingOut.model_validate(row)
