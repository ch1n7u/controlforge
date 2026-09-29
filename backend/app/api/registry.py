"""Control registry CRUD: frameworks, controls, targets and scopes.

Scope entries are the one place in this router where the request can be
*refused for policy reasons* rather than schema reasons. Every entry is run
through :func:`app.scope.policy.validate_entry` before it is stored, so an
over-broad, denied or loopback-without-a-lab authorization is rejected here -
at the moment a human is watching - instead of failing silently at run time.
"""

from __future__ import annotations

from collections.abc import Iterable

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as OrmSession, selectinload

from app.api.deps import client_ip, require_admin, require_user, require_writer
from app.core import audit
from app.db import get_db
from app.models.auth import User
from app.models.findings import Finding
from app.models.registry import (
    Control,
    Framework,
    FrameworkRef,
    Scope,
    ScopeEntry,
    Target,
    TargetScope,
)
from app.models.testing import ValidationRun, ValidationTest
from app.queue import jobs
from app.schemas.registry import (
    ControlCreate,
    ControlOut,
    ControlUpdate,
    FrameworkCreate,
    FrameworkOut,
    FrameworkRefCreate,
    FrameworkRefOut,
    FrameworkUpdate,
    ScopeCreate,
    ScopeEntryCreate,
    ScopeEntryOut,
    ScopeOut,
    ScopeUpdate,
    TargetCreate,
    TargetOut,
    TargetUpdate,
)
from app.scope.policy import ScopePolicy, ScopePolicyError, validate_entry

router = APIRouter(prefix="/api", tags=["registry"])


def _not_found(what: str, ident: int) -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"{what} {ident} not found")


def _conflict(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_409_CONFLICT, detail=detail)


def _policy_refusal(exc: ValueError) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"scope policy refused this entry: {exc}",
    )


def _scope_policy(scope: Scope) -> ScopePolicy:
    return ScopePolicy(
        allow_broad=scope.allow_broad,
        is_lab=scope.is_lab,
        authorization_ref=scope.authorization_ref,
    )


def _apply_entry(scope: Scope, payload: ScopeEntryCreate) -> ScopeEntry:
    try:
        normalized = validate_entry(
            payload.kind.value,
            payload.value,
            payload.ports,
            payload.protocol,
            _scope_policy(scope),
        )
    except ScopePolicyError as exc:
        raise _policy_refusal(exc) from exc

    entry = ScopeEntry(
        kind=payload.kind,
        value=normalized.value,
        ports=normalized.ports,
        protocol=normalized.protocol,
        note=payload.note,
    )
    # Attach through the relationship, not just the foreign key: the session is
    # configured with autoflush=False and expire_on_commit=False, so a scope
    # whose ``entries`` collection was already read would keep serving the stale
    # (empty) list for the rest of the request.
    scope.entries.append(entry)
    return entry


# ---------------------------------------------------------------- frameworks ---


@router.get("/frameworks", response_model=list[FrameworkOut])
def list_frameworks(
    db: OrmSession = Depends(get_db), _: User = Depends(require_user)
) -> list[Framework]:
    return list(db.execute(select(Framework).order_by(Framework.key)).scalars())


@router.post("/frameworks", response_model=FrameworkOut, status_code=status.HTTP_201_CREATED)
def create_framework(
    payload: FrameworkCreate,
    request: Request,
    user: User = Depends(require_writer),
    db: OrmSession = Depends(get_db),
) -> Framework:
    framework = Framework(**payload.model_dump())
    db.add(framework)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise _conflict(f"a framework with key {payload.key!r} already exists") from exc
    audit.record(
        db,
        action="framework.create",
        actor=user,
        actor_ip=client_ip(request),
        object_type="framework",
        object_id=framework.id,
        after={"key": framework.key, "name": framework.name},
    )
    db.commit()
    db.refresh(framework)
    return framework


@router.get("/frameworks/{framework_id}", response_model=FrameworkOut)
def get_framework(
    framework_id: int, db: OrmSession = Depends(get_db), _: User = Depends(require_user)
) -> Framework:
    framework = db.get(Framework, framework_id)
    if framework is None:
        raise _not_found("framework", framework_id)
    return framework


@router.patch("/frameworks/{framework_id}", response_model=FrameworkOut)
def update_framework(
    framework_id: int,
    payload: FrameworkUpdate,
    request: Request,
    user: User = Depends(require_writer),
    db: OrmSession = Depends(get_db),
) -> Framework:
    framework = db.get(Framework, framework_id)
    if framework is None:
        raise _not_found("framework", framework_id)
    changes = payload.model_dump(exclude_unset=True)
    before, after = audit.diff(framework, changes, list(changes))
    for field, value in changes.items():
        setattr(framework, field, value)
    audit.record(
        db,
        action="framework.update",
        actor=user,
        actor_ip=client_ip(request),
        object_type="framework",
        object_id=framework.id,
        before=before,
        after=after,
    )
    db.commit()
    db.refresh(framework)
    return framework


@router.delete("/frameworks/{framework_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_framework(
    framework_id: int,
    request: Request,
    user: User = Depends(require_admin),
    db: OrmSession = Depends(get_db),
) -> None:
    framework = db.get(Framework, framework_id)
    if framework is None:
        raise _not_found("framework", framework_id)
    audit.record(
        db,
        action="framework.delete",
        actor=user,
        actor_ip=client_ip(request),
        object_type="framework",
        object_id=framework.id,
        before={"key": framework.key, "name": framework.name},
    )
    db.delete(framework)
    db.commit()


# ------------------------------------------------------------------ controls ---


@router.get("/controls", response_model=list[ControlOut])
def list_controls(
    category: str | None = None,
    q: str | None = Query(default=None, max_length=100),
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: OrmSession = Depends(get_db),
    _: User = Depends(require_user),
) -> list[Control]:
    statement = select(Control).options(selectinload(Control.refs)).order_by(Control.key)
    if category:
        statement = statement.where(Control.category == category)
    if q:
        pattern = f"%{q}%"
        statement = statement.where(
            Control.key.ilike(pattern) | Control.title.ilike(pattern)
        )
    return list(db.execute(statement.limit(limit).offset(offset)).scalars())


@router.post("/controls", response_model=ControlOut, status_code=status.HTTP_201_CREATED)
def create_control(
    payload: ControlCreate,
    request: Request,
    user: User = Depends(require_writer),
    db: OrmSession = Depends(get_db),
) -> Control:
    control = Control(**payload.model_dump())
    db.add(control)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise _conflict(f"a control with key {payload.key!r} already exists") from exc
    audit.record(
        db,
        action="control.create",
        actor=user,
        actor_ip=client_ip(request),
        object_type="control",
        object_id=control.id,
        after={"key": control.key, "title": control.title},
    )
    db.commit()
    db.refresh(control)
    return control


@router.get("/controls/{control_id}", response_model=ControlOut)
def get_control(
    control_id: int, db: OrmSession = Depends(get_db), _: User = Depends(require_user)
) -> Control:
    control = db.get(Control, control_id)
    if control is None:
        raise _not_found("control", control_id)
    return control


@router.patch("/controls/{control_id}", response_model=ControlOut)
def update_control(
    control_id: int,
    payload: ControlUpdate,
    request: Request,
    user: User = Depends(require_writer),
    db: OrmSession = Depends(get_db),
) -> Control:
    control = db.get(Control, control_id)
    if control is None:
        raise _not_found("control", control_id)
    changes = payload.model_dump(exclude_unset=True)
    before, after = audit.diff(control, changes, list(changes))
    for field, value in changes.items():
        setattr(control, field, value)
    audit.record(
        db,
        action="control.update",
        actor=user,
        actor_ip=client_ip(request),
        object_type="control",
        object_id=control.id,
        before=before,
        after=after,
    )
    db.commit()
    db.refresh(control)
    return control


@router.delete("/controls/{control_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_control(
    control_id: int,
    request: Request,
    user: User = Depends(require_admin),
    db: OrmSession = Depends(get_db),
) -> None:
    control = db.get(Control, control_id)
    if control is None:
        raise _not_found("control", control_id)

    in_use = db.execute(
        select(func.count())
        .select_from(ValidationTest)
        .where(ValidationTest.control_id == control_id)
    ).scalar()
    if in_use:
        raise _conflict(
            f"control {control.key} is used by {in_use} validation test(s); "
            "delete or retarget those first"
        )

    dependent = db.execute(
        select(func.count()).select_from(FrameworkRef).where(FrameworkRef.control_id == control_id)
    ).scalar()
    if dependent:
        raise _conflict(
            f"control {control.key} is referenced by {dependent} framework mapping(s); "
            "remove those first"
        )

    audit.record(
        db,
        action="control.delete",
        actor=user,
        actor_ip=client_ip(request),
        object_type="control",
        object_id=control.id,
        before={"key": control.key, "title": control.title},
    )
    db.delete(control)
    db.commit()


@router.get("/controls/{control_id}/refs", response_model=list[FrameworkRefOut])
def list_control_refs(
    control_id: int, db: OrmSession = Depends(get_db), _: User = Depends(require_user)
) -> list[FrameworkRef]:
    if db.get(Control, control_id) is None:
        raise _not_found("control", control_id)
    return list(
        db.execute(select(FrameworkRef).where(FrameworkRef.control_id == control_id)).scalars()
    )


@router.post(
    "/controls/{control_id}/refs",
    response_model=FrameworkRefOut,
    status_code=status.HTTP_201_CREATED,
)
def add_control_ref(
    control_id: int,
    payload: FrameworkRefCreate,
    request: Request,
    user: User = Depends(require_writer),
    db: OrmSession = Depends(get_db),
) -> FrameworkRef:
    if db.get(Control, control_id) is None:
        raise _not_found("control", control_id)
    if db.get(Framework, payload.framework_id) is None:
        raise _not_found("framework", payload.framework_id)
    ref = FrameworkRef(control_id=control_id, **payload.model_dump())
    db.add(ref)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise _conflict(
            f"{payload.ref_code!r} already maps into framework {payload.framework_id}"
        ) from exc
    audit.record(
        db,
        action="control.map_framework",
        actor=user,
        actor_ip=client_ip(request),
        object_type="control",
        object_id=control_id,
        after={"framework_id": payload.framework_id, "ref_code": payload.ref_code},
    )
    db.commit()
    db.refresh(ref)
    return ref


@router.delete(
    "/controls/{control_id}/refs/{ref_id}", status_code=status.HTTP_204_NO_CONTENT
)
def delete_control_ref(
    control_id: int,
    ref_id: int,
    request: Request,
    user: User = Depends(require_writer),
    db: OrmSession = Depends(get_db),
) -> None:
    ref = db.get(FrameworkRef, ref_id)
    if ref is None or ref.control_id != control_id:
        raise _not_found("framework mapping", ref_id)
    audit.record(
        db,
        action="control.unmap_framework",
        actor=user,
        actor_ip=client_ip(request),
        object_type="control",
        object_id=control_id,
        before={"framework_id": ref.framework_id, "ref_code": ref.ref_code},
    )
    db.delete(ref)
    db.commit()


# ------------------------------------------------------------------- targets ---


@router.get("/targets", response_model=list[TargetOut])
def list_targets(
    enabled: bool | None = None,
    tag: str | None = Query(default=None, max_length=48),
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: OrmSession = Depends(get_db),
    _: User = Depends(require_user),
) -> list[Target]:
    statement = select(Target).order_by(Target.name)
    if enabled is not None:
        statement = statement.where(Target.enabled.is_(enabled))
    if tag:
        statement = statement.where(Target.tags.any(tag))
    return list(db.execute(statement.limit(limit).offset(offset)).scalars())


@router.post("/targets", response_model=TargetOut, status_code=status.HTTP_201_CREATED)
def create_target(
    payload: TargetCreate,
    request: Request,
    user: User = Depends(require_writer),
    db: OrmSession = Depends(get_db),
) -> Target:
    target = Target(**payload.model_dump())
    db.add(target)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise _conflict(
            "a target with the same host, port, protocol and path already exists"
        ) from exc
    audit.record(
        db,
        action="target.create",
        actor=user,
        actor_ip=client_ip(request),
        object_type="target",
        object_id=target.id,
        after={"name": target.name, "host": target.host, "port": target.port},
    )
    db.commit()
    db.refresh(target)
    return target


@router.get("/targets/{target_id}", response_model=TargetOut)
def get_target(
    target_id: int, db: OrmSession = Depends(get_db), _: User = Depends(require_user)
) -> Target:
    target = db.get(Target, target_id)
    if target is None:
        raise _not_found("target", target_id)
    return target


@router.patch("/targets/{target_id}", response_model=TargetOut)
def update_target(
    target_id: int,
    payload: TargetUpdate,
    request: Request,
    user: User = Depends(require_writer),
    db: OrmSession = Depends(get_db),
) -> Target:
    target = db.get(Target, target_id)
    if target is None:
        raise _not_found("target", target_id)
    changes = payload.model_dump(exclude_unset=True)
    before, after = audit.diff(target, changes, list(changes))
    for field, value in changes.items():
        setattr(target, field, value)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise _conflict(
            "another target already uses that host, port, protocol and path"
        ) from exc
    audit.record(
        db,
        action="target.update",
        actor=user,
        actor_ip=client_ip(request),
        object_type="target",
        object_id=target.id,
        before=before,
        after=after,
    )
    db.commit()
    db.refresh(target)
    return target


@router.delete("/targets/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_target(
    target_id: int,
    request: Request,
    user: User = Depends(require_admin),
    db: OrmSession = Depends(get_db),
) -> None:
    target = db.get(Target, target_id)
    if target is None:
        raise _not_found("target", target_id)
    recorded = db.execute(
        select(func.count())
        .select_from(ValidationRun)
        .where(ValidationRun.target_id == target_id)
    ).scalar()
    found = db.execute(
        select(func.count()).select_from(Finding).where(Finding.target_id == target_id)
    ).scalar()
    if recorded or found:
        raise _conflict(
            f"target {target.name!r} has {recorded} recorded run(s) and {found} finding(s); "
            "disable it instead so its history stays readable"
        )

    audit.record(
        db,
        action="target.delete",
        actor=user,
        actor_ip=client_ip(request),
        object_type="target",
        object_id=target.id,
        before={"name": target.name, "host": target.host, "port": target.port},
    )
    db.delete(target)
    db.commit()


# -------------------------------------------------------------------- scopes ---


def _load_scope(db: OrmSession, scope_id: int) -> Scope:
    scope = db.execute(
        select(Scope).options(selectinload(Scope.entries)).where(Scope.id == scope_id)
    ).scalar_one_or_none()
    if scope is None:
        raise _not_found("scope", scope_id)
    return scope


def _cancel_runs_for_scopes(
    db: OrmSession, scope_ids: Iterable[int], *, reason: str
) -> list[int]:
    """Stop in-flight runs against targets that these scopes authorize.

    Every change here can *narrow* what is authorized - a scope flagged
    inactive, an entry removed, an expiry brought forward, a target detached
    from its scope. A run that was queued or already scanning under the wider
    authorization must not be allowed to finish under the narrower one, so it
    is cancelled at the same moment the change is committed.
    """
    target_ids = set(
        db.execute(
            select(TargetScope.target_id).where(TargetScope.scope_id.in_(list(scope_ids)))
        ).scalars()
    )
    stopped: list[int] = []
    for target_id in target_ids:
        stopped.extend(jobs.cancel_active_for_target(db, target_id, reason=reason))
    return stopped


@router.get("/scopes", response_model=list[ScopeOut])
def list_scopes(
    active: bool | None = None,
    db: OrmSession = Depends(get_db),
    _: User = Depends(require_user),
) -> list[Scope]:
    statement = select(Scope).options(selectinload(Scope.entries)).order_by(Scope.name)
    if active is not None:
        statement = statement.where(Scope.active.is_(active))
    return list(db.execute(statement).scalars())


@router.post("/scopes", response_model=ScopeOut, status_code=status.HTTP_201_CREATED)
def create_scope(
    payload: ScopeCreate,
    request: Request,
    user: User = Depends(require_admin),
    db: OrmSession = Depends(get_db),
) -> Scope:
    """Creating an authorization boundary is an administrator action.

    Every entry is validated before anything is written, so a scope is never
    half-created with a subset of its entries.
    """
    data = payload.model_dump(exclude={"entries"})
    scope = Scope(**data, approved_by_user_id=user.id)
    db.add(scope)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise _conflict(f"a scope named {payload.name!r} already exists") from exc

    for entry_payload in payload.entries:
        _apply_entry(scope, entry_payload)

    audit.record(
        db,
        action="scope.create",
        actor=user,
        actor_ip=client_ip(request),
        object_type="scope",
        object_id=scope.id,
        after={
            "name": scope.name,
            "allow_broad": scope.allow_broad,
            "is_lab": scope.is_lab,
            "authorization_ref": scope.authorization_ref,
            "entries": [
                f"{e.kind.value}:{e.value}:{e.ports}/{e.protocol}" for e in scope.entries
            ],
        },
    )
    db.commit()
    return _load_scope(db, scope.id)


@router.get("/scopes/{scope_id}", response_model=ScopeOut)
def get_scope(
    scope_id: int, db: OrmSession = Depends(get_db), _: User = Depends(require_user)
) -> Scope:
    return _load_scope(db, scope_id)


@router.patch("/scopes/{scope_id}", response_model=ScopeOut)
def update_scope(
    scope_id: int,
    payload: ScopeUpdate,
    request: Request,
    user: User = Depends(require_admin),
    db: OrmSession = Depends(get_db),
) -> Scope:
    """Changing a scope's flags re-validates its entries.

    Loosening ``is_lab`` or ``allow_broad`` can invalidate entries that were
    previously acceptable (or make new ones acceptable), so the whole entry set
    is re-checked against the new flags rather than trusted.
    """
    scope = _load_scope(db, scope_id)
    changes = payload.model_dump(exclude_unset=True)
    before, after = audit.diff(scope, changes, list(changes))
    for field, value in changes.items():
        setattr(scope, field, value)

    policy = _scope_policy(scope)
    refusals: list[str] = []
    for entry in scope.entries:
        try:
            normalized = validate_entry(
                entry.kind.value, entry.value, entry.ports, entry.protocol, policy
            )
        except ScopePolicyError as exc:
            refusals.append(f"{entry.kind.value}:{entry.value} - {exc}")
        else:
            entry.value = normalized.value
            entry.ports = normalized.ports
            entry.protocol = normalized.protocol
    if refusals:
        db.rollback()
        raise _policy_refusal(ValueError("; ".join(refusals)))
    audit.record(
        db,
        action="scope.update",
        actor=user,
        actor_ip=client_ip(request),
        object_type="scope",
        object_id=scope.id,
        before=before,
        after=after,
    )
    _cancel_runs_for_scopes(
        db, [scope.id], reason=f"scope {scope.name!r} was changed while the run was active"
    )
    db.commit()
    return _load_scope(db, scope_id)


@router.delete("/scopes/{scope_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scope(
    scope_id: int,
    request: Request,
    user: User = Depends(require_admin),
    db: OrmSession = Depends(get_db),
) -> None:
    scope = _load_scope(db, scope_id)
    # Collected before the delete: the cascade takes target_scopes with it.
    _cancel_runs_for_scopes(
        db, [scope.id], reason=f"scope {scope.name!r} was deleted while the run was active"
    )
    audit.record(
        db,
        action="scope.delete",
        actor=user,
        actor_ip=client_ip(request),
        object_type="scope",
        object_id=scope.id,
        before={"name": scope.name, "entries": len(scope.entries)},
    )
    db.delete(scope)
    db.commit()


@router.post(
    "/scopes/{scope_id}/entries",
    response_model=ScopeEntryOut,
    status_code=status.HTTP_201_CREATED,
)
def add_scope_entry(
    scope_id: int,
    payload: ScopeEntryCreate,
    request: Request,
    user: User = Depends(require_admin),
    db: OrmSession = Depends(get_db),
) -> ScopeEntry:
    scope = _load_scope(db, scope_id)
    entry = _apply_entry(scope, payload)
    db.flush()
    audit.record(
        db,
        action="scope.entry_add",
        actor=user,
        actor_ip=client_ip(request),
        object_type="scope",
        object_id=scope.id,
        after={
            "kind": entry.kind.value,
            "value": entry.value,
            "ports": entry.ports,
            "protocol": entry.protocol,
        },
    )
    db.commit()
    db.refresh(entry)
    return entry


@router.delete(
    "/scopes/{scope_id}/entries/{entry_id}", status_code=status.HTTP_204_NO_CONTENT
)
def delete_scope_entry(
    scope_id: int,
    entry_id: int,
    request: Request,
    user: User = Depends(require_admin),
    db: OrmSession = Depends(get_db),
) -> None:
    entry = db.get(ScopeEntry, entry_id)
    if entry is None or entry.scope_id != scope_id:
        raise _not_found("scope entry", entry_id)
    audit.record(
        db,
        action="scope.entry_remove",
        actor=user,
        actor_ip=client_ip(request),
        object_type="scope",
        object_id=scope_id,
        before={
            "kind": entry.kind.value,
            "value": entry.value,
            "ports": entry.ports,
        },
    )
    _cancel_runs_for_scopes(
        db,
        [scope_id],
        reason=f"a scope entry ({entry.value}) was removed while the run was active",
    )
    db.delete(entry)
    db.commit()


# ------------------------------------------------------- target <-> scope ----


@router.get("/targets/{target_id}/scopes", response_model=list[ScopeOut])
def list_target_scopes(
    target_id: int, db: OrmSession = Depends(get_db), _: User = Depends(require_user)
) -> list[Scope]:
    if db.get(Target, target_id) is None:
        raise _not_found("target", target_id)
    return list(
        db.execute(
            select(Scope)
            .options(selectinload(Scope.entries))
            .join(TargetScope, TargetScope.scope_id == Scope.id)
            .where(TargetScope.target_id == target_id)
            .order_by(Scope.name)
        ).scalars()
    )


@router.put("/targets/{target_id}/scopes/{scope_id}", status_code=status.HTTP_204_NO_CONTENT)
def link_target_scope(
    target_id: int,
    scope_id: int,
    request: Request,
    user: User = Depends(require_admin),
    db: OrmSession = Depends(get_db),
) -> None:
    """Authorize a target by attaching it to a scope."""
    target = db.get(Target, target_id)
    if target is None:
        raise _not_found("target", target_id)
    if db.get(Scope, scope_id) is None:
        raise _not_found("scope", scope_id)

    existing = db.get(TargetScope, {"target_id": target_id, "scope_id": scope_id})
    if existing is not None:
        return

    db.add(TargetScope(target_id=target_id, scope_id=scope_id, linked_by_user_id=user.id))
    audit.record(
        db,
        action="target.scope_link",
        actor=user,
        actor_ip=client_ip(request),
        object_type="target",
        object_id=target_id,
        after={"scope_id": scope_id},
    )
    db.commit()


@router.delete(
    "/targets/{target_id}/scopes/{scope_id}", status_code=status.HTTP_204_NO_CONTENT
)
def unlink_target_scope(
    target_id: int,
    scope_id: int,
    request: Request,
    user: User = Depends(require_admin),
    db: OrmSession = Depends(get_db),
) -> None:
    link = db.get(TargetScope, {"target_id": target_id, "scope_id": scope_id})
    if link is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"target {target_id} is not linked to scope {scope_id}",
        )
    audit.record(
        db,
        action="target.scope_unlink",
        actor=user,
        actor_ip=client_ip(request),
        object_type="target",
        object_id=target_id,
        before={"scope_id": scope_id},
    )
    _cancel_runs_for_scopes(
        db,
        [scope_id],
        reason=f"target {target_id} was detached from the scope authorizing it",
    )
    db.delete(link)
    db.commit()
