"""Validation tests and their immutable versions.

A test is a name and a target selector. What it *executes* lives in a version,
and versions are never edited: runs, facts and findings all point at a version,
so editing one in place would silently rewrite the meaning of results that were
already recorded against it. Publishing a new version is the only way to change
what a test does.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as OrmSession, selectinload

from app.api.deps import client_ip, require_admin, require_user, require_writer
from app.core import audit
from app.db import get_db
from app.engines.catalogue import ENGINE_SPECS
from app.models.auth import User
from app.models.registry import Control
from app.models.testing import ValidationRun, ValidationTest, ValidationTestVersion
from app.schemas.testing import (
    EngineOut,
    TestVersionCreate,
    TestVersionOut,
    ValidationTestCreate,
    ValidationTestDetail,
    ValidationTestOut,
    ValidationTestUpdate,
)

router = APIRouter(prefix="/api", tags=["tests"])


def _not_found(what: str, ident: int) -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"{what} {ident} not found")


def _load_test(db: OrmSession, test_id: int) -> ValidationTest:
    test = db.execute(
        select(ValidationTest)
        .options(selectinload(ValidationTest.versions))
        .where(ValidationTest.id == test_id)
    ).scalar_one_or_none()
    if test is None:
        raise _not_found("test", test_id)
    return test


def _require_control(db: OrmSession, control_id: int) -> Control:
    control = db.get(Control, control_id)
    if control is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"control {control_id} does not exist",
        )
    return control


def _publish_version(
    db: OrmSession,
    test: ValidationTest,
    payload: TestVersionCreate,
    control: Control,
    user: User,
) -> ValidationTestVersion:
    """Append the next version and point the test at it.

    Attached through the relationship rather than by foreign key: the session
    runs with autoflush off and ``expire_on_commit=False``, so a collection that
    has already been read would otherwise keep serving a stale list.
    """
    next_version = max((v.version for v in test.versions), default=0) + 1
    version = ValidationTestVersion(
        version=next_version,
        engine_id=payload.engine_id,
        engine_params=payload.engine_params,
        assertion=payload.assertion,
        control_id=control.id,
        severity=payload.severity or control.default_severity,
        note=payload.note,
        created_by_user_id=user.id,
    )
    test.versions.append(version)
    test.current_version = next_version
    return version


# ------------------------------------------------------------------- engines --


@router.get("/engines", response_model=list[EngineOut])
def list_engines(_: User = Depends(require_user)) -> list[dict]:
    """The engine catalogue, including each engine's parameter schema."""
    return [spec.describe() for spec in ENGINE_SPECS]


# --------------------------------------------------------------------- tests --


@router.get("/tests", response_model=list[ValidationTestOut])
def list_tests(
    control_id: int | None = None,
    tag: str | None = None,
    enabled: bool | None = None,
    q: str | None = Query(default=None, max_length=120),
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: OrmSession = Depends(get_db),
    _: User = Depends(require_user),
) -> list[ValidationTest]:
    statement = select(ValidationTest).order_by(ValidationTest.key)
    if control_id is not None:
        statement = statement.where(ValidationTest.control_id == control_id)
    if enabled is not None:
        statement = statement.where(ValidationTest.enabled.is_(enabled))
    if tag:
        statement = statement.where(ValidationTest.tags.any(tag))
    if q:
        pattern = f"%{q.lower()}%"
        statement = statement.where(
            func.lower(ValidationTest.key).like(pattern)
            | func.lower(ValidationTest.name).like(pattern)
        )
    return list(db.execute(statement.limit(limit).offset(offset)).scalars())


@router.post("/tests", response_model=ValidationTestDetail, status_code=status.HTTP_201_CREATED)
def create_test(
    payload: ValidationTestCreate,
    request: Request,
    user: User = Depends(require_writer),
    db: OrmSession = Depends(get_db),
) -> ValidationTest:
    """Create a test together with its first version.

    Both are written in one transaction: a test with no version is not
    runnable, so it must never exist even briefly.
    """
    control = _require_control(db, payload.control_id)

    data = payload.model_dump(exclude={"version", "target_selector"})
    test = ValidationTest(
        **data,
        target_selector=payload.target_selector.model_dump(mode="json"),
    )
    db.add(test)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"a test with key {payload.key!r} already exists",
        ) from exc

    version = _publish_version(db, test, payload.version, control, user)

    audit.record(
        db,
        action="test.create",
        actor=user,
        actor_ip=client_ip(request),
        object_type="test",
        object_id=test.id,
        after={
            "key": test.key,
            "name": test.name,
            "control_id": control.id,
            "version": version.version,
            "engine_id": version.engine_id,
            "severity": version.severity.value,
        },
    )
    db.commit()
    return _load_test(db, test.id)


@router.get("/tests/{test_id}", response_model=ValidationTestDetail)
def get_test(
    test_id: int, db: OrmSession = Depends(get_db), _: User = Depends(require_user)
) -> ValidationTest:
    return _load_test(db, test_id)


@router.patch("/tests/{test_id}", response_model=ValidationTestDetail)
def update_test(
    test_id: int,
    payload: ValidationTestUpdate,
    request: Request,
    user: User = Depends(require_writer),
    db: OrmSession = Depends(get_db),
) -> ValidationTest:
    test = _load_test(db, test_id)
    changes = payload.model_dump(exclude_unset=True)
    if "target_selector" in changes:
        changes["target_selector"] = payload.target_selector.model_dump(mode="json")

    before, after = audit.diff(test, changes, list(changes))
    for field, value in changes.items():
        setattr(test, field, value)

    audit.record(
        db,
        action="test.update",
        actor=user,
        actor_ip=client_ip(request),
        object_type="test",
        object_id=test.id,
        before=before,
        after=after,
    )
    db.commit()
    return _load_test(db, test_id)


@router.delete("/tests/{test_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_test(
    test_id: int,
    request: Request,
    user: User = Depends(require_writer),
    db: OrmSession = Depends(get_db),
) -> None:
    test = _load_test(db, test_id)
    runs = db.execute(
        select(func.count()).select_from(ValidationRun).where(ValidationRun.test_id == test.id)
    ).scalar_one()
    if runs:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"test {test.key!r} has {runs} run(s) recorded against it; "
                "disable it instead of deleting it"
            ),
        )

    audit.record(
        db,
        action="test.delete",
        actor=user,
        actor_ip=client_ip(request),
        object_type="test",
        object_id=test.id,
        before={"key": test.key, "name": test.name, "versions": len(test.versions)},
    )
    db.delete(test)
    db.commit()


# ------------------------------------------------------------------ versions --


@router.get("/tests/{test_id}/versions", response_model=list[TestVersionOut])
def list_versions(
    test_id: int, db: OrmSession = Depends(get_db), _: User = Depends(require_user)
) -> list[ValidationTestVersion]:
    test = _load_test(db, test_id)
    return sorted(test.versions, key=lambda v: v.version)


@router.get("/tests/{test_id}/versions/{version}", response_model=TestVersionOut)
def get_version(
    test_id: int,
    version: int,
    db: OrmSession = Depends(get_db),
    _: User = Depends(require_user),
) -> ValidationTestVersion:
    row = db.execute(
        select(ValidationTestVersion).where(
            ValidationTestVersion.test_id == test_id,
            ValidationTestVersion.version == version,
        )
    ).scalar_one_or_none()
    if row is None:
        raise _not_found("test version", version)
    return row


@router.post(
    "/tests/{test_id}/versions",
    response_model=TestVersionOut,
    status_code=status.HTTP_201_CREATED,
)
def create_version(
    test_id: int,
    payload: TestVersionCreate,
    request: Request,
    user: User = Depends(require_writer),
    db: OrmSession = Depends(get_db),
) -> ValidationTestVersion:
    """Publish a new version. Older versions stay readable and stay referenced."""
    test = _load_test(db, test_id)
    control = _require_control(db, test.control_id)
    version = _publish_version(db, test, payload, control, user)
    db.flush()

    audit.record(
        db,
        action="test.version_create",
        actor=user,
        actor_ip=client_ip(request),
        object_type="test",
        object_id=test.id,
        after={
            "version": version.version,
            "engine_id": version.engine_id,
            "severity": version.severity.value,
        },
    )
    db.commit()
    db.refresh(version)
    return version
