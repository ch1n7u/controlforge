"""Runs: queueing validation work, following it, and reading what it produced.

Queueing and authorization are deliberately separate. This router records who
asked for a run and which targets it is aimed at; the worker re-checks the
scope when it picks the run up. A run whose target has left scope between
queueing and execution is refused there, with the reason in the run's own log,
so narrowing an authorization cannot be bypassed by a run that was already
queued.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse
from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session as OrmSession

from app.api.deps import client_ip, require_user, require_writer
from app.config import get_settings
from app.core import audit, sessions
from app.db import SessionLocal, get_db
from app.engines.catalogue import get_engine
from app.models.auth import User
from app.models.enums import AssertionStatus, RunStatus, TriggerKind
from app.models.facts import AssertionResult, Fact
from app.models.findings import Finding
from app.models.registry import Target
from app.models.testing import (
    Evidence,
    RunLog,
    ValidationRun,
    ValidationTest,
    ValidationTestVersion,
)
from app.queue import jobs
from app.schemas.runs import (
    AssertionResultOut,
    FactOut,
    LogLineOut,
    RunDetail,
    RunEvidenceOut,
    RunFactSummary,
    RunPage,
    RunStartRequest,
    RunStartResponse,
    RunSummary,
)

router = APIRouter(prefix="/api", tags=["runs"])

# Worst-first: a run that failed anything is reported as failed, because the
# one failure is what an operator has to act on.
ASSERTION_WORST_FIRST = (
    AssertionStatus.FAIL,
    AssertionStatus.INCONCLUSIVE,
    AssertionStatus.PASS,
    AssertionStatus.NOT_APPLICABLE,
)

STREAM_POLL_SECONDS = 1.0
STREAM_KEEPALIVE_SECONDS = 15.0
STREAM_BATCH_LIMIT = 1000


def _not_found(what: str, ident: int) -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"{what} {ident} not found")


def _conflict(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_409_CONFLICT, detail=detail)


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)


def _run_select() -> Select:
    return (
        select(
            ValidationRun,
            ValidationTest.key,
            ValidationTest.name,
            Target.name,
            Target.host,
            Target.port,
            User.username,
        )
        .join(ValidationTest, ValidationTest.id == ValidationRun.test_id)
        .join(Target, Target.id == ValidationRun.target_id)
        # Outer: a run keeps its place in the queue even if the account that
        # authorized it is later deleted (the FK is ON DELETE SET NULL).
        .outerjoin(User, User.id == ValidationRun.authorized_by_user_id)
    )


def _worst_assertion(statuses: list[AssertionStatus]) -> AssertionStatus | None:
    for candidate in ASSERTION_WORST_FIRST:
        if candidate in statuses:
            return candidate
    return None


def _has_assertion(run_id_column, assertion_status: AssertionStatus):
    return (
        select(AssertionResult.id)
        .where(AssertionResult.run_id == run_id_column)
        .where(AssertionResult.status == assertion_status)
        .exists()
    )


def _assertion_status_filter(assertion_status: AssertionStatus):
    """Match runs whose *worst* assertion status is the requested one.

    A run's reported assertion status is the worst of its results, so a run that
    passed three assertions and failed one filters as failed. The status of a run
    is the first candidate present in worst-first order: this one must be present
    and everything ranked worse than it must be absent. Candidates ranked below
    it are irrelevant - a run that both failed and passed is still a failure.
    """
    run_id_column = ValidationRun.id
    condition = None
    for candidate in ASSERTION_WORST_FIRST:
        present = _has_assertion(run_id_column, candidate)
        clause = present if candidate is assertion_status else ~present
        condition = clause if condition is None else condition & clause
        if candidate is assertion_status:
            break
    return condition


def _summaries(db: OrmSession, rows: list[Any]) -> list[RunSummary]:
    """Build the summary view for joined run rows.

    ``assertion_status`` and ``findings_count`` are derived, so they are read
    for the whole page in two grouped queries rather than one query per row.
    """
    run_ids = [row[0].id for row in rows]
    if not run_ids:
        return []

    assertion_statuses: dict[int, list[AssertionStatus]] = {}
    for run_id, result_status in db.execute(
        select(AssertionResult.run_id, AssertionResult.status).where(
            AssertionResult.run_id.in_(run_ids)
        )
    ):
        assertion_statuses.setdefault(run_id, []).append(result_status)

    finding_counts = dict(
        db.execute(
            select(Finding.last_failed_run_id, func.count())
            .where(Finding.last_failed_run_id.in_(run_ids))
            .group_by(Finding.last_failed_run_id)
        ).all()
    )

    summaries = []
    for run, test_key, test_name, target_name, target_host, target_port, actor in rows:
        duration = None
        if run.started_at is not None and run.finished_at is not None:
            duration = (run.finished_at - run.started_at).total_seconds()
        summaries.append(
            RunSummary(
                id=run.id,
                test_id=run.test_id,
                test_key=test_key,
                test_name=test_name,
                target_id=run.target_id,
                target_name=target_name,
                target_host=target_host,
                target_port=target_port,
                engine_id=run.engine_id,
                status=run.status,
                trigger=run.trigger,
                authorized_by_username=actor,
                attempt=run.attempt,
                queued_at=run.queued_at,
                started_at=run.started_at,
                finished_at=run.finished_at,
                duration_seconds=duration,
                exit_code=run.exit_code,
                assertion_status=_worst_assertion(assertion_statuses.get(run.id, [])),
                error_message=run.error_message,
                findings_count=finding_counts.get(run.id, 0),
            )
        )
    return summaries


# --------------------------------------------------------------------- crud --


@router.get("/runs", response_model=RunPage)
def list_runs(
    status: RunStatus | None = None,
    test_id: int | None = None,
    target_id: int | None = None,
    engine_id: str | None = Query(default=None, max_length=64),
    assertion_status: AssertionStatus | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: OrmSession = Depends(get_db),
    _: User = Depends(require_user),
) -> RunPage:
    conditions = []
    if status is not None:
        conditions.append(ValidationRun.status == status)
    if test_id is not None:
        conditions.append(ValidationRun.test_id == test_id)
    if target_id is not None:
        conditions.append(ValidationRun.target_id == target_id)
    if engine_id is not None:
        conditions.append(ValidationRun.engine_id == engine_id)
    if assertion_status is not None:
        conditions.append(_assertion_status_filter(assertion_status))

    total = db.execute(
        select(func.count()).select_from(ValidationRun).where(*conditions)
    ).scalar_one()
    rows = db.execute(
        _run_select()
        .where(*conditions)
        .order_by(ValidationRun.queued_at.desc(), ValidationRun.id.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return RunPage(items=_summaries(db, rows), total=total)


@router.get("/runs/{run_id}", response_model=RunDetail)
def get_run(
    run_id: int, db: OrmSession = Depends(get_db), _: User = Depends(require_user)
) -> RunDetail:
    rows = db.execute(_run_select().where(ValidationRun.id == run_id)).all()
    if not rows:
        raise _not_found("run", run_id)
    run = rows[0][0]
    summary = _summaries(db, rows)[0]

    facts_summary = [
        RunFactSummary(fact_type=fact_type, count=count)
        for fact_type, count in db.execute(
            select(Fact.fact_type, func.count())
            .where(Fact.run_id == run_id)
            .group_by(Fact.fact_type)
            .order_by(Fact.fact_type)
        )
    ]
    assertion_results = db.execute(
        select(AssertionResult)
        .where(AssertionResult.run_id == run_id)
        .order_by(AssertionResult.assertion_index)
    ).scalars()
    evidence = db.execute(
        select(Evidence).where(Evidence.run_id == run_id).order_by(Evidence.id)
    ).scalars()

    return RunDetail(
        **summary.model_dump(),
        argv=run.argv,
        tool_versions=run.tool_versions,
        resolved_ips=run.resolved_ips,
        scope_snapshot=run.scope_snapshot,
        timeout_seconds=run.timeout_seconds,
        observed_summary=run.observed_summary,
        cancel_requested=run.cancel_requested,
        retest_of_finding_id=run.retest_of_finding_id,
        facts_summary=facts_summary,
        assertion_results=[AssertionResultOut.model_validate(row) for row in assertion_results],
        evidence=[RunEvidenceOut.model_validate(row) for row in evidence],
    )


@router.post("/runs", response_model=RunStartResponse, status_code=status.HTTP_201_CREATED)
def start_runs(
    payload: RunStartRequest,
    request: Request,
    user: User = Depends(require_writer),
    db: OrmSession = Depends(get_db),
) -> RunStartResponse:
    test = db.get(ValidationTest, payload.test_id)
    if test is None:
        raise _not_found("test", payload.test_id)
    if not test.enabled:
        raise _conflict(f"test {test.key!r} is disabled; enable it before starting a run")

    version = db.execute(
        select(ValidationTestVersion).where(
            ValidationTestVersion.test_id == test.id,
            ValidationTestVersion.version == test.current_version,
        )
    ).scalar_one_or_none()
    if version is None:
        raise _conflict(f"test {test.key!r} has no version {test.current_version} to run")

    spec = get_engine(version.engine_id)
    if spec is None:
        raise _conflict(f"engine {version.engine_id!r} is not available")

    targets: list[Target] = []
    for target_id in payload.target_ids:
        target = db.get(Target, target_id)
        if target is None:
            raise _not_found("target", target_id)
        if not target.enabled:
            raise _conflict(f"target {target.name!r} (id {target.id}) is disabled")
        targets.append(target)

    runs = [
        jobs.enqueue(
            db,
            test_id=test.id,
            test_version_id=version.id,
            target_id=target.id,
            engine_id=version.engine_id,
            timeout_seconds=spec.default_timeout,
            trigger=TriggerKind.MANUAL,
            authorized_by_user_id=user.id,
        )
        for target in targets
    ]

    audit.record(
        db,
        action="run.start",
        actor=user,
        actor_ip=client_ip(request),
        object_type="test",
        object_id=test.id,
        after={
            "test_key": test.key,
            "test_name": test.name,
            "version": version.version,
            "engine_id": version.engine_id,
            "targets": [
                {"id": target.id, "name": target.name, "host": target.host, "port": target.port}
                for target in targets
            ],
            "run_ids": [run.id for run in runs],
        },
    )
    db.commit()

    rows = db.execute(
        _run_select().where(ValidationRun.id.in_([run.id for run in runs])).order_by(ValidationRun.id)
    ).all()
    return RunStartResponse(runs=_summaries(db, rows))


@router.post("/runs/{run_id}/cancel", response_model=RunSummary)
def cancel_run(
    run_id: int,
    request: Request,
    user: User = Depends(require_writer),
    db: OrmSession = Depends(get_db),
) -> RunSummary:
    run = db.get(ValidationRun, run_id)
    if run is None:
        raise _not_found("run", run_id)
    if run.status.is_terminal:
        raise _conflict(f"run {run_id} is already {run.status.value}")

    jobs.request_cancel(db, run, reason=f"cancellation requested by {user.username}")
    audit.record(
        db,
        action="run.cancel",
        actor=user,
        actor_ip=client_ip(request),
        object_type="run",
        object_id=run.id,
        after={"status": run.status.value, "cancel_requested": run.cancel_requested},
    )
    db.commit()

    rows = db.execute(_run_select().where(ValidationRun.id == run_id)).all()
    return _summaries(db, rows)[0]


# ---------------------------------------------------------------- run output --


@router.get("/runs/{run_id}/log", response_model=list[LogLineOut])
def run_log(
    run_id: int,
    after_id: int = Query(default=0, ge=0),
    limit: int = Query(default=1000, ge=1, le=5000),
    db: OrmSession = Depends(get_db),
    _: User = Depends(require_user),
) -> list[RunLog]:
    if db.get(ValidationRun, run_id) is None:
        raise _not_found("run", run_id)
    return list(
        db.execute(
            select(RunLog)
            .where(RunLog.run_id == run_id, RunLog.id > after_id)
            .order_by(RunLog.id)
            .limit(limit)
        ).scalars()
    )


@router.get("/runs/{run_id}/facts", response_model=list[FactOut])
def run_facts(
    run_id: int,
    fact_type: str | None = Query(default=None, max_length=64),
    db: OrmSession = Depends(get_db),
    _: User = Depends(require_user),
) -> list[Fact]:
    if db.get(ValidationRun, run_id) is None:
        raise _not_found("run", run_id)
    statement = select(Fact).where(Fact.run_id == run_id).order_by(Fact.id)
    if fact_type:
        statement = statement.where(Fact.fact_type == fact_type)
    return list(db.execute(statement).scalars())


# ------------------------------------------------------------------- streaming --


def _poll(run_id: int, after_id: int) -> tuple[list[dict[str, Any]], RunStatus | None, bool]:
    """New log lines, the run's status, and whether the run is over.

    Runs in a worker thread against its own short-lived session: a stream can
    live for minutes, so it must not hold a pooled connection while it waits.
    """
    with SessionLocal() as session:
        run = session.get(ValidationRun, run_id)
        if run is None:
            return [], None, True
        rows = session.execute(
            select(RunLog.id, RunLog.ts, RunLog.stream, RunLog.level, RunLog.message)
            .where(RunLog.run_id == run_id, RunLog.id > after_id)
            .order_by(RunLog.id)
            .limit(STREAM_BATCH_LIMIT)
        ).all()
        events = [
            {
                "type": "log",
                "id": row.id,
                "ts": row.ts.isoformat(),
                "stream": row.stream.value,
                "level": row.level,
                "message": row.message,
            }
            for row in rows
        ]
        return events, run.status, run.status.is_terminal


def _run_exists(run_id: int) -> bool:
    with SessionLocal() as session:
        return session.get(ValidationRun, run_id) is not None


def _stream_user_reason(token: str) -> str | None:
    """None when the subscriber is authenticated, otherwise why not."""
    with SessionLocal() as session:
        record = sessions.resolve_session(session, token)
        if record is None:
            return "session expired or invalid"
        user = session.get(User, record.user_id)
        if user is None or not user.is_active:
            return "account is not active"
        session.commit()  # resolve_session advanced the session's last_seen_at
        return None


async def _authenticate_stream(request: Request) -> None:
    """Authenticate an SSE subscriber without pinning a pooled connection.

    ``Depends(require_user)`` cannot be used here: a dependency's exit - and so
    its session close - runs after the response finishes, which for a stream is
    minutes later. The check below opens its own short-lived session instead.
    """
    token = request.cookies.get(get_settings().cookie_name)
    if not token:
        raise _unauthorized("not authenticated")
    reason = await asyncio.to_thread(_stream_user_reason, token)
    if reason is not None:
        raise _unauthorized(reason)


def _sse(payload: dict[str, Any]) -> str:
    return f"data: {json.dumps(payload)}\n\n"


async def _event_stream(request: Request, run_id: int) -> AsyncIterator[str]:
    last_id = 0
    sent_status: RunStatus | None = None
    last_keepalive = time.monotonic()

    while True:
        if await request.is_disconnected():
            return

        events, run_status, terminal = await asyncio.to_thread(_poll, run_id, last_id)
        for event in events:
            yield _sse(event)
        if events:
            last_id = events[-1]["id"]
        if run_status is not None and run_status is not sent_status:
            sent_status = run_status
            yield _sse({"type": "status", "status": run_status.value})
        if terminal and not events:
            # Announced only once the log has fully drained, so a late
            # subscriber still sees everything a finished run produced.
            yield _sse({"type": "done"})
            return

        if time.monotonic() - last_keepalive >= STREAM_KEEPALIVE_SECONDS:
            last_keepalive = time.monotonic()
            yield ": keep-alive\n\n"
        await asyncio.sleep(STREAM_POLL_SECONDS)


@router.get("/runs/{run_id}/stream")
async def stream_run(run_id: int, request: Request) -> StreamingResponse:
    """Follow a run live: log lines, status changes, then ``done``."""
    await _authenticate_stream(request)
    if not await asyncio.to_thread(_run_exists, run_id):
        raise _not_found("run", run_id)
    return StreamingResponse(
        _event_stream(request, run_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            # nginx buffers proxied responses by default, which would hold the
            # whole stream back until the connection closes.
            "X-Accel-Buffering": "no",
        },
    )
