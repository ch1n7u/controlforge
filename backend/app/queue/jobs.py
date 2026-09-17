"""The job queue, which is Postgres and nothing else.

There is no Redis here on purpose. A run is a row, and the transition from
queued to running is a short transaction that takes the row ``FOR UPDATE SKIP
LOCKED``, marks it running with a lease, and commits. Everything else - the
worker process dying, the machine rebooting, a scope being narrowed mid-run -
falls out of that single fact:

* a worker that dies stops heartbeating, its lease expires, and the reaper
  returns the run to the queue with its attempt count already incremented, so a
  run that kills its worker cannot loop forever;
* a scope change can set ``cancel_requested`` on the affected runs, which the
  executing worker notices on its next poll;
* nothing is lost between "the operator pressed run" and "the run executed",
  because the queue *is* the database the operator just wrote to.

Leases are deliberately short (a worker renews its own while it works) so that
a laptop that suspends or a container that is killed does not leave a run
looking alive for an hour.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.config import Settings
from app.models.enums import RunStatus, TriggerKind
from app.models.testing import RunLog, ValidationRun

# When a run cannot start because its target is busy, it goes back in the queue
# shortly rather than immediately, so a worker does not spin on the same row.
BUSY_RETRY_SECONDS = 5

# After the final attempt fails, the run is left alone for this long before the
# reaper notices; the lease is what marks it, so this only sets the requeue gap.
REQUEUE_DELAY_SECONDS = 2


def now() -> datetime:
    return datetime.now(UTC)


def enqueue(
    session: Session,
    *,
    test_id: int,
    test_version_id: int,
    target_id: int,
    engine_id: str,
    timeout_seconds: int,
    trigger: TriggerKind = TriggerKind.MANUAL,
    authorized_by_user_id: int | None = None,
    authorization_ref: str | None = None,
    retest_of_finding_id: int | None = None,
    max_attempts: int = 2,
) -> ValidationRun:
    """Put one run on the queue. Committed by the caller."""
    run = ValidationRun(
        test_id=test_id,
        test_version_id=test_version_id,
        target_id=target_id,
        engine_id=engine_id,
        status=RunStatus.QUEUED,
        trigger=trigger,
        attempt=0,
        max_attempts=max_attempts,
        run_after=now(),
        authorized_by_user_id=authorized_by_user_id,
        authorization_ref=authorization_ref,
        retest_of_finding_id=retest_of_finding_id,
        timeout_seconds=timeout_seconds,
    )
    session.add(run)
    session.flush()
    log(session, run.id, "system", "info", "queued")
    return run


def log(session: Session, run_id: int, stream: str, level: str, message: str) -> None:
    session.add(RunLog(run_id=run_id, stream=stream, level=level, message=message))


def counts(session: Session) -> dict[str, int]:
    rows = session.execute(
        select(ValidationRun.status, func.count()).group_by(ValidationRun.status)
    ).all()
    return {status.value: count for status, count in rows}


def next_candidate(session: Session) -> tuple[int, int] | None:
    """The oldest run due to start, as ``(run_id, target_id)``.

    No lock is taken here: this only decides which target to try to reserve. The
    row itself is claimed later, under ``SKIP LOCKED``, so two workers reading
    the same candidate is harmless.
    """
    row = session.execute(
        select(ValidationRun.id, ValidationRun.target_id)
        .where(
            ValidationRun.status == RunStatus.QUEUED,
            ValidationRun.run_after <= func.now(),
        )
        .order_by(ValidationRun.run_after, ValidationRun.id)
        .limit(1)
    ).first()
    return (row[0], row[1]) if row else None


def claim(
    session: Session,
    run_id: int,
    *,
    worker_id: str,
    settings: Settings,
) -> ValidationRun | None:
    """Take the run, or return None if someone else got there first."""
    run = session.execute(
        select(ValidationRun)
        .where(
            ValidationRun.id == run_id,
            ValidationRun.status == RunStatus.QUEUED,
            ValidationRun.run_after <= func.now(),
        )
        .with_for_update(skip_locked=True)
    ).scalar_one_or_none()
    if run is None:
        return None

    lease = now() + timedelta(seconds=settings.lease_seconds)
    run.status = RunStatus.RUNNING
    run.started_at = run.started_at or now()
    run.attempt += 1
    run.worker_id = worker_id
    run.heartbeat_at = now()
    run.lease_until = lease
    # A previous attempt's message describes a run that is over; this attempt
    # writes its own if it fails.
    run.error_message = None
    session.flush()
    return run


def defer(session: Session, run_id: int, *, seconds: int, reason: str) -> None:
    """Put a claimed run back in the queue without spending an attempt.

    Used when the target is already busy: nothing was attempted, so the run
    should not be penalised for the wait.
    """
    session.execute(
        update(ValidationRun)
        .where(ValidationRun.id == run_id, ValidationRun.status == RunStatus.QUEUED)
        .values(run_after=func.now() + timedelta(seconds=seconds))
    )
    # The wait is recorded as a log line, not as error_message: the run is
    # still queued and will very likely succeed, so stamping it with an error
    # left a stale message on runs that had in fact completed cleanly.
    log(session, run_id, "system", "info", f"deferred: {reason}")


def heartbeat(session: Session, run_id: int, *, worker_id: str, settings: Settings) -> bool:
    """Extend the lease. False means this worker no longer owns the run."""
    result = session.execute(
        update(ValidationRun)
        .where(
            ValidationRun.id == run_id,
            ValidationRun.worker_id == worker_id,
            ValidationRun.status == RunStatus.RUNNING,
        )
        .values(
            heartbeat_at=func.now(),
            lease_until=now() + timedelta(seconds=settings.lease_seconds),
        )
    )
    return bool(result.rowcount)


def cancel_requested(session: Session, run_id: int) -> bool:
    return bool(
        session.execute(
            select(ValidationRun.cancel_requested).where(ValidationRun.id == run_id)
        ).scalar_one_or_none()
    )


def request_cancel(session: Session, run: ValidationRun, *, reason: str | None = None) -> bool:
    """Ask for a run to stop. Returns True if it will still be picked up.

    A queued run is cancelled outright - there is no worker to notice a flag. A
    running run is flagged, and its worker stops it on the next poll: the tool
    is killed by process group, and whatever it had already produced is kept.
    """
    if run.status.is_terminal:
        return False
    if run.status is RunStatus.QUEUED:
        run.status = RunStatus.CANCELLED
        run.finished_at = now()
        run.error_message = reason or "cancelled before it started"
        log(session, run.id, "system", "warning", run.error_message)
        return False
    run.cancel_requested = True
    log(session, run.id, "system", "warning", reason or "cancellation requested")
    return True


def cancel_active_for_target(session: Session, target_id: int, *, reason: str) -> list[int]:
    """Queue a cancellation for every run touching a target whose scope changed.

    A scope edit that narrows what is authorized must not leave a scan running
    under the old authorization.
    """
    runs = session.execute(
        select(ValidationRun).where(
            ValidationRun.target_id == target_id,
            ValidationRun.status.in_([RunStatus.QUEUED, RunStatus.RUNNING]),
        )
    ).scalars().all()
    stopped = []
    for run in runs:
        request_cancel(session, run, reason=reason)
        stopped.append(run.id)
    return stopped


def reap(session: Session, *, limit: int = 50) -> dict[str, list[int]]:
    """Recover runs whose lease expired.

    A run that still has attempts left goes back in the queue; one that has used
    them all is marked dead. Either way the reason is written to the run's log,
    so an operator sees a worker died rather than wondering why a run restarted.
    """
    expired = session.execute(
        select(ValidationRun)
        .where(
            ValidationRun.status == RunStatus.RUNNING,
            ValidationRun.lease_until.is_not(None),
            ValidationRun.lease_until < func.now(),
        )
        .order_by(ValidationRun.lease_until)
        .limit(limit)
        .with_for_update(skip_locked=True)
    ).scalars().all()

    requeued: list[int] = []
    dead: list[int] = []
    for run in expired:
        exhausted = run.attempt >= run.max_attempts
        run.worker_id = None
        run.lease_until = None
        run.heartbeat_at = None
        if exhausted:
            run.status = RunStatus.DEAD
            run.finished_at = now()
            run.error_message = (
                f"no worker completed this run in {run.attempt} attempt(s); "
                "its lease expired each time"
            )
            log(session, run.id, "system", "error", run.error_message)
            dead.append(run.id)
        else:
            run.status = RunStatus.QUEUED
            run.run_after = func.now() + timedelta(seconds=REQUEUE_DELAY_SECONDS)
            run.error_message = "the worker holding this run stopped responding; requeued"
            log(session, run.id, "system", "warning", run.error_message)
            requeued.append(run.id)

    return {"requeued": requeued, "dead": dead}


def active_run_count(session: Session) -> int:
    return int(
        session.execute(
            select(func.count()).where(ValidationRun.status == RunStatus.RUNNING)
        ).scalar_one()
    )


def busy_targets(session: Session) -> set[int]:
    """Targets with a run in flight, for the UI and for enqueue-time advice."""
    return set(
        session.execute(
            select(ValidationRun.target_id).where(ValidationRun.status == RunStatus.RUNNING)
        ).scalars()
    )


def kill_switch_engaged(session: Session) -> bool:
    """Whether a stop has been requested for all execution.

    Two sources, both honoured: the environment variable (set by an operator
    with shell access, which is the fastest way to stop a runaway) and the
    stored setting (set from the UI). Either one stops new work; neither can
    un-stop the other.
    """
    from app.config import get_settings
    from app.models.registry import Setting

    if get_settings().kill_switch:
        return True
    value = session.execute(
        select(Setting.value).where(Setting.key == "kill_switch")
    ).scalar_one_or_none()
    if value is None:
        return False
    if isinstance(value, dict):
        value = value.get("value")
    return str(value).strip().lower() in {"1", "true", "yes", "on"}
