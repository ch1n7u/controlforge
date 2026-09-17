"""Findings: the work queue of control failures.

A finding is deduplicated *state* (one per test, target and assertion), not one
row per observation, so this router shows the same finding across many runs and
derives what it can - how often it was seen failing, what the last run said -
from the rows already recorded rather than from counters that would drift.

Reading is open to every authenticated user; triage and retests require the
analyst or administrator role, and a retest is refused while one is already in
flight for the same test and target.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import and_, case, func, select
from sqlalchemy.orm import Session as OrmSession, selectinload

from app.api.deps import client_ip, require_user, require_writer
from app.core import audit
from app.db import get_db
from app.engines.catalogue import get_engine
from app.models.auth import User
from app.models.enums import (
    AssertionStatus,
    FindingStatus,
    RemediationActionKind,
    RunStatus,
    Severity,
    TriggerKind,
)
from app.models.facts import AssertionResult, Fact
from app.models.findings import Finding, RemediationAction
from app.models.registry import Control, Target
from app.models.testing import (
    Evidence,
    ValidationRun,
    ValidationTest,
    ValidationTestVersion,
)
from app.queue import jobs
from app.schemas.findings import (
    EvidenceItemOut,
    FactOut,
    FindingDetail,
    FindingListOut,
    FindingRetestOut,
    FindingSummary,
    FindingSummaryStats,
    FindingTimelineEntry,
    FindingUpdate,
)

router = APIRouter(prefix="/api", tags=["findings"])

# "Open-ish" is everything the enum does not consider closed: what the work
# queue, the open count and the overdue count are about.
_OPEN_STATUSES = tuple(member for member in FindingStatus if not member.is_closed)

# Severity is stored as text, where alphabetical order is meaningless (high
# sorts above critical); ordering by the enum's own rank is the only correct one.
_SEVERITY_RANK = case(
    *((Finding.severity == member, member.rank) for member in Severity), else_=-1
)


def _not_found(finding_id: int) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND, detail=f"finding {finding_id} not found"
    )


def _conflict(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_409_CONFLICT, detail=detail)


def _load_finding(db: OrmSession, finding_id: int) -> Finding:
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise _not_found(finding_id)
    return finding


def _last_run_id(finding: Finding) -> int | None:
    """The run a reader should look at: for a resolved finding the one that
    closed it, otherwise the most recent failure."""
    if finding.status is FindingStatus.RESOLVED and finding.resolved_by_run_id is not None:
        return finding.resolved_by_run_id
    return finding.last_failed_run_id


def _matching_assertion_result(
    db: OrmSession, finding: Finding
) -> AssertionResult | None:
    """The assertion result for this finding's index in its last run."""
    run_id = _last_run_id(finding)
    if run_id is None:
        return None
    return db.execute(
        select(AssertionResult).where(
            AssertionResult.run_id == run_id,
            AssertionResult.assertion_index == finding.assertion_index,
        )
    ).scalar_one_or_none()


def _occurrence_counts(db: OrmSession, finding_ids: list[int]) -> dict[int, int]:
    """Occurrences = how many assertion_results observed this exact assertion failing.

    Defined as the count of ``assertion_results`` rows with status 'fail' matching
    this finding's (control_id, test_version_id, target_id, assertion_index).
    """
    if not finding_ids:
        return {}
    rows = db.execute(
        select(Finding.id, func.count())
        .select_from(Finding)
        .join(
            AssertionResult,
            and_(
                AssertionResult.control_id == Finding.control_id,
                AssertionResult.test_version_id == Finding.test_version_id,
                AssertionResult.target_id == Finding.target_id,
                AssertionResult.assertion_index == Finding.assertion_index,
            ),
        )
        .where(
            Finding.id.in_(finding_ids),
            AssertionResult.status == AssertionStatus.FAIL,
        )
        .group_by(Finding.id)
    ).all()
    return {finding_id: count for finding_id, count in rows}


def _last_assertion_statuses(
    db: OrmSession, findings: list[Finding]
) -> dict[int, AssertionStatus]:
    """Last assertion status per finding, batched so a list page stays one query."""
    wanted = {
        (run_id, finding.assertion_index)
        for finding in findings
        if (run_id := _last_run_id(finding)) is not None
    }
    if not wanted:
        return {}
    by_pair = {
        (run_id, index): result_status
        for run_id, index, result_status in db.execute(
            select(
                AssertionResult.run_id,
                AssertionResult.assertion_index,
                AssertionResult.status,
            ).where(AssertionResult.run_id.in_({run_id for run_id, _ in wanted}))
        ).all()
    }
    statuses: dict[int, AssertionStatus] = {}
    for finding in findings:
        run_id = _last_run_id(finding)
        if run_id is None:
            continue
        found = by_pair.get((run_id, finding.assertion_index))
        if found is not None:
            statuses[finding.id] = found
    return statuses


def _summary(
    finding: Finding,
    *,
    control_key: str,
    control_title: str,
    test_key: str,
    target_name: str,
    occurrences: int,
    last_status: AssertionStatus | None,
) -> FindingSummary:
    return FindingSummary(
        id=finding.id,
        status=finding.status,
        severity=finding.severity,
        title=finding.title,
        control_id=finding.control_id,
        control_key=control_key,
        control_title=control_title,
        test_id=finding.test_id,
        test_key=test_key,
        target_id=finding.target_id,
        target_name=target_name,
        first_seen_at=finding.first_seen_at,
        last_seen_at=finding.last_seen_at,
        last_run_id=_last_run_id(finding),
        occurrences=occurrences,
        last_status=last_status,
        assigned_to=finding.assigned_to_user_id,
        retest_of_finding_id=finding.retest_of_finding_id,
        resolved_at=finding.resolved_at,
    )


def _facts_in_order(db: OrmSession, fact_ids: list | None) -> list[Fact]:
    """Facts in the order the assertion referenced them, not by id."""
    if not fact_ids:
        return []
    by_id = {
        fact.id: fact
        for fact in db.execute(select(Fact).where(Fact.id.in_(fact_ids))).scalars()
    }
    return [by_id[fact_id] for fact_id in fact_ids if fact_id in by_id]


def _evidence_for(db: OrmSession, facts: list[Fact], run_id: int | None) -> list[Evidence]:
    # Evidence referenced by this assertion's own facts is preferred over the
    # run's whole evidence set - it is the evidence for *this* result.
    referenced: list[int] = []
    for fact in facts:
        if fact.evidence_id is not None and fact.evidence_id not in referenced:
            referenced.append(fact.evidence_id)
    if referenced:
        by_id = {
            item.id: item
            for item in db.execute(
                select(Evidence).where(Evidence.id.in_(referenced))
            ).scalars()
        }
        return [by_id[item_id] for item_id in referenced if item_id in by_id]
    if run_id is None:
        return []
    return list(
        db.execute(
            select(Evidence).where(Evidence.run_id == run_id).order_by(Evidence.id)
        ).scalars()
    )


def _timeline(db: OrmSession, finding: Finding) -> list[FindingTimelineEntry]:
    rows = db.execute(
        select(RemediationAction, User.username)
        .join(User, User.id == RemediationAction.user_id, isouter=True)
        .where(RemediationAction.finding_id == finding.id)
        .order_by(RemediationAction.id)
    ).all()
    return [
        FindingTimelineEntry(
            id=action.id,
            kind=action.kind,
            note=action.note,
            created_at=action.created_at,
            actor=username,
            from_status=action.from_status,
            to_status=action.to_status,
            # A due date is a property of the state, so only the state-change
            # entries carry the finding's deadline.
            due_at=(
                finding.due_at
                if action.kind is RemediationActionKind.STATUS_CHANGE
                else None
            ),
        )
        for action, username in rows
    ]


def _detail(db: OrmSession, finding: Finding) -> FindingDetail:
    control_key, control_title, remediation, test_key, target_name = db.execute(
        select(Control.key, Control.title, Control.remediation, ValidationTest.key, Target.name)
        .select_from(Finding)
        .join(Control, Control.id == Finding.control_id)
        .join(ValidationTest, ValidationTest.id == Finding.test_id)
        .join(Target, Target.id == Finding.target_id)
        .where(Finding.id == finding.id)
    ).one()

    result = _matching_assertion_result(db, finding)
    facts = _facts_in_order(db, result.fact_ids if result else None)
    summary = _summary(
        finding,
        control_key=control_key,
        control_title=control_title,
        test_key=test_key,
        target_name=target_name,
        occurrences=_occurrence_counts(db, [finding.id]).get(finding.id, 0),
        last_status=result.status if result else None,
    )
    return FindingDetail(
        **summary.model_dump(),
        description=finding.detail,
        expected=finding.expected,
        observed=finding.observed,
        reason=result.reason if result else None,
        facts=[FactOut.model_validate(fact) for fact in facts],
        evidence=[
            EvidenceItemOut.model_validate(item)
            for item in _evidence_for(db, facts, _last_run_id(finding))
        ],
        timeline=_timeline(db, finding),
        remediation_guidance=remediation,
    )


# ------------------------------------------------------------------- summary --


@router.get("/findings/summary", response_model=FindingSummaryStats)
def findings_summary(
    db: OrmSession = Depends(get_db), _: User = Depends(require_user)
) -> FindingSummaryStats:
    """Counts over every finding. Declared before ``/{finding_id}`` so the
    literal path wins the match."""
    by_severity = {member.value: 0 for member in Severity}
    for severity, count in db.execute(
        select(Finding.severity, func.count()).group_by(Finding.severity)
    ).all():
        by_severity[severity.value] = count

    by_status = {member.value: 0 for member in FindingStatus}
    for finding_status, count in db.execute(
        select(Finding.status, func.count()).group_by(Finding.status)
    ).all():
        by_status[finding_status.value] = count

    open_total = db.execute(
        select(func.count()).select_from(Finding).where(Finding.status.in_(_OPEN_STATUSES))
    ).scalar_one()
    overdue_total = db.execute(
        select(func.count())
        .select_from(Finding)
        .where(
            Finding.status.in_(_OPEN_STATUSES),
            Finding.due_at.is_not(None),
            Finding.due_at < func.now(),
        )
    ).scalar_one()

    return FindingSummaryStats(
        by_severity=by_severity,
        by_status=by_status,
        open_total=open_total,
        overdue_total=overdue_total,
    )


# ---------------------------------------------------------------------- list --


@router.get("/findings", response_model=FindingListOut)
def list_findings(
    status_filter: FindingStatus | None = Query(default=None, alias="status"),
    severity: Severity | None = None,
    target_id: int | None = None,
    control_id: int | None = None,
    test_id: int | None = None,
    q: str | None = Query(default=None, max_length=120),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: OrmSession = Depends(get_db),
    _: User = Depends(require_user),
) -> FindingListOut:
    conditions = []
    if status_filter is not None:
        conditions.append(Finding.status == status_filter)
    if severity is not None:
        conditions.append(Finding.severity == severity)
    if target_id is not None:
        conditions.append(Finding.target_id == target_id)
    if control_id is not None:
        conditions.append(Finding.control_id == control_id)
    if test_id is not None:
        conditions.append(Finding.test_id == test_id)
    if q:
        conditions.append(Finding.title.ilike(f"%{q}%"))

    total = db.execute(
        select(func.count()).select_from(Finding).where(*conditions)
    ).scalar_one()
    rows = db.execute(
        select(Finding, Control.key, Control.title, ValidationTest.key, Target.name)
        .join(Control, Control.id == Finding.control_id)
        .join(ValidationTest, ValidationTest.id == Finding.test_id)
        .join(Target, Target.id == Finding.target_id)
        .where(*conditions)
        .order_by(_SEVERITY_RANK.desc(), Finding.last_seen_at.desc(), Finding.id.desc())
        .limit(limit)
        .offset(offset)
    ).all()

    findings = [row[0] for row in rows]
    occurrences = _occurrence_counts(db, [finding.id for finding in findings])
    last_statuses = _last_assertion_statuses(db, findings)
    return FindingListOut(
        items=[
            _summary(
                finding,
                control_key=control_key,
                control_title=control_title,
                test_key=test_key,
                target_name=target_name,
                occurrences=occurrences.get(finding.id, 0),
                last_status=last_statuses.get(finding.id),
            )
            for finding, control_key, control_title, test_key, target_name in rows
        ],
        total=total,
    )


# -------------------------------------------------------------------- detail --


@router.get("/findings/{finding_id}", response_model=FindingDetail)
def get_finding(
    finding_id: int,
    db: OrmSession = Depends(get_db),
    _: User = Depends(require_user),
) -> FindingDetail:
    return _detail(db, _load_finding(db, finding_id))


# --------------------------------------------------------------------- triage --


@router.patch("/findings/{finding_id}", response_model=FindingDetail)
def update_finding(
    finding_id: int,
    payload: FindingUpdate,
    request: Request,
    user: User = Depends(require_writer),
    db: OrmSession = Depends(get_db),
) -> FindingDetail:
    """Apply a triage edit and record one remediation action per changed field."""
    finding = _load_finding(db, finding_id)
    changes = payload.model_dump(exclude_unset=True)
    # An explicit null means "leave alone" for everything but assigned_to, where
    # null is the documented way to unassign.
    for field in ("status", "severity", "note"):
        if changes.get(field) is None:
            changes.pop(field, None)

    assigned_to = changes.get("assigned_to")
    if assigned_to is not None and db.get(User, assigned_to) is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"user {assigned_to} does not exist",
        )

    tracked = {"status": "status", "severity": "severity", "assigned_to": "assigned_to_user_id"}
    before = {
        field: getattr(finding, column)
        for field, column in tracked.items()
        if field in changes
    }
    after = {field: changes[field] for field in before}
    if "note" in changes:
        after["note"] = changes["note"]  # a comment is appended, not a column change

    previous_status = finding.status
    now = datetime.now(UTC)

    def action(**fields) -> None:
        db.add(RemediationAction(finding_id=finding.id, user_id=user.id, **fields))

    if "status" in changes:
        new_status = changes["status"]
        finding.status = new_status
        # A close stamps resolved_at once; a closed->open move keeps it as
        # history, an open->open move must not carry a stale close time.
        if new_status.is_closed:
            if finding.resolved_at is None:
                finding.resolved_at = now
        elif not previous_status.is_closed:
            finding.resolved_at = None
        action(
            kind=RemediationActionKind.STATUS_CHANGE,
            from_status=previous_status,
            to_status=new_status,
            note=f"status changed from {previous_status.value} to {new_status.value}",
        )
    if "severity" in changes:
        previous_severity = finding.severity
        finding.severity = changes["severity"]
        # There is no severity kind; the change is a factual comment on the trail.
        action(
            kind=RemediationActionKind.COMMENT,
            note=(
                f"severity changed from {previous_severity.value} "
                f"to {changes['severity'].value}"
            ),
        )
    if "assigned_to" in changes:
        finding.assigned_to_user_id = assigned_to
        action(
            kind=RemediationActionKind.ASSIGNMENT,
            note=f"assigned to user #{assigned_to}" if assigned_to else "unassigned",
            detail={"assigned_to_user_id": assigned_to},
        )
    if "note" in changes:
        action(kind=RemediationActionKind.COMMENT, note=changes["note"])

    audit.record(
        db,
        action="finding.update",
        actor=user,
        actor_ip=client_ip(request),
        object_type="finding",
        object_id=finding.id,
        before=before,
        after=after,
    )
    db.commit()
    return _detail(db, finding)


# -------------------------------------------------------------------- retest --


def _version_for_retest(db: OrmSession, finding: Finding) -> ValidationTestVersion:
    """The test's current version when it exists, else the version the finding
    was recorded against - a retest must execute what the test says today."""
    test = db.execute(
        select(ValidationTest)
        .options(selectinload(ValidationTest.versions))
        .where(ValidationTest.id == finding.test_id)
    ).scalar_one_or_none()
    if test is not None:
        current = next(
            (version for version in test.versions if version.version == test.current_version),
            None,
        )
        if current is not None:
            return current
    version = db.get(ValidationTestVersion, finding.test_version_id)
    if version is None:
        raise _conflict(
            f"finding {finding.id} cannot be retested: its test has no runnable version"
        )
    return version


@router.post("/findings/{finding_id}/retest", response_model=FindingRetestOut)
def retest_finding(
    finding_id: int,
    request: Request,
    user: User = Depends(require_writer),
    db: OrmSession = Depends(get_db),
) -> FindingRetestOut:
    """Queue a fresh run of the finding's test against its target.

    Refused while a run for the same test and target is queued or running: the
    retest would race the run already in flight for the same answer.
    """
    finding = _load_finding(db, finding_id)
    version = _version_for_retest(db, finding)
    spec = get_engine(version.engine_id)
    if spec is None:
        raise _conflict(
            f"finding {finding.id} names unknown engine {version.engine_id!r}; "
            "no run was queued"
        )

    active = db.execute(
        select(ValidationRun.id)
        .where(
            ValidationRun.test_id == finding.test_id,
            ValidationRun.target_id == finding.target_id,
            ValidationRun.status.in_((RunStatus.QUEUED, RunStatus.RUNNING)),
        )
        .limit(1)
    ).scalar_one_or_none()
    if active is not None:
        raise _conflict(
            f"run {active} for this test and target is already queued or running; "
            "wait for it to finish instead of double-queuing"
        )

    run = jobs.enqueue(
        db,
        test_id=finding.test_id,
        test_version_id=version.id,
        target_id=finding.target_id,
        engine_id=version.engine_id,
        timeout_seconds=spec.default_timeout,
        trigger=TriggerKind.RETEST,
        authorized_by_user_id=user.id,
        retest_of_finding_id=finding.id,
    )
    audit.record(
        db,
        action="finding.retest",
        actor=user,
        actor_ip=client_ip(request),
        object_type="finding",
        object_id=finding.id,
        after={
            "run_id": run.id,
            "test_id": finding.test_id,
            "test_version_id": version.id,
            "target_id": finding.target_id,
            "engine_id": version.engine_id,
        },
    )
    db.commit()
    return FindingRetestOut(run_id=run.id)
