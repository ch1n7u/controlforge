"""Dashboard aggregates: summary, assertion trend and per-control posture.

Every number here is computed by the database. The assertion tables grow with
every run, so "current posture" is a ``DISTINCT ON`` pick of the newest result
per (test, target) - the historical rows are never loaded into Python to be
reduced there.
"""

from __future__ import annotations

from datetime import date, datetime, time, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import Date, Float, cast, func, or_, select
from sqlalchemy.orm import Session as OrmSession

from app.api.deps import require_user
from app.db import get_db
from app.models.auth import User
from app.models.enums import AssertionStatus, FindingStatus, RunStatus, Severity
from app.models.facts import AssertionResult
from app.models.findings import Finding
from app.models.registry import Control, Scope, Setting, Target, TargetScope
from app.models.testing import ValidationRun, ValidationTestVersion
from app.schemas.dashboard import (
    AssertionCounts,
    CoverageCounts,
    DashboardSummary,
    DashboardTrend,
    FindingsCounts,
    PostureRow,
    RunCounts,
    TargetCounts,
    TrendDay,
)
from app.schemas.settings import StalenessSettings, defaults

router = APIRouter(prefix="/api", tags=["dashboard"])

TREND_DAYS_MAX = 365
POSTURE_LIMIT_MAX = 200


def _latest_assertions():
    """The newest assertion result per (test, target) pair.

    The test identity comes through the version: a result evaluated against
    version 2 and one against version 3 are the same test. ORDER BY must lead
    with the DISTINCT ON expressions; ``id DESC`` breaks ties when two results
    carry the same ``evaluated_at``.
    """
    return (
        select(
            ValidationTestVersion.test_id.label("test_id"),
            AssertionResult.target_id.label("target_id"),
            AssertionResult.control_id.label("control_id"),
            AssertionResult.status.label("status"),
            AssertionResult.evaluated_at.label("evaluated_at"),
        )
        .join(
            ValidationTestVersion,
            ValidationTestVersion.id == AssertionResult.test_version_id,
        )
        .distinct(ValidationTestVersion.test_id, AssertionResult.target_id)
        .order_by(
            ValidationTestVersion.test_id,
            AssertionResult.target_id,
            AssertionResult.evaluated_at.desc(),
            AssertionResult.id.desc(),
        )
        .subquery()
    )


def _staleness_hours(db: OrmSession) -> int:
    """The staleness window, resolved exactly the way /api/settings resolves it.

    A stored ``staleness`` row wins; with no row the schema default applies, so
    the dashboard and the settings page can never disagree about what "stale"
    means (the default is 168 h / 7 days - see StalenessSettings).
    """
    row = db.execute(select(Setting).where(Setting.key == "staleness")).scalar_one_or_none()
    value = row.value if row is not None else defaults()["staleness"]
    return StalenessSettings.model_validate(value).max_age_hours


@router.get("/dashboard/summary", response_model=DashboardSummary)
def dashboard_summary(
    db: OrmSession = Depends(get_db), _: User = Depends(require_user)
) -> DashboardSummary:
    now = datetime.now(timezone.utc)

    # --- assertions: current posture, one row per (test, target) -------------
    latest = _latest_assertions()
    assertion_counts = {status.value: 0 for status in AssertionStatus}
    for status, count in db.execute(
        select(latest.c.status, func.count()).group_by(latest.c.status)
    ):
        assertion_counts[status.value] = count

    # --- findings: every finding, grouped both ways --------------------------
    by_severity = {severity.value: 0 for severity in Severity}
    for severity, count in db.execute(
        select(Finding.severity, func.count()).group_by(Finding.severity)
    ):
        by_severity[severity.value] = count

    by_status = {status.value: 0 for status in FindingStatus}
    for status, count in db.execute(
        select(Finding.status, func.count()).group_by(Finding.status)
    ):
        by_status[status.value] = count

    # --- targets: enabled only, including the scoped count -------------------
    targets_total = db.execute(
        select(func.count()).select_from(Target).where(Target.enabled.is_(True))
    ).scalar_one()
    targets_scoped = db.execute(
        select(func.count(func.distinct(TargetScope.target_id)))
        .select_from(TargetScope)
        .join(Target, Target.id == TargetScope.target_id)
        .join(Scope, Scope.id == TargetScope.scope_id)
        .where(
            Target.enabled.is_(True),
            Scope.active.is_(True),
            or_(Scope.expires_at.is_(None), Scope.expires_at > now),
        )
    ).scalar_one()

    # --- runs: the last 24 h, plus what the queue holds right now ------------
    # The window is fixed rather than configurable: the strip answers "what has
    # the platform been doing today", and per-install windows would make two
    # dashboards disagree about the same moment.
    day_ago = now - timedelta(hours=24)
    run_counts = db.execute(
        select(
            func.count().filter(ValidationRun.queued_at >= day_ago).label("last_24h"),
            func.count().filter(ValidationRun.status == RunStatus.RUNNING).label("running"),
            func.count().filter(ValidationRun.status == RunStatus.QUEUED).label("queued"),
            func.count()
            .filter(
                ValidationRun.status == RunStatus.FAILED,
                ValidationRun.finished_at >= day_ago,
            )
            .label("failed"),
        ).select_from(ValidationRun)
    ).one()

    # --- coverage: enabled controls with anything newer than the window ------
    controls_total = db.execute(
        select(func.count()).select_from(Control).where(Control.enabled.is_(True))
    ).scalar_one()
    stale_before = now - timedelta(hours=_staleness_hours(db))
    controls_recent = db.execute(
        select(func.count(func.distinct(AssertionResult.control_id)))
        .select_from(AssertionResult)
        .join(Control, Control.id == AssertionResult.control_id)
        .where(Control.enabled.is_(True), AssertionResult.evaluated_at > stale_before)
    ).scalar_one()

    return DashboardSummary(
        assertions=AssertionCounts(
            passed=assertion_counts[AssertionStatus.PASS.value],
            fail=assertion_counts[AssertionStatus.FAIL.value],
            inconclusive=assertion_counts[AssertionStatus.INCONCLUSIVE.value],
            not_applicable=assertion_counts[AssertionStatus.NOT_APPLICABLE.value],
        ),
        findings=FindingsCounts(by_severity=by_severity, by_status=by_status),
        targets=TargetCounts(total=targets_total, scoped=targets_scoped),
        runs=RunCounts(
            last_24h=run_counts.last_24h,
            running=run_counts.running,
            queued=run_counts.queued,
            failed=run_counts.failed,
        ),
        coverage=CoverageCounts(
            controls_total=controls_total,
            controls_with_recent_results=controls_recent,
            controls_stale=controls_total - controls_recent,
        ),
        last_updated=now,
    )


@router.get("/dashboard/trend", response_model=DashboardTrend)
def dashboard_trend(
    days: int = Query(default=30, description="Window length in days (clamped to 1..365)."),
    db: OrmSession = Depends(get_db),
    _: User = Depends(require_user),
) -> DashboardTrend:
    """Assertion outcomes per calendar day, including days with no data.

    Values are clamped rather than rejected: the parameter drives a chart
    control, so a stray value should draw a sane chart, not a 422.
    """
    days = max(1, min(days, TREND_DAYS_MAX))
    today = datetime.now(timezone.utc).date()
    first_day = today - timedelta(days=days - 1)
    cutoff = datetime.combine(first_day, time.min, tzinfo=timezone.utc)

    # Bucketing happens in SQL. The explicit UTC conversion pins the bucket to
    # a UTC calendar day whatever the server's TimeZone setting is, so the SQL
    # days and the Python-filled day list below always agree.
    day = func.date_trunc("day", func.timezone("UTC", AssertionResult.evaluated_at)).cast(Date)
    rows = db.execute(
        select(day.label("day"), AssertionResult.status, func.count())
        .where(AssertionResult.evaluated_at >= cutoff)
        .group_by(day, AssertionResult.status)
    ).all()

    counts: dict[date, dict[str, int]] = {
        first_day + timedelta(days=offset): {
            "pass": 0,
            "fail": 0,
            "inconclusive": 0,
            "not_applicable": 0,
        }
        for offset in range(days)
    }
    for day_value, status, count in rows:
        bucket = counts.get(day_value)
        if bucket is not None:
            bucket[status.value] += count

    return DashboardTrend(
        days=[
            TrendDay(
                date=day_value,
                passed=bucket["pass"],
                fail=bucket["fail"],
                inconclusive=bucket["inconclusive"],
                not_applicable=bucket["not_applicable"],
            )
            for day_value, bucket in sorted(counts.items())
        ]
    )


@router.get("/dashboard/posture_by_control", response_model=list[PostureRow])
def posture_by_control(
    limit: int = Query(default=20, description="Rows to return (clamped to 1..200)."),
    db: OrmSession = Depends(get_db),
    _: User = Depends(require_user),
) -> list[PostureRow]:
    """Worst controls first, using the same "latest per (test, target)" rule.

    A control appears only once at least one of its pairs has a result.
    """
    limit = max(1, min(limit, POSTURE_LIMIT_MAX))
    latest = _latest_assertions()

    # coverage_ratio = decided / (decided + inconclusive): decided results over
    # decided-plus-undecided. NOT_APPLICABLE is excluded from the denominator -
    # the control does not apply on those targets, so they say nothing about
    # whether it works where it does apply.
    decided = func.count().filter(
        latest.c.status.in_((AssertionStatus.PASS, AssertionStatus.FAIL))
    )
    denominator = func.count().filter(
        latest.c.status.in_(
            (AssertionStatus.PASS, AssertionStatus.FAIL, AssertionStatus.INCONCLUSIVE)
        )
    )
    coverage_ratio = func.coalesce(cast(decided, Float) / func.nullif(denominator, 0), 0.0)
    fail_count = func.count().filter(latest.c.status == AssertionStatus.FAIL)

    rows = db.execute(
        select(
            Control.id.label("control_id"),
            Control.key.label("control_key"),
            Control.title.label("control_title"),
            Control.category.label("category"),
            func.count().filter(latest.c.status == AssertionStatus.PASS).label("pass_count"),
            fail_count.label("fail_count"),
            func.count()
            .filter(latest.c.status == AssertionStatus.INCONCLUSIVE)
            .label("inconclusive_count"),
            func.count()
            .filter(latest.c.status == AssertionStatus.NOT_APPLICABLE)
            .label("not_applicable_count"),
            coverage_ratio.label("coverage_ratio"),
            func.max(latest.c.evaluated_at).label("last_evaluated_at"),
        )
        .select_from(latest)
        .join(Control, Control.id == latest.c.control_id)
        .group_by(Control.id, Control.key, Control.title, Control.category)
        .order_by(fail_count.desc(), coverage_ratio.asc(), Control.key)
        .limit(limit)
    ).all()

    return [
        PostureRow(
            control_id=row.control_id,
            control_key=row.control_key,
            control_title=row.control_title,
            category=row.category,
            passed=row.pass_count,
            fail=row.fail_count,
            inconclusive=row.inconclusive_count,
            not_applicable=row.not_applicable_count,
            coverage_ratio=row.coverage_ratio,
            last_evaluated_at=row.last_evaluated_at,
        )
        for row in rows
    ]
