"""Dashboard aggregates over real rows.

The dashboard is the screen an operator trusts to say whether the controls are
working, so these tests pin the two rules that are easy to get subtly wrong:
"current posture" means the newest result per (test, target) - neither every
historical row nor the worst one - and a control whose latest evidence predates
the staleness window is reported stale rather than covered.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.main import app
from app.models.enums import (
    AssertionStatus,
    FindingStatus,
    RunStatus,
    Severity,
    TargetType,
)
from app.models.facts import AssertionResult
from app.models.findings import Finding
from app.models.registry import Control, Scope, Target, TargetScope
from app.models.testing import ValidationRun, ValidationTest, ValidationTestVersion
from tests.conftest import csrf_headers


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def make_control(db, key: str, *, enabled: bool = True, category: str = "headers") -> Control:
    control = Control(
        key=key,
        title=f"Control {key}",
        category=category,
        default_severity=Severity.MEDIUM,
        enabled=enabled,
    )
    db.add(control)
    db.flush()
    return control


def make_test(db, control: Control, key: str) -> tuple[ValidationTest, ValidationTestVersion]:
    test = ValidationTest(key=key, name=f"Test {key}", control_id=control.id)
    db.add(test)
    db.flush()
    version = ValidationTestVersion(
        test_id=test.id,
        version=1,
        engine_id="http_headers",
        engine_params={},
        assertion={"fact": "http_header"},
        control_id=control.id,
        severity=Severity.MEDIUM,
    )
    db.add(version)
    db.flush()
    test.current_version = 1
    return test, version


def make_target(db, name: str, *, enabled: bool = True) -> Target:
    target = Target(
        name=name,
        target_type=TargetType.WEBAPP,
        host=f"{name}.lab",
        port=443,
        protocol="https",
        enabled=enabled,
    )
    db.add(target)
    db.flush()
    return target


def add_result(db, test, version, target, status, evaluated_at, *, assertion_index: int = 0):
    """Record one assertion result, with the terminal run that produced it."""
    run = ValidationRun(
        test_id=test.id,
        test_version_id=version.id,
        target_id=target.id,
        engine_id="http_headers",
        status=RunStatus.PASSED,
        queued_at=evaluated_at,
        finished_at=evaluated_at,
    )
    db.add(run)
    db.flush()
    result = AssertionResult(
        run_id=run.id,
        test_version_id=version.id,
        target_id=target.id,
        control_id=version.control_id,
        assertion_index=assertion_index,
        assertion={},
        status=status,
        severity=Severity.MEDIUM,
        evaluated_at=evaluated_at,
    )
    db.add(result)
    db.flush()
    return result


# ------------------------------------------------------------------ summary --


def test_summary_counts_the_newest_result_per_test_and_target(admin_client, db):
    """The old FAIL is superseded by the newer PASS on the same pair, and a
    "worst wins" implementation would report the opposite."""
    control = make_control(db, "C-1")
    test, version = make_test(db, control, "t-1")
    superseded = make_target(db, "web-1")
    failing = make_target(db, "web-2")
    now = utcnow()

    add_result(db, test, version, superseded, AssertionStatus.FAIL, now - timedelta(days=3))
    add_result(db, test, version, superseded, AssertionStatus.FAIL, now - timedelta(days=1))
    add_result(db, test, version, superseded, AssertionStatus.PASS, now - timedelta(hours=2))
    add_result(db, test, version, failing, AssertionStatus.FAIL, now - timedelta(hours=1))

    # a second test against the same control and target is its own pair
    test2, version2 = make_test(db, control, "t-2")
    add_result(db, test2, version2, superseded, AssertionStatus.INCONCLUSIVE, now)
    db.commit()

    body = admin_client.get("/api/dashboard/summary").json()
    assert body["assertions"] == {
        "pass": 1,
        "fail": 1,
        "inconclusive": 1,
        "not_applicable": 0,
    }
    assert datetime.fromisoformat(body["last_updated"]).tzinfo is not None


def test_summary_groups_findings_by_severity_and_status(admin_client, db):
    control = make_control(db, "C-1")
    test, version = make_test(db, control, "t-1")
    target = make_target(db, "web-1")
    for index, (severity, status) in enumerate(
        [
            (Severity.HIGH, FindingStatus.OPEN),
            (Severity.MEDIUM, FindingStatus.OPEN),
            (Severity.MEDIUM, FindingStatus.RESOLVED),
        ]
    ):
        db.add(
            Finding(
                fingerprint=f"fp-{index}",
                title=f"Finding {index}",
                control_id=control.id,
                test_id=test.id,
                test_version_id=version.id,
                target_id=target.id,
                assertion_index=index,
                assertion={},
                severity=severity,
                status=status,
            )
        )
    db.commit()

    body = admin_client.get("/api/dashboard/summary").json()
    assert body["findings"]["by_severity"] == {
        "info": 0,
        "low": 0,
        "medium": 2,
        "high": 1,
        "critical": 0,
    }
    assert body["findings"]["by_status"] == {
        "open": 2,
        "triaged": 0,
        "remediating": 0,
        "accepted_risk": 0,
        "false_positive": 0,
        "resolved": 1,
    }


def test_summary_counts_only_enabled_and_authorized_targets(admin_client, db):
    authorized = make_target(db, "web-1")
    expired = make_target(db, "web-2")
    inactive = make_target(db, "web-3")
    disabled = make_target(db, "web-4", enabled=False)

    live_scope = Scope(name="live", active=True)
    expired_scope = Scope(name="expired", active=True, expires_at=utcnow() - timedelta(days=1))
    inactive_scope = Scope(name="inactive", active=False)
    db.add_all([live_scope, expired_scope, inactive_scope])
    db.flush()
    db.add_all(
        [
            TargetScope(target_id=authorized.id, scope_id=live_scope.id),
            TargetScope(target_id=expired.id, scope_id=expired_scope.id),
            TargetScope(target_id=inactive.id, scope_id=inactive_scope.id),
            # a disabled target does not count even under a live scope
            TargetScope(target_id=disabled.id, scope_id=live_scope.id),
        ]
    )
    db.commit()

    body = admin_client.get("/api/dashboard/summary").json()
    assert body["targets"] == {"total": 3, "scoped": 1}


def test_summary_counts_runs_over_a_fixed_24_hour_window(admin_client, db):
    control = make_control(db, "C-1")
    test, version = make_test(db, control, "t-1")
    target = make_target(db, "web-1")
    now = utcnow()

    def run(status, queued_at, finished_at=None):
        db.add(
            ValidationRun(
                test_id=test.id,
                test_version_id=version.id,
                target_id=target.id,
                engine_id="http_headers",
                status=status,
                queued_at=queued_at,
                finished_at=finished_at,
            )
        )

    run(RunStatus.QUEUED, now - timedelta(hours=1))
    run(RunStatus.QUEUED, now - timedelta(hours=30))  # outside the 24 h window
    run(RunStatus.RUNNING, now - timedelta(hours=2))
    run(RunStatus.FAILED, now - timedelta(hours=3), now - timedelta(hours=2))
    run(RunStatus.FAILED, now - timedelta(hours=26), now - timedelta(hours=25))
    db.commit()

    body = admin_client.get("/api/dashboard/summary").json()
    assert body["runs"] == {"last_24h": 3, "running": 1, "queued": 2, "failed": 1}


# -------------------------------------------------------------------- trend --


def test_trend_buckets_days_and_fills_the_empty_ones(admin_client, db):
    control = make_control(db, "C-1")
    test, version = make_test(db, control, "t-1")
    target = make_target(db, "web-1")
    now = utcnow()

    add_result(db, test, version, target, AssertionStatus.PASS, now)
    add_result(db, test, version, target, AssertionStatus.PASS, now)
    add_result(db, test, version, target, AssertionStatus.FAIL, now - timedelta(days=2))
    add_result(db, test, version, target, AssertionStatus.INCONCLUSIVE, now - timedelta(days=4))
    # old enough to fall outside a 5-day window
    add_result(db, test, version, target, AssertionStatus.FAIL, now - timedelta(days=9))
    db.commit()

    days = admin_client.get("/api/dashboard/trend?days=5").json()["days"]
    today = now.date()
    expected_dates = [
        (today - timedelta(days=offset)).isoformat() for offset in (4, 3, 2, 1, 0)
    ]
    assert [day["date"] for day in days] == expected_dates
    assert days[4] == {
        "date": today.isoformat(),
        "pass": 2,
        "fail": 0,
        "inconclusive": 0,
        "not_applicable": 0,
    }
    assert days[2]["fail"] == 1
    assert days[0]["inconclusive"] == 1
    # the days between the results carry zeros, not a gap
    for empty in (days[1], days[3]):
        assert [empty[key] for key in ("pass", "fail", "inconclusive", "not_applicable")] == [
            0,
            0,
            0,
            0,
        ]
    assert days[3]["date"] == (today - timedelta(days=1)).isoformat()
    # nothing older than the window leaks in
    total = sum(
        day[key] for day in days for key in ("pass", "fail", "inconclusive", "not_applicable")
    )
    assert total == 4


def test_trend_window_defaults_and_clamps(admin_client):
    today = utcnow().date()
    default_days = admin_client.get("/api/dashboard/trend").json()["days"]
    assert len(default_days) == 30
    assert default_days[-1]["date"] == today.isoformat()

    assert len(admin_client.get("/api/dashboard/trend?days=0").json()["days"]) == 1
    assert len(admin_client.get("/api/dashboard/trend?days=9999").json()["days"]) == 365


# ------------------------------------------------------------------ posture --


def test_posture_orders_worst_first_and_skips_controls_without_results(admin_client, db):
    now = utcnow()

    worst = make_control(db, "M-worst")
    worst_test, worst_version = make_test(db, worst, "ta")
    t1, t2, t3, t4 = (make_target(db, f"w{i}") for i in range(1, 5))
    # t1 failed once and now passes - the newest result must win here too
    add_result(db, worst_test, worst_version, t1, AssertionStatus.FAIL, now - timedelta(days=2))
    add_result(db, worst_test, worst_version, t1, AssertionStatus.PASS, now - timedelta(hours=1))
    add_result(db, worst_test, worst_version, t2, AssertionStatus.FAIL, now - timedelta(hours=2))
    add_result(db, worst_test, worst_version, t3, AssertionStatus.FAIL, now - timedelta(hours=3))
    # fail=2, pass=1, ratio 3/3

    # Keys are chosen so a key-based tie-break cannot imitate the ratio order:
    # "Z-mixed" sorts last alphabetically yet must come before "A-even".
    mixed = make_control(db, "Z-mixed")
    mixed_test, mixed_version = make_test(db, mixed, "tb")
    add_result(db, mixed_test, mixed_version, t1, AssertionStatus.FAIL, now - timedelta(hours=4))
    add_result(db, mixed_test, mixed_version, t2, AssertionStatus.PASS, now - timedelta(hours=5))
    add_result(
        db, mixed_test, mixed_version, t3, AssertionStatus.INCONCLUSIVE, now - timedelta(hours=6)
    )
    add_result(
        db, mixed_test, mixed_version, t4, AssertionStatus.INCONCLUSIVE, now - timedelta(hours=7)
    )
    # fail=1, decided=2, denominator=4 -> ratio 0.5, so it sorts ahead of A-even

    even = make_control(db, "A-even")
    even_test, even_version = make_test(db, even, "te")
    add_result(db, even_test, even_version, t1, AssertionStatus.FAIL, now - timedelta(hours=8))
    add_result(db, even_test, even_version, t2, AssertionStatus.PASS, now - timedelta(hours=9))
    # fail=1, ratio 1.0

    inapplicable = make_control(db, "N-na")
    na_test, na_version = make_test(db, inapplicable, "tc")
    add_result(
        db, na_test, na_version, t1, AssertionStatus.NOT_APPLICABLE, now - timedelta(hours=10)
    )
    add_result(
        db, na_test, na_version, t2, AssertionStatus.NOT_APPLICABLE, now - timedelta(hours=11)
    )
    # zero denominator

    make_control(db, "D-silent")
    db.commit()

    rows = admin_client.get("/api/dashboard/posture_by_control").json()
    assert [row["control_key"] for row in rows] == ["M-worst", "Z-mixed", "A-even", "N-na"]

    assert rows[0]["fail"] == 2 and rows[0]["pass"] == 1
    assert rows[0]["coverage_ratio"] == 1.0
    assert rows[1]["coverage_ratio"] == 0.5
    assert rows[3]["not_applicable"] == 2 and rows[3]["coverage_ratio"] == 0.0
    assert datetime.fromisoformat(rows[0]["last_evaluated_at"]) == now - timedelta(hours=1)
    assert rows[0]["control_title"] == "Control M-worst"
    assert rows[0]["category"] == "headers"

    assert len(admin_client.get("/api/dashboard/posture_by_control?limit=2").json()) == 2
    assert len(admin_client.get("/api/dashboard/posture_by_control?limit=0").json()) == 1


# ----------------------------------------------------------------- coverage --


def test_a_control_without_recent_results_is_stale_not_covered(admin_client, db):
    now = utcnow()

    fresh = make_control(db, "C-fresh")
    fresh_test, fresh_version = make_test(db, fresh, "tf")
    add_result(
        db, fresh_test, fresh_version, make_target(db, "w1"), AssertionStatus.PASS,
        now - timedelta(hours=2),
    )

    old = make_control(db, "C-old")
    old_test, old_version = make_test(db, old, "to")
    add_result(
        db, old_test, old_version, make_target(db, "w2"), AssertionStatus.PASS,
        now - timedelta(days=8),
    )

    make_control(db, "C-silent")  # no results at all
    make_control(db, "C-disabled", enabled=False)  # not part of the enabled total
    db.commit()

    body = admin_client.get("/api/dashboard/summary").json()
    assert body["coverage"] == {
        "controls_total": 3,
        "controls_with_recent_results": 1,
        "controls_stale": 2,
    }

    keys = [
        row["control_key"]
        for row in admin_client.get("/api/dashboard/posture_by_control").json()
    ]
    assert "C-silent" not in keys
    assert "C-fresh" in keys and "C-old" in keys


def test_the_staleness_window_follows_the_staleness_setting(admin_client, db):
    """The window is not hardcoded: it is whatever /api/settings resolves."""
    now = utcnow()
    for key, age in (("C-new", timedelta(hours=1)), ("C-recentish", timedelta(hours=3))):
        control = make_control(db, key)
        test, version = make_test(db, control, f"t-{key}")
        add_result(db, test, version, make_target(db, f"w-{key}"), AssertionStatus.PASS, now - age)
    db.commit()

    # under the 7-day default both count as covered
    before = admin_client.get("/api/dashboard/summary").json()
    assert before["coverage"]["controls_with_recent_results"] == 2

    response = admin_client.put(
        "/api/settings/staleness",
        json={"value": {"max_age_hours": 2}},
        headers=csrf_headers(admin_client),
    )
    assert response.status_code == 200, response.text

    after = admin_client.get("/api/dashboard/summary").json()
    assert after["coverage"]["controls_with_recent_results"] == 1
    assert after["coverage"]["controls_stale"] == 1


# --------------------------------------------------------------------- RBAC --


def test_dashboard_requires_authentication(client):
    for path in (
        "/api/dashboard/summary",
        "/api/dashboard/trend",
        "/api/dashboard/posture_by_control",
    ):
        assert client.get(path).status_code == 401
