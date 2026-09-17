"""Runs over HTTP: queueing, following, cancelling and reading output.

The properties with teeth here are the ones the SPA depends on: the summary
and detail shapes it renders without null checks, and the SSE stream, which
must replay history, report status changes, and end with a done event so the
log view can close cleanly.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.engines.catalogue import get_engine
from app.main import app
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.enums import (
    AssertionStatus,
    EvidenceKind,
    RunStatus,
    Severity,
    StreamKind,
    TargetType,
)
from app.models.facts import AssertionResult, Fact
from app.models.findings import Finding
from app.models.registry import Control, Target
from app.models.testing import (
    Evidence,
    RunLog,
    ValidationRun,
    ValidationTest,
    ValidationTestVersion,
)
from tests.conftest import csrf_headers, login


def make_test(db, *, key="hdr-hsts", enabled=True, engine_id="http_headers"):
    control = Control(
        key=f"ctl-{key}",
        title=f"Control for {key}",
        category="headers",
        default_severity=Severity.MEDIUM,
    )
    db.add(control)
    db.flush()
    test = ValidationTest(
        key=key,
        name=f"Test {key}",
        control_id=control.id,
        tags=[],
        target_selector={},
        enabled=enabled,
        current_version=1,
    )
    db.add(test)
    db.flush()
    version = ValidationTestVersion(
        test_id=test.id,
        version=1,
        engine_id=engine_id,
        engine_params={},
        assertion={"fact": "http_header"},
        control_id=control.id,
        severity=Severity.MEDIUM,
    )
    db.add(version)
    db.flush()
    return test, version


def make_target(db, *, name="lab-web", host="127.0.0.1", port=8081, enabled=True):
    target = Target(
        name=name,
        target_type=TargetType.WEBAPP,
        host=host,
        port=port,
        enabled=enabled,
    )
    db.add(target)
    db.flush()
    return target


def make_run(db, test, version, target, *, status=RunStatus.QUEUED, **overrides):
    run = ValidationRun(
        test_id=test.id,
        test_version_id=version.id,
        target_id=target.id,
        engine_id=overrides.pop("engine_id", version.engine_id),
        status=status,
        **overrides,
    )
    db.add(run)
    db.flush()
    return run


def start_payload(test, targets):
    return {"test_id": test.id, "target_ids": [target.id for target in targets]}


# ------------------------------------------------------------------ starting --


def test_starting_a_run_queues_one_run_per_target(admin_client, admin_user, db):
    test, version = make_test(db)
    first = make_target(db, name="web-one", port=8081)
    second = make_target(db, name="web-two", port=8082)
    db.commit()

    response = admin_client.post(
        "/api/runs", json=start_payload(test, [first, second]), headers=csrf_headers(admin_client)
    )
    assert response.status_code == 201, response.text
    runs = response.json()["runs"]
    assert len(runs) == 2
    assert {run["target_name"] for run in runs} == {"web-one", "web-two"}
    assert all(run["test_key"] == "hdr-hsts" for run in runs)
    assert all(run["test_id"] == test.id for run in runs)
    assert all(run["target_host"] == "127.0.0.1" for run in runs)
    assert all(run["engine_id"] == "http_headers" for run in runs)
    assert all(run["status"] == "queued" for run in runs)
    assert all(run["trigger"] == "manual" for run in runs)
    assert all(run["attempt"] == 0 for run in runs)
    assert all(run["duration_seconds"] is None for run in runs)
    assert all(run["assertion_status"] is None for run in runs)
    assert all(run["findings_count"] == 0 for run in runs)
    assert all(run["authorized_by_username"] == "admin" for run in runs)

    queued = db.execute(select(ValidationRun).order_by(ValidationRun.id)).scalars().all()
    assert [row.target_id for row in queued] == [first.id, second.id]
    assert all(row.test_version_id == version.id for row in queued)
    assert all(row.authorized_by_user_id == admin_user.id for row in queued)
    assert all(row.timeout_seconds == get_engine("http_headers").default_timeout for row in queued)

    entry = db.query(AuditLog).filter(AuditLog.action == "run.start").one()
    assert entry.actor_username == "admin"
    assert entry.after["test_key"] == "hdr-hsts"
    assert entry.after["version"] == 1
    assert {target["name"] for target in entry.after["targets"]} == {"web-one", "web-two"}
    assert entry.after["run_ids"] == [row.id for row in queued]


def test_a_disabled_test_cannot_be_run(admin_client, db):
    test, _ = make_test(db, enabled=False)
    target = make_target(db)
    db.commit()

    response = admin_client.post(
        "/api/runs", json=start_payload(test, [target]), headers=csrf_headers(admin_client)
    )
    assert response.status_code == 409
    assert "disabled" in response.json()["detail"]
    assert db.query(ValidationRun).count() == 0


def test_a_run_survives_the_deletion_of_the_account_that_queued_it(
    admin_client, analyst_user, db
):
    """The run is the record of what was tested; it must not disappear with the
    operator. The FK is ON DELETE SET NULL, so the run stays and only the name it
    reports goes absent - the actor is still on the audit row."""
    test, _ = make_test(db)
    target = make_target(db)
    db.commit()

    with TestClient(app) as analyst_client:
        login(analyst_client, analyst_user.username)
        started = analyst_client.post(
            "/api/runs",
            json=start_payload(test, [target]),
            headers=csrf_headers(analyst_client),
        ).json()["runs"][0]
    assert started["authorized_by_username"] == "analyst"

    db.delete(db.get(User, analyst_user.id))
    db.commit()

    detail = admin_client.get(f"/api/runs/{started['id']}")
    assert detail.status_code == 200
    assert detail.json()["authorized_by_username"] is None
    assert detail.json()["status"] == "queued"


def test_an_unknown_test_is_a_404(admin_client, db):
    target = make_target(db)
    db.commit()
    response = admin_client.post(
        "/api/runs",
        json={"test_id": 999_999, "target_ids": [target.id]},
        headers=csrf_headers(admin_client),
    )
    assert response.status_code == 404


def test_an_unknown_target_is_a_404(admin_client, db):
    test, _ = make_test(db)
    db.commit()
    response = admin_client.post(
        "/api/runs",
        json={"test_id": test.id, "target_ids": [999_999]},
        headers=csrf_headers(admin_client),
    )
    assert response.status_code == 404


def test_a_disabled_target_is_refused_by_name(admin_client, db):
    test, _ = make_test(db)
    target = make_target(db, name="retired-web", enabled=False)
    db.commit()

    response = admin_client.post(
        "/api/runs", json=start_payload(test, [target]), headers=csrf_headers(admin_client)
    )
    assert response.status_code == 409
    assert "retired-web" in response.json()["detail"]
    assert db.query(ValidationRun).count() == 0


def test_a_run_needs_at_least_one_target(admin_client, db):
    test, _ = make_test(db)
    db.commit()
    response = admin_client.post(
        "/api/runs", json={"test_id": test.id, "target_ids": []}, headers=csrf_headers(admin_client)
    )
    assert response.status_code == 422


def test_starting_a_run_requires_csrf(admin_client, db):
    test, _ = make_test(db)
    target = make_target(db)
    db.commit()
    response = admin_client.post("/api/runs", json=start_payload(test, [target]))
    assert response.status_code == 403
    assert "CSRF" in response.json()["detail"]


def test_a_viewer_can_read_runs_but_cannot_start_them(client, viewer_user, db):
    test, version = make_test(db)
    target = make_target(db)
    run = make_run(db, test, version, target)
    db.commit()

    login(client, viewer_user.username)
    assert client.get("/api/runs").status_code == 200
    assert client.get(f"/api/runs/{run.id}").status_code == 200
    refused = client.post(
        "/api/runs", json=start_payload(test, [target]), headers=csrf_headers(client)
    )
    assert refused.status_code == 403


def test_runs_require_authentication(client):
    assert client.get("/api/runs").status_code == 401


# ------------------------------------------------------------------ filtering --


def test_runs_can_be_filtered(admin_client, db):
    first_test, first_version = make_test(db, key="one")
    second_test, second_version = make_test(db, key="two", engine_id="nmap")
    first_target = make_target(db, name="web-one", port=8081)
    second_target = make_target(db, name="web-two", port=8082)
    oldest = make_run(db, first_test, first_version, first_target, status=RunStatus.QUEUED)
    middle = make_run(db, first_test, first_version, second_target, status=RunStatus.PASSED)
    newest = make_run(db, second_test, second_version, first_target, status=RunStatus.PASSED)
    db.commit()

    body = admin_client.get("/api/runs").json()
    assert body["total"] == 3
    assert [run["id"] for run in body["items"]] == [newest.id, middle.id, oldest.id]

    def ids(query: str) -> list[int]:
        page = admin_client.get(f"/api/runs?{query}").json()
        return [run["id"] for run in page["items"]]

    assert ids("status=passed") == [newest.id, middle.id]
    assert ids(f"test_id={first_test.id}") == [middle.id, oldest.id]
    assert ids(f"target_id={first_target.id}") == [newest.id, oldest.id]
    assert ids("engine_id=nmap") == [newest.id]
    assert admin_client.get("/api/runs?status=passed").json()["total"] == 2
    assert ids("limit=1&offset=1") == [middle.id]
    assert admin_client.get("/api/runs?status=nonsense").status_code == 422


def test_an_unknown_run_is_a_404(admin_client):
    assert admin_client.get("/api/runs/999999").status_code == 404
    assert admin_client.get("/api/runs/999999/log").status_code == 404
    assert admin_client.get("/api/runs/999999/facts").status_code == 404


# --------------------------------------------------------------------- detail --


def test_run_detail_reports_facts_assertions_and_findings(admin_client, db):
    test, version = make_test(db)
    target = make_target(db)
    run = make_run(
        db,
        test,
        version,
        target,
        status=RunStatus.FAILED,
        started_at=datetime(2026, 9, 17, 10, 0, tzinfo=UTC),
        finished_at=datetime(2026, 9, 17, 10, 0, 5, tzinfo=UTC),
        exit_code=1,
        timeout_seconds=60,
        argv=["testssl.sh", "--json"],
        resolved_ips=["127.0.0.1"],
    )
    db.add_all(
        [
            Fact(
                run_id=run.id,
                target_id=target.id,
                fact_type="http_header",
                subject="",
                key="strict-transport-security",
                value={"name": "strict-transport-security"},
            ),
            Fact(
                run_id=run.id,
                target_id=target.id,
                fact_type="http_header",
                subject="",
                key="content-security-policy",
                value={"name": "content-security-policy"},
            ),
            Fact(
                run_id=run.id,
                target_id=target.id,
                fact_type="http_response",
                subject="",
                key="status",
                value={"status": 200},
            ),
        ]
    )
    db.add(
        AssertionResult(
            run_id=run.id,
            test_version_id=version.id,
            target_id=target.id,
            control_id=version.control_id,
            assertion_index=0,
            assertion={"fact": "http_header", "op": "exists"},
            status=AssertionStatus.PASS,
            severity=Severity.MEDIUM,
            reason="header present",
            fact_ids=[],
        )
    )
    db.add(
        AssertionResult(
            run_id=run.id,
            test_version_id=version.id,
            target_id=target.id,
            control_id=version.control_id,
            assertion_index=1,
            assertion={"fact": "http_header", "op": "exists"},
            status=AssertionStatus.FAIL,
            severity=Severity.HIGH,
            reason="content-security-policy is missing",
            fact_ids=[7, 8],
        )
    )
    db.add(
        Finding(
            fingerprint="f" * 64,
            title="Missing CSP",
            control_id=version.control_id,
            test_id=test.id,
            test_version_id=version.id,
            target_id=target.id,
            assertion={"fact": "http_header"},
            severity=Severity.HIGH,
            last_failed_run_id=run.id,
        )
    )
    db.add(
        Evidence(
            run_id=run.id,
            kind=EvidenceKind.STDOUT,
            filename="run.log",
            rel_path=f"runs/{run.id}.log",
            sha256="a" * 64,
            size_bytes=42,
            mime="text/plain",
        )
    )
    db.commit()

    body = admin_client.get(f"/api/runs/{run.id}").json()
    assert body["duration_seconds"] == 5.0
    assert body["assertion_status"] == "fail"
    assert body["findings_count"] == 1
    assert body["argv"] == ["testssl.sh", "--json"]
    assert body["resolved_ips"] == ["127.0.0.1"]
    assert body["timeout_seconds"] == 60
    assert body["cancel_requested"] is False
    assert body["facts_summary"] == [
        {"fact_type": "http_header", "count": 2},
        {"fact_type": "http_response", "count": 1},
    ]
    assert [row["status"] for row in body["assertion_results"]] == ["pass", "fail"]
    assert body["assertion_results"][1]["reason"] == "content-security-policy is missing"
    assert body["assertion_results"][1]["fact_ids"] == [7, 8]
    assert body["assertion_results"][0]["fact_ids"] == []
    assert body["evidence"][0]["filename"] == "run.log"
    assert body["evidence"][0]["size_bytes"] == 42
    assert body["evidence"][0]["sha256"] == "a" * 64


def test_assertion_status_reports_the_worst_result(admin_client, db):
    test, version = make_test(db)
    target = make_target(db)

    def add_result(run, index, result_status):
        db.add(
            AssertionResult(
                run_id=run.id,
                test_version_id=version.id,
                target_id=target.id,
                control_id=version.control_id,
                assertion_index=index,
                assertion={"fact": "http_header"},
                status=result_status,
                severity=Severity.MEDIUM,
            )
        )

    mostly_clean = make_run(db, test, version, target, status=RunStatus.PASSED)
    add_result(mostly_clean, 0, AssertionStatus.PASS)
    add_result(mostly_clean, 1, AssertionStatus.NOT_APPLICABLE)

    undecided = make_run(db, test, version, target, status=RunStatus.PASSED)
    add_result(undecided, 0, AssertionStatus.PASS)
    add_result(undecided, 1, AssertionStatus.INCONCLUSIVE)
    db.commit()

    assert admin_client.get(f"/api/runs/{mostly_clean.id}").json()["assertion_status"] == "pass"
    assert admin_client.get(f"/api/runs/{undecided.id}").json()["assertion_status"] == "inconclusive"


def test_runs_can_be_filtered_by_assertion_status(admin_client, db):
    """The filter matches a run's *worst* assertion status, which is the status
    the list shows - so a run that failed one assertion is found under failed
    and not under passed, even though it also has a passing assertion."""
    test, version = make_test(db)
    target = make_target(db)

    def add_result(run, index, result_status):
        db.add(
            AssertionResult(
                run_id=run.id,
                test_version_id=version.id,
                target_id=target.id,
                control_id=version.control_id,
                assertion_index=index,
                assertion={"fact": "http_header"},
                status=result_status,
                severity=Severity.MEDIUM,
            )
        )

    clean = make_run(db, test, version, target, status=RunStatus.PASSED)
    add_result(clean, 0, AssertionStatus.PASS)

    mixed = make_run(db, test, version, target, status=RunStatus.FAILED)
    add_result(mixed, 0, AssertionStatus.PASS)
    add_result(mixed, 1, AssertionStatus.FAIL)

    undecided = make_run(db, test, version, target, status=RunStatus.INCONCLUSIVE)
    add_result(undecided, 0, AssertionStatus.INCONCLUSIVE)

    never_evaluated = make_run(db, test, version, target, status=RunStatus.QUEUED)
    db.commit()

    def filtered(assertion_status: str) -> set[int]:
        response = admin_client.get(f"/api/runs?assertion_status={assertion_status}")
        assert response.status_code == 200, response.text
        return {row["id"] for row in response.json()["items"]}

    assert filtered("fail") == {mixed.id}
    assert filtered("pass") == {clean.id}
    assert filtered("inconclusive") == {undecided.id}
    assert filtered("not_applicable") == set()
    # a run with no assertion results has no status to match
    assert never_evaluated.id not in filtered("pass") | filtered("inconclusive")


def test_an_unknown_assertion_status_is_rejected(admin_client):
    assert admin_client.get("/api/runs?assertion_status=mostly").status_code == 422


# ------------------------------------------------------------------- log/facts --


def test_run_log_returns_new_lines_after_a_cursor(admin_client, db):
    test, version = make_test(db)
    target = make_target(db)
    run = make_run(db, test, version, target, status=RunStatus.RUNNING)
    lines = [
        RunLog(run_id=run.id, stream=StreamKind.SYSTEM, level="info", message=f"line {index}")
        for index in range(1, 6)
    ]
    db.add_all(lines)
    db.commit()

    body = admin_client.get(f"/api/runs/{run.id}/log").json()
    assert [line["message"] for line in body] == [f"line {index}" for index in range(1, 6)]
    assert [line["id"] for line in body] == [line.id for line in lines]
    assert body[0]["stream"] == "system"
    assert body[0]["level"] == "info"
    assert body[0]["ts"] is not None

    after = admin_client.get(f"/api/runs/{run.id}/log?after_id={lines[2].id}").json()
    assert [line["message"] for line in after] == ["line 4", "line 5"]
    assert all(line["id"] > lines[2].id for line in after)

    assert admin_client.get(f"/api/runs/{run.id}/log?limit=999999").status_code == 422


def test_run_facts_can_be_filtered_by_type(admin_client, db):
    test, version = make_test(db)
    target = make_target(db)
    run = make_run(db, test, version, target, status=RunStatus.PASSED)
    db.add_all(
        [
            Fact(
                run_id=run.id,
                target_id=target.id,
                fact_type="http_header",
                subject="",
                key="x-frame-options",
                value={"name": "x-frame-options", "value": "DENY"},
                confidence=0.9,
            ),
            Fact(
                run_id=run.id,
                target_id=target.id,
                fact_type="http_header",
                subject="",
                key="server",
                value={"name": "server", "value": "nginx"},
            ),
            Fact(
                run_id=run.id,
                target_id=target.id,
                fact_type="http_response",
                subject="",
                key="status",
                value={"status": 200},
            ),
        ]
    )
    db.commit()

    everything = admin_client.get(f"/api/runs/{run.id}/facts").json()
    assert len(everything) == 3
    filtered = admin_client.get(f"/api/runs/{run.id}/facts?fact_type=http_header").json()
    assert [fact["fact_type"] for fact in filtered] == ["http_header", "http_header"]
    assert filtered[0]["key"] == "x-frame-options"
    assert filtered[0]["value"] == {"name": "x-frame-options", "value": "DENY"}
    assert filtered[0]["confidence"] == 0.9
    assert filtered[0]["evidence_id"] is None


# ------------------------------------------------------------------ cancelling --


def test_cancelling_a_queued_run_stops_it_outright(admin_client, db):
    """A queued run has no worker to notice a flag, so it is closed directly."""
    test, version = make_test(db)
    target = make_target(db)
    run = make_run(db, test, version, target, status=RunStatus.QUEUED)
    db.commit()

    response = admin_client.post(f"/api/runs/{run.id}/cancel", headers=csrf_headers(admin_client))
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["id"] == run.id
    assert body["status"] == "cancelled"
    assert body["finished_at"] is not None
    assert admin_client.get(f"/api/runs/{run.id}").json()["cancel_requested"] is False

    db.expire_all()
    stored = db.get(ValidationRun, run.id)
    assert stored.status is RunStatus.CANCELLED
    assert stored.cancel_requested is False
    assert db.query(AuditLog).filter(AuditLog.action == "run.cancel").count() == 1


def test_cancelling_a_running_run_asks_its_worker_to_stop(admin_client, db):
    test, version = make_test(db)
    target = make_target(db)
    run = make_run(
        db,
        test,
        version,
        target,
        status=RunStatus.RUNNING,
        started_at=datetime(2026, 9, 17, 10, 0, tzinfo=UTC),
    )
    db.commit()

    response = admin_client.post(f"/api/runs/{run.id}/cancel", headers=csrf_headers(admin_client))
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "running"

    detail = admin_client.get(f"/api/runs/{run.id}").json()
    assert detail["cancel_requested"] is True

    db.expire_all()
    assert db.get(ValidationRun, run.id).cancel_requested is True


def test_cancelling_a_finished_run_conflicts(admin_client, db):
    test, version = make_test(db)
    target = make_target(db)
    run = make_run(
        db,
        test,
        version,
        target,
        status=RunStatus.PASSED,
        started_at=datetime(2026, 9, 17, 10, 0, tzinfo=UTC),
        finished_at=datetime(2026, 9, 17, 10, 0, 5, tzinfo=UTC),
    )
    db.commit()

    response = admin_client.post(f"/api/runs/{run.id}/cancel", headers=csrf_headers(admin_client))
    assert response.status_code == 409
    assert "passed" in response.json()["detail"]


# ------------------------------------------------------------------- streaming --


def sse_events(body: str) -> list[dict]:
    return [
        json.loads(line[len("data: ") :])
        for line in body.splitlines()
        if line.startswith("data: ")
    ]


def test_the_stream_replays_history_and_ends_with_done(admin_client, db):
    test, version = make_test(db)
    target = make_target(db)
    run = make_run(
        db,
        test,
        version,
        target,
        status=RunStatus.PASSED,
        started_at=datetime(2026, 9, 17, 10, 0, tzinfo=UTC),
        finished_at=datetime(2026, 9, 17, 10, 0, 5, tzinfo=UTC),
    )
    db.add_all(
        [
            RunLog(run_id=run.id, stream=StreamKind.SYSTEM, level="info", message="queued"),
            RunLog(run_id=run.id, stream=StreamKind.STDOUT, level="info", message="finished"),
        ]
    )
    db.commit()

    response = admin_client.get(f"/api/runs/{run.id}/stream")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")

    events = sse_events(response.text)
    assert events[-1] == {"type": "done"}
    assert [event["message"] for event in events if event["type"] == "log"] == [
        "queued",
        "finished",
    ]
    assert [event["status"] for event in events if event["type"] == "status"] == ["passed"]
    assert all(event["type"] == "log" for event in events[:-2])


def test_the_stream_requires_an_authenticated_session(client, db):
    test, version = make_test(db)
    target = make_target(db)
    run = make_run(db, test, version, target, status=RunStatus.PASSED)
    db.commit()

    assert client.get(f"/api/runs/{run.id}/stream").status_code == 401
