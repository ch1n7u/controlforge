"""Findings over HTTP: list, detail, triage and retests.

The properties a reviewer relies on: the list obeys its filters and ordering,
a triage edit leaves both a changed row and an append-only timeline entry, and
a retest can never double-queue a run for the same test and target.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from app.engines.catalogue import get_engine
from app.main import app
from app.models.audit import AuditLog
from app.models.enums import (
    AssertionStatus,
    EvidenceKind,
    FindingStatus,
    RemediationActionKind,
    RunStatus,
    Severity,
    TargetType,
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
from tests.conftest import csrf_headers, login

SUMMARY_FIELDS = {
    "id",
    "status",
    "severity",
    "title",
    "control_id",
    "control_key",
    "control_title",
    "test_id",
    "test_key",
    "target_id",
    "target_name",
    "first_seen_at",
    "last_seen_at",
    "last_run_id",
    "occurrences",
    "last_status",
    "assigned_to",
    "retest_of_finding_id",
    "resolved_at",
}

DETAIL_FIELDS = SUMMARY_FIELDS | {
    "description",
    "expected",
    "observed",
    "reason",
    "facts",
    "evidence",
    "timeline",
    "remediation_guidance",
}

TIMELINE_FIELDS = {
    "id",
    "kind",
    "note",
    "created_at",
    "actor",
    "from_status",
    "to_status",
    "due_at",
}


def _seed_finding(
    db,
    n: int = 1,
    *,
    severity: Severity = Severity.HIGH,
    status: FindingStatus = FindingStatus.OPEN,
    due_at: datetime | None = None,
    title: str | None = None,
    assigned_to_user_id: int | None = None,
) -> dict:
    """Build the whole graph a finding needs and return the rows by name."""
    control = Control(
        key=f"ctl-{n}",
        title=f"Control {n}",
        category="headers",
        default_severity=severity,
        remediation=f"Fix control {n}.",
    )
    db.add(control)
    target = Target(
        name=f"target-{n}", target_type=TargetType.WEBAPP, host="127.0.0.1", port=9000 + n
    )
    db.add(target)
    db.flush()

    test = ValidationTest(
        key=f"test-{n}", name=f"Test {n}", control_id=control.id, current_version=1
    )
    db.add(test)
    db.flush()

    version = ValidationTestVersion(
        test_id=test.id,
        version=1,
        engine_id="http_headers",
        engine_params={},
        assertion={"fact": "http_header"},
        control_id=control.id,
        severity=severity,
    )
    db.add(version)
    db.flush()

    run = ValidationRun(
        test_id=test.id,
        test_version_id=version.id,
        target_id=target.id,
        engine_id="http_headers",
        status=RunStatus.FAILED,
    )
    db.add(run)
    db.flush()

    finding = Finding(
        fingerprint=f"fingerprint-{n}",
        title=title if title is not None else f"Control {n} missing on target-{n}",
        control_id=control.id,
        test_id=test.id,
        test_version_id=version.id,
        target_id=target.id,
        assertion_index=0,
        assertion={"fact": "http_header"},
        severity=severity,
        status=status,
        expected={"assertion": {"fact": "http_header"}},
        observed={"reason": "header not present"},
        detail=f"Control {n} was not satisfied.",
        last_failed_run_id=run.id,
        assigned_to_user_id=assigned_to_user_id,
        due_at=due_at,
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return {
        "control": control,
        "target": target,
        "test": test,
        "version": version,
        "run": run,
        "finding": finding,
    }


def _add_result(
    db,
    graph: dict,
    *,
    run: ValidationRun | None = None,
    status: AssertionStatus = AssertionStatus.FAIL,
    reason: str = "the header is absent",
    fact_ids: list[int] | None = None,
) -> AssertionResult:
    result = AssertionResult(
        run_id=(run or graph["run"]).id,
        test_version_id=graph["version"].id,
        target_id=graph["target"].id,
        control_id=graph["control"].id,
        assertion_index=0,
        assertion={"fact": "http_header"},
        status=status,
        severity=graph["finding"].severity,
        reason=reason,
        fact_ids=fact_ids,
    )
    db.add(result)
    db.commit()
    db.refresh(result)
    return result


def _actions(db, finding_id: int) -> list[RemediationAction]:
    return list(
        db.execute(
            select(RemediationAction)
            .where(RemediationAction.finding_id == finding_id)
            .order_by(RemediationAction.id)
        ).scalars()
    )


def _patch(client, finding_id: int, payload: dict):
    return client.patch(
        f"/api/findings/{finding_id}", json=payload, headers=csrf_headers(client)
    )


# ---------------------------------------------------------------------- auth --


def test_findings_require_authentication(client):
    for path in ("/api/findings", "/api/findings/summary", "/api/findings/1"):
        assert client.get(path).status_code == 401


def test_a_viewer_can_read_but_not_triage(viewer_user, admin_client, client, db):
    graph = _seed_finding(db, 1)
    finding_id = graph["finding"].id

    login(client, viewer_user.username)
    assert client.get("/api/findings").status_code == 200
    assert client.get("/api/findings/summary").status_code == 200
    assert client.get(f"/api/findings/{finding_id}").status_code == 200

    refused = _patch(client, finding_id, {"status": "resolved"})
    assert refused.status_code == 403
    refused = client.post(
        f"/api/findings/{finding_id}/retest", headers=csrf_headers(client)
    )
    assert refused.status_code == 403


def test_triage_and_retest_require_csrf(admin_client, db):
    graph = _seed_finding(db, 1)
    finding_id = graph["finding"].id
    assert admin_client.patch(
        f"/api/findings/{finding_id}", json={"status": "resolved"}
    ).status_code == 403
    assert admin_client.post(f"/api/findings/{finding_id}/retest").status_code == 403


# ---------------------------------------------------------------------- list --


def test_the_list_is_ordered_by_severity_then_recency(admin_client, db):
    low = _seed_finding(db, 1, severity=Severity.LOW)
    critical = _seed_finding(db, 2, severity=Severity.CRITICAL)
    older_high = _seed_finding(db, 3, severity=Severity.HIGH)
    newer_high = _seed_finding(db, 4, severity=Severity.HIGH)

    older_high["finding"].last_seen_at = datetime.now(UTC) - timedelta(hours=2)
    newer_high["finding"].last_seen_at = datetime.now(UTC) - timedelta(hours=1)
    db.commit()

    body = admin_client.get("/api/findings").json()
    assert body["total"] == 4
    assert [item["severity"] for item in body["items"]] == [
        "critical",
        "high",
        "high",
        "low",
    ]
    assert [item["id"] for item in body["items"][1:3]] == [
        newer_high["finding"].id,
        older_high["finding"].id,
    ]

    item = body["items"][0]
    assert set(item) == SUMMARY_FIELDS
    assert item["status"] == "open"
    assert item["title"] == "Control 2 missing on target-2"
    assert item["control_id"] == critical["control"].id
    assert item["control_key"] == "ctl-2"
    assert item["control_title"] == "Control 2"
    assert item["test_id"] == critical["test"].id
    assert item["test_key"] == "test-2"
    assert item["target_id"] == critical["target"].id
    assert item["target_name"] == "target-2"
    assert item["last_run_id"] == critical["run"].id
    assert item["occurrences"] == 0
    assert item["last_status"] is None
    assert item["assigned_to"] is None
    assert item["retest_of_finding_id"] is None
    assert item["resolved_at"] is None


def test_the_list_obeys_every_filter(admin_client, db):
    high_open = _seed_finding(db, 1, severity=Severity.HIGH)
    low_triaged = _seed_finding(db, 2, severity=Severity.LOW, status=FindingStatus.TRIAGED)
    critical_resolved = _seed_finding(
        db, 3, severity=Severity.CRITICAL, status=FindingStatus.RESOLVED
    )

    def ids(query: str) -> list[int]:
        body = admin_client.get(f"/api/findings?{query}").json()
        return [item["id"] for item in body["items"]]

    assert ids("status=open") == [high_open["finding"].id]
    assert ids("status=triaged") == [low_triaged["finding"].id]
    assert ids("severity=critical") == [critical_resolved["finding"].id]
    assert ids(f"target_id={low_triaged['target'].id}") == [low_triaged["finding"].id]
    assert ids(f"control_id={critical_resolved['control'].id}") == [
        critical_resolved["finding"].id
    ]
    assert ids(f"test_id={high_open['test'].id}") == [high_open["finding"].id]
    # substring, case-insensitive, on the title only
    assert ids("q=TARGET-2") == [low_triaged["finding"].id]
    assert ids("q=missing") == [
        critical_resolved["finding"].id,
        high_open["finding"].id,
        low_triaged["finding"].id,
    ]

    page = admin_client.get("/api/findings?limit=1&offset=1").json()
    assert page["total"] == 3
    assert [item["id"] for item in page["items"]] == [high_open["finding"].id]


def test_nonsense_filters_are_refused(admin_client):
    for query in ("status=nonsense", "severity=urgent", "limit=500", "limit=0", "offset=-1"):
        assert admin_client.get(f"/api/findings?{query}").status_code == 422, query


# ------------------------------------------------------------------- summary --


def test_the_summary_counts_open_and_overdue_findings(admin_client, db):
    now = datetime.now(UTC)
    _seed_finding(db, 1, severity=Severity.HIGH, due_at=now - timedelta(days=1))
    _seed_finding(
        db, 2, severity=Severity.LOW, status=FindingStatus.TRIAGED, due_at=now + timedelta(days=1)
    )
    _seed_finding(
        db,
        3,
        severity=Severity.CRITICAL,
        status=FindingStatus.RESOLVED,
        due_at=now - timedelta(days=1),
    )
    _seed_finding(db, 4, severity=Severity.INFO)

    body = admin_client.get("/api/findings/summary").json()
    assert body["by_severity"] == {
        "info": 1,
        "low": 1,
        "medium": 0,
        "high": 1,
        "critical": 1,
    }
    assert body["by_status"] == {
        "open": 2,
        "triaged": 1,
        "remediating": 0,
        "accepted_risk": 0,
        "false_positive": 0,
        "resolved": 1,
    }
    # open-ish = open/triaged/remediating; the overdue clock only runs on those
    assert body["open_total"] == 3
    assert body["overdue_total"] == 1


# -------------------------------------------------------------------- triage --


def test_a_status_change_updates_the_row_and_the_timeline(
    admin_client, db, admin_user
):
    graph = _seed_finding(db, 1, due_at=(datetime.now(UTC) - timedelta(days=1)).replace(microsecond=0))
    finding_id = graph["finding"].id

    response = _patch(admin_client, finding_id, {"status": "resolved"})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "resolved"
    assert body["resolved_at"] is not None
    assert set(body) == DETAIL_FIELDS

    db.refresh(graph["finding"])
    assert graph["finding"].status is FindingStatus.RESOLVED
    assert graph["finding"].resolved_at is not None

    actions = _actions(db, finding_id)
    assert len(actions) == 1
    assert actions[0].kind is RemediationActionKind.STATUS_CHANGE
    assert actions[0].from_status is FindingStatus.OPEN
    assert actions[0].to_status is FindingStatus.RESOLVED
    assert actions[0].user_id == admin_user.id

    entry = body["timeline"][-1]
    assert set(entry) == TIMELINE_FIELDS
    assert entry["kind"] == "status_change"
    assert entry["from_status"] == "open"
    assert entry["to_status"] == "resolved"
    assert entry["actor"] == "admin"
    assert datetime.fromisoformat(entry["due_at"].replace("Z", "+00:00")) == graph[
        "finding"
    ].due_at

    # A close keeps its date when the finding is reopened; an open->open move
    # must not carry a stale close time.
    assert _patch(admin_client, finding_id, {"status": "open"}).status_code == 200
    db.refresh(graph["finding"])
    assert graph["finding"].resolved_at is not None

    assert _patch(admin_client, finding_id, {"status": "triaged"}).status_code == 200
    db.refresh(graph["finding"])
    assert graph["finding"].resolved_at is None
    assert len(_actions(db, finding_id)) == 3


def test_a_note_alone_still_records_an_action(admin_client, db):
    graph = _seed_finding(db, 1)
    finding_id = graph["finding"].id

    response = _patch(admin_client, finding_id, {"note": "Waiting on the platform team"})
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "open"

    db.refresh(graph["finding"])
    assert graph["finding"].status is FindingStatus.OPEN
    actions = _actions(db, finding_id)
    assert [(action.kind, action.note) for action in actions] == [
        (RemediationActionKind.COMMENT, "Waiting on the platform team")
    ]
    assert response.json()["timeline"][-1]["note"] == "Waiting on the platform team"

    audit_row = db.execute(
        select(AuditLog).where(AuditLog.action == "finding.update")
    ).scalar_one()
    assert audit_row.object_id == str(finding_id)
    assert audit_row.after["note"] == "Waiting on the platform team"


def test_severity_and_assignment_changes_get_their_own_actions(
    admin_client, db, admin_user
):
    graph = _seed_finding(db, 1)
    finding_id = graph["finding"].id

    body = _patch(
        admin_client, finding_id, {"severity": "critical", "assigned_to": admin_user.id}
    ).json()
    assert body["severity"] == "critical"
    assert body["assigned_to"] == admin_user.id

    actions = _actions(db, finding_id)
    assert [action.kind for action in actions] == [
        RemediationActionKind.COMMENT,
        RemediationActionKind.ASSIGNMENT,
    ]
    assert "high" in actions[0].note and "critical" in actions[0].note
    assert actions[1].detail == {"assigned_to_user_id": admin_user.id}

    # An explicit null unassigns.
    body = _patch(admin_client, finding_id, {"assigned_to": None}).json()
    assert body["assigned_to"] is None
    assert _actions(db, finding_id)[-1].note == "unassigned"


def test_nonsense_triage_updates_are_refused(admin_client, db):
    graph = _seed_finding(db, 1)
    finding_id = graph["finding"].id
    assert _patch(admin_client, finding_id, {"status": "nonsense"}).status_code == 422
    assert _patch(admin_client, finding_id, {"severity": "urgent"}).status_code == 422
    assert _patch(admin_client, finding_id, {"typo_field": 1}).status_code == 422
    assert _patch(admin_client, finding_id, {"assigned_to": 999_999}).status_code == 400
    assert _actions(db, finding_id) == []


# -------------------------------------------------------------------- retest --


def test_retest_queues_one_run_and_refuses_a_second(admin_client, db, admin_user):
    graph = _seed_finding(db, 1)
    finding_id = graph["finding"].id

    response = admin_client.post(
        f"/api/findings/{finding_id}/retest", headers=csrf_headers(admin_client)
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert set(body) == {"run_id"}

    run = db.get(ValidationRun, body["run_id"])
    assert run is not None
    assert run.status is RunStatus.QUEUED
    assert run.trigger is TriggerKind.RETEST
    assert run.retest_of_finding_id == finding_id
    assert run.test_id == graph["test"].id
    assert run.test_version_id == graph["version"].id
    assert run.target_id == graph["target"].id
    assert run.engine_id == "http_headers"
    assert run.timeout_seconds == get_engine("http_headers").default_timeout
    assert run.authorized_by_user_id == admin_user.id

    again = admin_client.post(
        f"/api/findings/{finding_id}/retest", headers=csrf_headers(admin_client)
    )
    assert again.status_code == 409
    assert "already queued or running" in again.json()["detail"]
    assert len(
        list(
            db.execute(
                select(ValidationRun).where(ValidationRun.retest_of_finding_id == finding_id)
            ).scalars()
        )
    ) == 1

    audit_row = db.execute(
        select(AuditLog).where(AuditLog.action == "finding.retest")
    ).scalar_one()
    assert audit_row.after["run_id"] == run.id

    # Once the first run is out of the way, a retest may be queued again.
    run.status = RunStatus.CANCELLED
    db.commit()
    retried = admin_client.post(
        f"/api/findings/{finding_id}/retest", headers=csrf_headers(admin_client)
    )
    assert retried.status_code == 200
    assert retried.json()["run_id"] != run.id


def test_retest_uses_the_tests_current_version(admin_client, db):
    graph = _seed_finding(db, 1)
    newer = ValidationTestVersion(
        test_id=graph["test"].id,
        version=2,
        engine_id="http_headers",
        engine_params={},
        assertion={"fact": "http_header"},
        control_id=graph["control"].id,
        severity=Severity.HIGH,
    )
    db.add(newer)
    graph["test"].current_version = 2
    db.commit()

    body = admin_client.post(
        f"/api/findings/{graph['finding'].id}/retest",
        headers=csrf_headers(admin_client),
    ).json()
    run = db.get(ValidationRun, body["run_id"])
    assert run.test_version_id == newer.id


# -------------------------------------------------------------------- detail --


def test_the_detail_carries_the_assertion_facts_and_evidence(admin_client, db):
    graph = _seed_finding(db, 1)
    run = graph["run"]
    other_evidence = Evidence(
        run_id=run.id,
        kind=EvidenceKind.STDOUT,
        filename="stdout.txt",
        rel_path="runs/1/stdout.txt",
        sha256="a" * 64,
        size_bytes=10,
        mime="text/plain",
    )
    fact_evidence = Evidence(
        run_id=run.id,
        kind=EvidenceKind.ARTIFACT,
        filename="headers.txt",
        rel_path="runs/1/headers.txt",
        sha256="b" * 64,
        size_bytes=20,
        mime="text/plain",
    )
    db.add_all([other_evidence, fact_evidence])
    db.flush()

    fact_a = Fact(
        run_id=run.id,
        target_id=graph["target"].id,
        fact_type="http_header",
        subject="https://127.0.0.1:9001",
        key="strict-transport-security",
        value={"name": "strict-transport-security"},
        confidence=0.9,
        detail="header absent",
        evidence_id=fact_evidence.id,
    )
    fact_b = Fact(
        run_id=run.id,
        target_id=graph["target"].id,
        fact_type="http_response",
        subject="https://127.0.0.1:9001",
        key="status",
        value={"status": 200},
    )
    db.add_all([fact_a, fact_b])
    db.flush()
    _add_result(db, graph, reason="the header is absent", fact_ids=[fact_b.id, fact_a.id])
    db.commit()

    body = admin_client.get(f"/api/findings/{graph['finding'].id}").json()
    assert set(body) == DETAIL_FIELDS
    assert body["description"] == "Control 1 was not satisfied."
    assert body["expected"] == {"assertion": {"fact": "http_header"}}
    assert body["observed"] == {"reason": "header not present"}
    assert body["reason"] == "the header is absent"
    assert body["remediation_guidance"] == "Fix control 1."
    assert body["occurrences"] == 1
    assert body["last_status"] == "fail"
    assert body["timeline"] == []

    # Facts come back in the order the assertion referenced them.
    assert [fact["id"] for fact in body["facts"]] == [fact_b.id, fact_a.id]
    assert set(body["facts"][0]) == {
        "id",
        "fact_type",
        "subject",
        "key",
        "value",
        "confidence",
        "detail",
        "evidence_id",
    }
    assert body["facts"][1]["evidence_id"] == fact_evidence.id

    # Evidence referenced by the assertion's facts wins over the run's whole set.
    assert [item["id"] for item in body["evidence"]] == [fact_evidence.id]
    assert set(body["evidence"][0]) == {
        "id",
        "run_id",
        "kind",
        "filename",
        "sha256",
        "size_bytes",
        "mime",
        "truncated",
        "created_at",
        "detail",
    }


def test_evidence_falls_back_to_the_run_when_no_fact_references_any(admin_client, db):
    graph = _seed_finding(db, 1)
    first = Evidence(
        run_id=graph["run"].id,
        kind=EvidenceKind.STDOUT,
        filename="stdout.txt",
        rel_path="runs/1/stdout.txt",
        sha256="a" * 64,
        size_bytes=10,
        mime="text/plain",
    )
    second = Evidence(
        run_id=graph["run"].id,
        kind=EvidenceKind.STDERR,
        filename="stderr.txt",
        rel_path="runs/1/stderr.txt",
        sha256="c" * 64,
        size_bytes=4,
        mime="text/plain",
    )
    db.add_all([first, second])
    db.commit()
    _add_result(db, graph, fact_ids=None)

    body = admin_client.get(f"/api/findings/{graph['finding'].id}").json()
    assert [item["id"] for item in body["evidence"]] == [first.id, second.id]
    assert body["facts"] == []
    assert body["reason"] == "the header is absent"


def test_a_resolved_finding_reports_the_run_that_closed_it(admin_client, db):
    graph = _seed_finding(db, 1, status=FindingStatus.RESOLVED)
    resolving_run = ValidationRun(
        test_id=graph["test"].id,
        test_version_id=graph["version"].id,
        target_id=graph["target"].id,
        engine_id="http_headers",
        status=RunStatus.PASSED,
        trigger=TriggerKind.RETEST,
    )
    db.add(resolving_run)
    db.flush()
    graph["finding"].resolved_by_run_id = resolving_run.id
    graph["finding"].resolved_at = datetime.now(UTC)
    db.add(
        AssertionResult(
            run_id=resolving_run.id,
            test_version_id=graph["version"].id,
            target_id=graph["target"].id,
            control_id=graph["control"].id,
            assertion_index=0,
            assertion={"fact": "http_header"},
            status=AssertionStatus.PASS,
            severity=Severity.HIGH,
            reason="the header is present",
        )
    )
    db.commit()

    body = admin_client.get(f"/api/findings/{graph['finding'].id}").json()
    assert body["last_run_id"] == resolving_run.id
    assert body["last_status"] == "pass"
    assert body["occurrences"] == 0
    assert body["resolved_at"] is not None


def test_an_unknown_finding_is_a_404(admin_client):
    assert admin_client.get("/api/findings/999999").status_code == 404
    assert _patch(admin_client, 999999, {"status": "resolved"}).status_code == 404
    assert (
        admin_client.post(
            "/api/findings/999999/retest", headers=csrf_headers(admin_client)
        ).status_code
        == 404
    )
