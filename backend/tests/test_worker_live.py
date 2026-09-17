"""End-to-end: a run goes in, and a finding comes out - then closes again.

These tests drive the real worker against the real lab containers, and read the
result back out of the database and off the disk. Everything below the queue is
exercised: authorization against a stored scope, the engine subprocess, the
evidence store, the tri-state evaluator and the finding lifecycle.

They are skipped when the lab is not running, because a platform that validates
controls needs something to validate, and a test that quietly passes with no
target would be exactly the kind of empty green this platform exists to avoid.
"""

from __future__ import annotations

import socket
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from app.config import get_settings
from app.core import findings as findings_engine
from app.core.evidence import EvidenceError, read as read_evidence
from app.models.enums import (
    AssertionStatus,
    EvidenceKind,
    FindingStatus,
    RunStatus,
    ScopeEntryKind,
    Severity,
    TargetType,
)
from app.models.findings import Finding
from app.models.facts import AssertionResult, Fact
from app.models.registry import Control, Scope, ScopeEntry, Setting, Target, TargetScope
from app.models.testing import Evidence, RunLog, ValidationRun, ValidationTest, ValidationTestVersion
from app.queue import jobs
from app.runner.worker import Worker

LAB_HOST = "127.0.0.1"
LAB_HEADERS_PORT = 8081
LAB_WEBAPP_PORT = 8082
ABSENT_HEADER = "x-valtros-probe"

# The assertion that fails against the lab's header target no matter how that
# container is configured: it asks for a header nothing would ever send.
REQUIRE_ABSENT = {"fact": "http_header", "op": "exists", "where": {"key": ABSENT_HEADER}}
ALLOW_ABSENT = {"fact": "http_header", "op": "not_exists", "where": {"key": ABSENT_HEADER}}


def _reachable(port: int) -> bool:
    try:
        with socket.create_connection((LAB_HOST, port), timeout=1.0):
            return True
    except OSError:
        return False


requires_lab = pytest.mark.skipif(
    not _reachable(LAB_HEADERS_PORT),
    reason="the local test lab is not running (scripts/lab_up.sh)",
)


@pytest.fixture
def domain(db, admin_user) -> SimpleNamespace:
    """A control, a scoped lab target and an enabled test - the whole graph."""
    control = Control(
        key="CF-TEST-HEADERS",
        title="Responses carry the required header",
        category="network",
        default_severity=Severity.MEDIUM,
    )
    target = Target(
        name="lab-headers",
        target_type=TargetType.WEBAPP,
        host=LAB_HOST,
        port=LAB_HEADERS_PORT,
        protocol="http",
        tags=["lab"],
    )
    scope = Scope(
        name="lab-loopback",
        description="The platform's own lab targets, listening on loopback.",
        is_lab=True,
        active=True,
    )
    db.add_all([control, target, scope])
    db.flush()
    db.add(
        ScopeEntry(
            scope_id=scope.id,
            kind=ScopeEntryKind.HOST,
            value=LAB_HOST,
            ports=str(LAB_HEADERS_PORT),
            protocol="tcp",
            note="the lab's header target",
        )
    )
    db.add(TargetScope(target_id=target.id, scope_id=scope.id))
    test = ValidationTest(
        key="cf-test-headers-present",
        name="Required header is present",
        control_id=control.id,
        tags=["lab"],
    )
    db.add(test)
    db.commit()
    return SimpleNamespace(control=control, target=target, scope=scope, test=test)


def _add_version(db, domain, assertion: dict, *, note: str | None = None) -> ValidationTestVersion:
    test = db.get(ValidationTest, domain.test.id)
    version = ValidationTestVersion(
        test_id=test.id,
        version=test.current_version,
        engine_id="http_headers",
        engine_params={},
        assertion=assertion,
        control_id=domain.control.id,
        severity=Severity.MEDIUM,
        note=note,
    )
    db.add(version)
    db.flush()
    test.current_version = version.version + 1
    db.commit()
    return version


def _enqueue(db, domain, version, *, timeout_seconds: int = 60) -> int:
    run = jobs.enqueue(
        db,
        test_id=version.test_id,
        test_version_id=version.id,
        target_id=domain.target.id,
        engine_id="http_headers",
        timeout_seconds=timeout_seconds,
    )
    db.commit()
    return run.id


def _run_worker() -> bool:
    return Worker(settings=get_settings(), worker_id="test-worker").run_once()


@requires_lab
def test_a_failing_validation_opens_a_finding_and_the_fix_closes_it(db, admin_user, domain):
    # --- the control is violated: the header the assertion requires is absent
    failing = _add_version(db, domain, REQUIRE_ABSENT, note="initial validation")
    run_id = _enqueue(db, domain, failing)

    assert _run_worker() is True

    db.expire_all()
    run = db.get(ValidationRun, run_id)
    assert run.status is RunStatus.FAILED, run.error_message

    # The safety record: which addresses were authorized, and by which rules.
    assert run.resolved_ips == [LAB_HOST]
    assert run.scope_snapshot["matched_rules"] == ["lab-loopback:host:127.0.0.1"]
    assert run.exit_code is None  # a Python engine, not a subprocess

    facts = db.execute(select(Fact).where(Fact.run_id == run_id)).scalars().all()
    assert facts, "the engine reported no facts at all"
    assert all(f.confidence == 1.0 for f in facts)
    assert {f.fact_type for f in facts} <= {"http_response", "http_header", "http_cookie"}

    result = db.execute(
        select(AssertionResult).where(AssertionResult.run_id == run_id)
    ).scalar_one()
    assert result.status is AssertionStatus.FAIL
    assert result.severity is Severity.MEDIUM
    assert ABSENT_HEADER in result.reason

    # Every fact is traceable: it points at stored evidence, and that evidence
    # still hashes to what was recorded.
    assert all(fact.evidence_id is not None for fact in facts)
    evidence = db.execute(select(Evidence).where(Evidence.run_id == run_id)).scalars().all()
    assert evidence
    for item in evidence:
        payload, check = read_evidence(item, get_settings())
        assert check.intact, f"evidence {item.rel_path} does not verify"
        assert payload
    assert {fact.evidence_id for fact in facts} <= {item.id for item in evidence}

    finding = db.execute(
        select(Finding).where(Finding.test_id == domain.test.id)
    ).scalar_one()
    assert finding.status is FindingStatus.OPEN
    assert finding.severity is Severity.MEDIUM
    assert finding.last_failed_run_id == run_id
    assert finding.fingerprint == findings_engine.fingerprint(domain.test.id, domain.target.id)

    log_text = "\n".join(
        db.execute(select(RunLog.message).where(RunLog.run_id == run_id)).scalars()
    )
    assert "authorized:" in log_text

    # --- the control is fixed, and a new version of the test says so
    passing = _add_version(db, domain, ALLOW_ABSENT, note="after the header was added")
    retest_id = _enqueue(db, domain, passing)

    assert _run_worker() is True

    db.expire_all()
    retest = db.get(ValidationRun, retest_id)
    assert retest.status is RunStatus.PASSED, retest.error_message

    finding = db.get(Finding, finding.id)
    assert finding.status is FindingStatus.RESOLVED
    assert finding.resolved_by_run_id == retest_id
    assert finding.test_version_id == passing.id, "the finding should cite the version that resolved it"


@requires_lab
def test_a_finding_that_fails_again_reopens(db, admin_user, domain):
    failing = _add_version(db, domain, REQUIRE_ABSENT)
    _enqueue(db, domain, failing)
    assert _run_worker() is True

    db.expire_all()
    finding = db.execute(select(Finding).where(Finding.test_id == domain.test.id)).scalar_one()
    finding.status = FindingStatus.RESOLVED
    db.commit()

    _enqueue(db, domain, failing)
    assert _run_worker() is True

    db.expire_all()
    finding = db.get(Finding, finding.id)
    assert finding.status is FindingStatus.OPEN
    assert finding.resolved_at is None


@requires_lab
def test_a_target_with_no_scope_is_refused_and_the_run_records_why(db, admin_user, domain):
    unscoped = Target(
        name="lab-unscoped",
        target_type=TargetType.WEBAPP,
        host=LAB_HOST,
        port=LAB_WEBAPP_PORT,
        protocol="http",
        tags=["lab"],
    )
    db.add(unscoped)
    db.commit()

    version = _add_version(db, domain, ALLOW_ABSENT)
    run = jobs.enqueue(
        db,
        test_id=version.test_id,
        test_version_id=version.id,
        target_id=unscoped.id,
        engine_id="http_headers",
        timeout_seconds=30,
    )
    db.commit()

    assert _run_worker() is True

    db.expire_all()
    finished = db.get(ValidationRun, run.id)
    assert finished.status is RunStatus.ERROR
    assert "no active scope authorizes" in finished.error_message
    assert finished.resolved_ips is None, "a refused run must not record an authorization it never had"
    assert db.execute(select(Fact).where(Fact.run_id == run.id)).scalars().all() == []


@requires_lab
def test_a_disabled_test_is_not_run(db, admin_user, domain):
    version = _add_version(db, domain, ALLOW_ABSENT)
    run_id = _enqueue(db, domain, version)

    test = db.get(ValidationTest, domain.test.id)
    test.enabled = False
    db.commit()

    assert _run_worker() is True

    db.expire_all()
    run = db.get(ValidationRun, run_id)
    assert run.status is RunStatus.CANCELLED
    assert "disabled" in run.error_message


@requires_lab
def test_the_kill_switch_stops_new_runs(db, admin_user, domain):
    version = _add_version(db, domain, ALLOW_ABSENT)
    run_id = _enqueue(db, domain, version)

    db.add(Setting(key="kill_switch", value={"value": True}))
    db.commit()

    assert _run_worker() is False

    db.expire_all()
    assert db.get(ValidationRun, run_id).status is RunStatus.QUEUED


@requires_lab
def test_evidence_that_cannot_be_stored_fails_the_run(db, admin_user, domain, monkeypatch):
    """An evaluation whose evidence is missing must not be reported as an observation."""
    from app.core.evidence import EvidenceError
    from app.runner import worker as worker_module

    def explode(*args, **kwargs):
        raise EvidenceError("the evidence store is read-only")

    monkeypatch.setattr(worker_module, "store_bytes", explode)

    version = _add_version(db, domain, ALLOW_ABSENT)
    run_id = _enqueue(db, domain, version)
    assert _run_worker() is True

    db.expire_all()
    run = db.get(ValidationRun, run_id)
    assert run.status is RunStatus.ERROR
    assert "evidence could not be stored" in run.error_message
    assert db.execute(select(Fact).where(Fact.run_id == run_id)).scalars().all() == []
    assert (
        db.execute(select(AssertionResult).where(AssertionResult.run_id == run_id)).scalar_one_or_none()
        is None
    ), "no verdict may be recorded for a run whose evidence is missing"


def test_a_failed_engine_still_records_the_tool_it_ran(db, admin_user, domain, monkeypatch):
    """A run that fails is the run whose command line and tool version matter
    most, so an engine that got as far as running its tool hands that back with
    the failure instead of dropping it. The captured output is kept too: it is
    usually the only account of why the tool gave up."""
    from app.engines.context import EngineError, EngineResult
    from app.runner import worker as worker_module

    def explode(*args, **kwargs):
        partial = EngineResult(argv=["testssl", "--quiet", "--ip", "127.0.0.1", "lab:8443"])
        partial.stdout = "testssl was starting its checks when it was stopped"
        partial.tool_versions["testssl"] = "testssl version 3.2.4 from https://testssl.sh/"
        raise EngineError("testssl was stopped at its 120s budget", result=partial)

    monkeypatch.setattr(worker_module, "run_engine", explode)

    version = _add_version(db, domain, ALLOW_ABSENT)
    run_id = _enqueue(db, domain, version)
    assert _run_worker() is True

    db.expire_all()
    run = db.get(ValidationRun, run_id)
    assert run.status is RunStatus.ERROR
    assert run.error_message == "testssl was stopped at its 120s budget"
    assert run.argv == ["testssl", "--quiet", "--ip", "127.0.0.1", "lab:8443"]
    assert run.tool_versions == {"testssl": "testssl version 3.2.4 from https://testssl.sh/"}
    assert run.finished_at is not None

    captures = db.execute(select(Evidence).where(Evidence.run_id == run_id)).scalars().all()
    stored = next(entry for entry in captures if entry.kind is EvidenceKind.STDOUT)
    payload, check = read_evidence(stored, get_settings())
    assert b"stopped" in payload
    assert check.intact, "the capture of a failed run is still evidence and must verify"
