"""Turning evaluation outcomes into findings, and closing them again.

A finding is not an observation, it is a *state*: "this control is not satisfied
on this target". It has to survive being observed a hundred more times, and it
has to close by itself when the control starts holding - otherwise the list
becomes a log, and a log is not a work queue.

Three rules give it that shape:

* **one finding per (test, target, assertion)**, found by fingerprint, so a run
  every hour does not create an hourly duplicate. The fingerprint is built from
  the test rather than the test *version*: tightening an assertion is not a
  different weakness, and the finding records which version last observed it;
* **a failure reopens what a fix closed.** A finding that was resolved and then
  fails again is a regression, and it says so in its timeline;
* **a pass resolves what a failure opened** - but an INCONCLUSIVE observation
  changes nothing. Deciding a finding is gone because a tool could not read the
  response is the exact mistake this platform exists to prevent.
"""

from __future__ import annotations

import hashlib

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.assertions import AssertionOutcome
from app.models.enums import (
    AssertionStatus,
    FindingStatus,
    RemediationActionKind,
    RunStatus,
)
from app.models.findings import Finding, RemediationAction
from app.models.registry import Control, Target
from app.models.testing import ValidationRun, ValidationTest, ValidationTestVersion

# Bumped if the fingerprint recipe ever changes, so old findings can be told
# apart from new ones instead of silently merging with them.
FINGERPRINT_NAMESPACE = "cf-finding-v1"


def fingerprint(test_id: int, target_id: int, assertion_index: int = 0) -> str:
    material = f"{FINGERPRINT_NAMESPACE}:{test_id}:{target_id}:{assertion_index}"
    return hashlib.sha256(material.encode()).hexdigest()


def _title(control: Control, target: Target) -> str:
    return f"{control.key}: {control.title} — {target.name}"


def _action(
    session: Session,
    finding: Finding,
    *,
    kind: RemediationActionKind,
    note: str,
    from_status: FindingStatus | None = None,
    to_status: FindingStatus | None = None,
    user_id: int | None = None,
    detail: dict | None = None,
) -> None:
    session.add(
        RemediationAction(
            finding_id=finding.id,
            user_id=user_id,
            kind=kind,
            from_status=from_status,
            to_status=to_status,
            note=note,
            detail=detail,
        )
    )


def _open_finding(
    session: Session,
    *,
    fingerprint_value: str,
    run: ValidationRun,
    version: ValidationTestVersion,
    control: Control,
    target: Target,
    outcome: AssertionOutcome,
) -> Finding:
    finding = Finding(
        fingerprint=fingerprint_value,
        title=_title(control, target),
        control_id=version.control_id,
        test_id=run.test_id,
        test_version_id=version.id,
        target_id=run.target_id,
        assertion_index=0,
        assertion=version.assertion,
        severity=outcome.severity,
        status=FindingStatus.OPEN,
        expected={"assertion": version.assertion},
        observed={"reason": outcome.reason, "matched_facts": outcome.matched},
        detail=outcome.reason,
        last_failed_run_id=run.id,
        retest_of_finding_id=run.retest_of_finding_id,
    )
    session.add(finding)
    session.flush()
    _action(
        session,
        finding,
        kind=RemediationActionKind.STATUS_CHANGE,
        note=f"opened by run {run.id}: {outcome.reason}"[:2000],
        to_status=FindingStatus.OPEN,
        detail={"run_id": run.id},
    )
    return finding


def record_outcome(
    session: Session,
    *,
    run: ValidationRun,
    version: ValidationTestVersion,
    control: Control,
    target: Target,
    outcome: AssertionOutcome,
    assertion_index: int = 0,
) -> Finding | None:
    """Apply one assertion outcome to the finding for this test and target.

    Returns the finding that changed, if any.
    """
    finger = fingerprint(run.test_id, run.target_id, assertion_index)

    if outcome.status is AssertionStatus.FAIL:
        finding = session.execute(
            select(Finding).where(Finding.fingerprint == finger)
        ).scalar_one_or_none()

        if finding is None:
            return _open_finding(
                session,
                fingerprint_value=finger,
                run=run,
                version=version,
                control=control,
                target=target,
                outcome=outcome,
            )

        previous = finding.status
        finding.last_seen_at = run.started_at or run.queued_at
        finding.last_failed_run_id = run.id
        finding.test_version_id = version.id
        finding.assertion = version.assertion
        finding.severity = outcome.severity
        finding.expected = {"assertion": version.assertion}
        finding.observed = {"reason": outcome.reason, "matched_facts": outcome.matched}
        finding.detail = outcome.reason

        if previous is FindingStatus.RESOLVED:
            # Seen failing again after a fix: that is a regression, and the
            # finding goes back to open with the history intact.
            finding.status = FindingStatus.OPEN
            finding.resolved_at = None
            finding.resolved_by_run_id = None
            _action(
                session,
                finding,
                kind=RemediationActionKind.STATUS_CHANGE,
                note=f"reopened by run {run.id}: the control failed again"[:2000],
                from_status=previous,
                to_status=FindingStatus.OPEN,
                detail={"run_id": run.id},
            )
        elif previous in (FindingStatus.ACCEPTED_RISK, FindingStatus.FALSE_POSITIVE):
            # A decision was recorded about this finding. A machine observation
            # does not get to overrule a human's risk decision, so the state
            # stands; the run is noted in the timeline for whoever reviews it.
            _action(
                session,
                finding,
                kind=RemediationActionKind.COMMENT,
                note=f"run {run.id} failed again while this finding is {previous.value}"[:2000],
                detail={"run_id": run.id},
            )
        else:
            _action(
                session,
                finding,
                kind=RemediationActionKind.COMMENT,
                note=f"observed failing again by run {run.id}"[:2000],
                detail={"run_id": run.id},
            )
        return finding

    if outcome.status is not AssertionStatus.PASS:
        # INCONCLUSIVE and NOT_APPLICABLE leave the finding exactly as it was.
        return None

    resolved: Finding | None = None
    finding = session.execute(
        select(Finding).where(Finding.fingerprint == finger)
    ).scalar_one_or_none()
    if finding is not None and not finding.status.is_closed:
        resolved = finding
    elif run.retest_of_finding_id is not None:
        # A retest can be attached to a specific finding; resolve that one even
        # if the fingerprint moved (the test may have been edited since).
        retested = session.get(Finding, run.retest_of_finding_id)
        if retested is not None and not retested.status.is_closed:
            resolved = retested

    if resolved is None:
        return None

    previous = resolved.status
    resolved.status = FindingStatus.RESOLVED
    resolved.resolved_at = run.finished_at or run.started_at or run.queued_at
    resolved.resolved_by_run_id = run.id
    # The version that observed the failure and the version that observed the
    # fix are both worth knowing; this column always holds the most recent one.
    resolved.test_version_id = version.id
    _action(
        session,
        resolved,
        kind=RemediationActionKind.STATUS_CHANGE,
        note=f"resolved by run {run.id}: the control now holds"[:2000],
        from_status=previous,
        to_status=FindingStatus.RESOLVED,
        detail={"run_id": run.id},
    )
    return resolved


def status_for_run(outcome: AssertionOutcome, *, execution_failed: bool = False) -> RunStatus:
    """The run status a given outcome produces.

    An execution failure is reported as an error rather than as the assertion's
    result, because there is no assertion result to report. An INCONCLUSIVE
    outcome gets its own run status rather than being folded into passed: a run
    that observed nothing must not appear alongside runs that found the control
    in place.
    """
    if execution_failed:
        return RunStatus.ERROR
    if outcome.status is AssertionStatus.PASS:
        return RunStatus.PASSED
    if outcome.status is AssertionStatus.FAIL:
        return RunStatus.FAILED
    if outcome.status is AssertionStatus.NOT_APPLICABLE:
        return RunStatus.NOT_APPLICABLE
    return RunStatus.INCONCLUSIVE
