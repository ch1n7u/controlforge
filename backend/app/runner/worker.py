"""The worker: one run at a time, from a claim to a finding.

This is where the pieces meet. A claim comes off the queue, the authorization
is checked *again, now* rather than trusted from when the run was queued, the
engine runs under a lease the worker keeps renewing, and what comes back is
turned into facts, evidence, an assertion result and - if the control did not
hold - a finding.

The ordering inside a run is deliberate:

1. **authorize, then execute.** The scope rules are read from the database
   immediately before the tool starts. A run that was authorized when it was
   queued is not authorized now; a scope that was narrowed in between must stop
   this run, and re-reading is the only way to know.
2. **evidence before verdict.** The captured output is written and hashed
   before the assertion is evaluated, so every evaluation can be traced back to
   bytes that were recorded, not to bytes that existed only in memory.
3. **evaluate against stored facts.** The assertion sees the fact *rows*, so
   what it was evaluated against is exactly what an auditor can query
   afterwards.

The long-lived parts - the subprocess, the clock - never run inside a database
transaction. Sessions are opened for the load, for each log flush, and for the
persist, and are closed in between; a run that takes ten minutes holds a
connection for a few hundred milliseconds of it.
"""

from __future__ import annotations

import json
import logging
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.core import findings as findings_engine
from app.core.assertions import AssertionOutcome, AssertionStatus, evaluate
from app.core.evidence import EvidenceError, store_bytes
from app.db import AdvisoryLock, engine, session_scope
from app.engines.context import (
    EngineContext,
    EngineError,
    EngineResult,
    TargetView,
)
from app.engines.runtime import run_engine
from app.models.enums import EvidenceKind, RunStatus, TargetType
from app.models.facts import AssertionResult, Fact
from app.models.registry import Control, Target
from app.models.testing import ValidationRun, ValidationTest, ValidationTestVersion
from app.queue import jobs
from app.scope.authorize import authorize
from app.scope.load import ScopeLoadError, active_rules_for_target

logger = logging.getLogger("controlforge.worker")

# Tool output can be chatty; batching keeps the run log from costing one
# transaction per line while still showing progress during a long scan.
LOG_FLUSH_SECONDS = 0.5
LOG_MESSAGE_MAX_CHARS = 1900

# How often the in-flight run checks whether it has been cancelled. Cheap - one
# small SELECT - and it is also the tick that flushes buffered output.
CANCEL_POLL_SECONDS = 1.0


class RunSkipped(RuntimeError):
    """The run was not started, with the status and reason already decided."""

    def __init__(self, status: RunStatus, message: str) -> None:
        super().__init__(message)
        self.status = status


@dataclass
class _Plan:
    """Everything a run needs, loaded in one short transaction."""

    run: ValidationRun
    test: ValidationTest
    version: ValidationTestVersion
    control: Control
    target: Target
    view: TargetView
    scope_snapshot: dict
    resolved_ips: list[str]


class LogSink:
    """Buffers run output and writes it to ``run_logs`` in small batches."""

    def __init__(self, run_id: int, max_lines: int) -> None:
        self.run_id = run_id
        self.max_lines = max_lines
        self._pending: list[tuple[str, str, str]] = []
        self._partial = {"stdout": "", "stderr": ""}
        self._written = 0
        self._dropped = 0
        self._last_flush = time.monotonic()

    def system(self, level: str, message: str) -> None:
        self._add("system", level, message)

    def output(self, stream: str, text: str) -> None:
        key = "stderr" if stream == "stderr" else "stdout"
        parts = (self._partial[key] + text).split("\n")
        *complete, rest = parts
        self._partial[key] = rest
        level = "warning" if key == "stderr" else "info"
        for line in complete:
            if line.strip():
                self._add(key, level, line)

    def _add(self, stream: str, level: str, message: str) -> None:
        if self._written + len(self._pending) >= self.max_lines:
            self._dropped += 1
            return
        self._pending.append((stream, level, message.rstrip()[:LOG_MESSAGE_MAX_CHARS]))

    def flush(self, *, force: bool = False) -> None:
        if not force and time.monotonic() - self._last_flush < LOG_FLUSH_SECONDS:
            return
        if force:
            for key, rest in self._partial.items():
                if rest.strip():
                    self._add(key, "warning" if key == "stderr" else "info", rest)
                self._partial[key] = ""

        if not self._pending and not self._dropped:
            return

        batch, self._pending = self._pending, []
        dropped, self._dropped = self._dropped, 0
        self._written += len(batch)
        self._last_flush = time.monotonic()

        try:
            with session_scope() as session:
                for stream, level, message in batch:
                    jobs.log(session, self.run_id, stream, level, message)
                if dropped:
                    jobs.log(
                        session,
                        self.run_id,
                        "system",
                        "warning",
                        f"{dropped} further output line(s) were not kept: this run's "
                        f"log limit ({self.max_lines} lines) was reached",
                    )
        except Exception:
            # Losing log lines is not a reason to lose the run.
            logger.exception("could not flush run %s log lines", self.run_id)
            self._dropped += len(batch)


class RunControl:
    """Lease renewal and cancellation polling, called from the tool's read loop."""

    def __init__(self, run_id: int, worker_id: str, settings: Settings, logs: LogSink) -> None:
        self.run_id = run_id
        self.worker_id = worker_id
        self.settings = settings
        self.logs = logs
        self.cancelled = False
        self.lost_lease = False
        self._last_beat = 0.0
        self._last_poll = 0.0

    def check(self) -> bool:
        now = time.monotonic()
        if now - self._last_poll >= CANCEL_POLL_SECONDS:
            self._last_poll = now
            due = now - self._last_beat >= self.settings.heartbeat_seconds
            try:
                with session_scope() as session:
                    if due:
                        self._last_beat = now
                        if not jobs.heartbeat(
                            session,
                            self.run_id,
                            worker_id=self.worker_id,
                            settings=self.settings,
                        ):
                            self.lost_lease = True
                            return True
                    if jobs.cancel_requested(session, self.run_id):
                        self.cancelled = True
            except Exception:
                # The database being briefly unreachable must not abort a run
                # that is otherwise fine: the lease will lapse only if this
                # keeps up, and the reaper is the backstop for that.
                logger.exception("run %s could not renew its lease", self.run_id)
        self.logs.flush()
        if self.cancelled:
            self.logs.system("warning", "cancellation requested; stopping the tool")
            return True
        if self.lost_lease:
            self.logs.system("error", "this worker no longer owns the run; stopping")
            return True
        return False


class Worker:
    def __init__(self, *, settings: Settings | None = None, worker_id: str | None = None) -> None:
        self.settings = settings or get_settings()
        self.worker_id = worker_id or f"{engine.url.database}@{_hostname()}:{_pid()}"

    # -- queue ---------------------------------------------------------------

    def run_once(self) -> bool:
        """Attempt one run. True means work was done (or deliberately deferred)."""
        lock: AdvisoryLock | None = None
        claimed: int | None = None
        try:
            with session_scope() as session:
                if jobs.kill_switch_engaged(session):
                    logger.warning("kill switch engaged: not starting new runs")
                    return False
                if jobs.active_run_count(session) >= self.settings.max_concurrent_runs:
                    return False
                candidate = jobs.next_candidate(session)
                if candidate is None:
                    return False
                run_id, target_id = candidate

                lock = self._reserve_target(target_id)
                if lock is None:
                    jobs.defer(
                        session,
                        run_id,
                        seconds=jobs.BUSY_RETRY_SECONDS,
                        reason="another run is already in flight against this target",
                    )
                    return True

                run = jobs.claim(
                    session, run_id, worker_id=self.worker_id, settings=self.settings
                )
                if run is None:
                    lock.release()
                    lock = None
                    return True
                claimed = run.id
                jobs.log(
                    session,
                    run.id,
                    "system",
                    "info",
                    f"claimed by {self.worker_id} (attempt {run.attempt})",
                )
        except Exception:
            if lock is not None:
                lock.release()
            raise

        if claimed is None:
            return False

        try:
            self.execute_run(claimed)
        finally:
            lock.release()
        return True

    def _reserve_target(self, target_id: int) -> AdvisoryLock | None:
        """Take a per-target slot, or None if every slot is in use.

        The lock lives on its own connection so that a worker dying mid-run
        releases it immediately - a stale in-process flag cannot do that.
        """
        slots = max(1, self.settings.per_target_concurrency)
        for slot in range(slots):
            lock = AdvisoryLock(f"target:{target_id}:{slot}")
            if lock.acquire():
                return lock
        return None

    def reap(self) -> None:
        try:
            with session_scope() as session:
                outcome = jobs.reap(session)
        except Exception:
            logger.exception("reaping expired leases failed")
            return
        if outcome["requeued"] or outcome["dead"]:
            logger.warning(
                "reaper: requeued %s, dead-lettered %s",
                outcome["requeued"],
                outcome["dead"],
            )

    # -- one run -------------------------------------------------------------

    def execute_run(self, run_id: int) -> None:
        logs = LogSink(run_id, self.settings.run_log_max_lines)
        control = RunControl(run_id, self.worker_id, self.settings, logs)
        workdir: Path | None = None

        try:
            try:
                plan = self._load_plan(run_id, logs)
            except RunSkipped as skip:
                self._finish_skipped(run_id, skip, logs)
                return

            workdir = self._make_workdir(run_id)
            result: EngineResult | None = None
            failure: str | None = None
            try:
                result = run_engine(
                    plan.run.engine_id, plan.view, plan.version.engine_params, self._context(plan, workdir, control, logs)
                )
            except EngineError as exc:
                failure = str(exc)
                # The engine may have run its tool far enough to capture output
                # and a tool version before giving up. That partial result is
                # recorded with the failure: it is the record of what actually
                # executed, and _persist keeps the run in the error state.
                result = exc.result
                logs.system("error", failure)
            except Exception as exc:  # a bug in an engine is a failed run, not a crashed worker
                failure = f"the {plan.run.engine_id} engine failed: {exc}"
                logger.exception("run %s: engine raised", run_id)
                logs.system("error", failure)

            if control.lost_lease and not control.cancelled:
                # Another worker owns this run now (the lease lapsed, the reaper
                # requeued it). Writing anything here would collide with that
                # worker's result, so this attempt keeps only its own log lines.
                logger.warning("run %s: lease lost; leaving the result to its new owner", run_id)
                return

            self._persist(plan, result, failure, control, logs)
        except EngineError as exc:
            # Raised while storing the result: the observation exists but could
            # not be recorded, which is a failure with a reason worth showing.
            logger.error("run %s: %s", run_id, exc)
            logs.system("error", str(exc))
            self._fail_safely(run_id, str(exc))
        except Exception as exc:
            logger.exception("run %s: unexpected failure while executing", run_id)
            self._fail_safely(run_id, f"an unexpected error stopped this run: {exc}")
        finally:
            logs.flush(force=True)
            if workdir is not None:
                shutil.rmtree(workdir, ignore_errors=True)

    def _load_plan(self, run_id: int, logs: LogSink) -> _Plan:
        with session_scope() as session:
            run = session.get(ValidationRun, run_id)
            if run is None:
                raise RunSkipped(RunStatus.ERROR, f"run {run_id} no longer exists")

            test = session.get(ValidationTest, run.test_id)
            version = session.get(ValidationTestVersion, run.test_version_id)
            target = session.get(Target, run.target_id)
            if test is None or version is None or target is None:
                raise RunSkipped(
                    RunStatus.ERROR,
                    "this run's test, test version or target has been deleted",
                )
            if not test.enabled:
                raise RunSkipped(RunStatus.CANCELLED, f"test {test.key!r} was disabled before this run started")
            if not target.enabled:
                raise RunSkipped(RunStatus.CANCELLED, f"target {target.name!r} is disabled")

            control = session.get(Control, version.control_id)
            if control is None:
                raise RunSkipped(RunStatus.ERROR, "this run's control no longer exists")

            try:
                rules = active_rules_for_target(session, target.id)
            except ScopeLoadError as exc:
                raise RunSkipped(RunStatus.ERROR, str(exc)) from exc

            port = _effective_port(target)
            if target.target_type is TargetType.LOCAL:
                # A local baseline reads this machine's own kernel and
                # configuration and opens no socket, so there is no address to
                # resolve and nothing to authorize at the network layer. The
                # scope link that allowed the run to get this far is still
                # required (active_rules_for_target refuses a target no active
                # scope covers): a human registered this host as one the
                # platform may inspect, and the snapshot records which scope
                # said so.
                addresses = []
                snapshot: dict = {
                    "mode": "local",
                    "scopes": sorted({rule.scope_name for rule in rules}),
                }
                reason = "local inspection; this run sends no packets"
            else:
                decision = authorize(target.host, port, target.protocol, rules)
                if not decision.allowed:
                    # Deliberately an error rather than a cancelled run: an
                    # attempt to reach something that is not authorized is a
                    # thing an operator needs to see, not a run that quietly
                    # did not happen.
                    raise RunSkipped(RunStatus.ERROR, f"refused to run: {decision.reason}")
                addresses = decision.addresses
                snapshot = decision.scope_snapshot
                reason = decision.reason

            run.resolved_ips = addresses
            run.scope_snapshot = snapshot
            jobs.log(
                session,
                run.id,
                "system",
                "info",
                f"authorized: {reason}"
                + (f"; testing {addresses[0]}:{port}" if addresses else ""),
            )
            if len(addresses) > 1:
                jobs.log(
                    session,
                    run.id,
                    "system",
                    "info",
                    f"{addresses[0]} chosen for this run; every address "
                    f"({', '.join(addresses)}) was checked against scope",
                )

            view = TargetView(
                ip=addresses[0] if addresses else target.host,
                port=port,
                protocol=target.protocol,
                hostname=target.host,
                path=target.path,
                target_type=target.target_type,
            )
            plan = _Plan(
                run=run,
                test=test,
                version=version,
                control=control,
                target=target,
                view=view,
                scope_snapshot=snapshot,
                resolved_ips=addresses,
            )

        logs.system(
            "info",
            f"{test.key}: {plan.control.key} against {target.name} using the "
            f"{run.engine_id} engine (test version {version.version})",
        )
        return plan

    def _context(
        self, plan: _Plan, workdir: Path, control: RunControl, logs: LogSink
    ) -> EngineContext:
        return EngineContext(
            run_id=plan.run.id,
            timeout_seconds=plan.run.timeout_seconds or 300,
            max_output_bytes=self.settings.stream_byte_cap,
            safe_mode=self.settings.safe_mode,
            workdir=workdir,
            should_cancel=control.check,
            log=lambda level, message: logs.system(level, message),
            on_output=logs.output,
            evidence_kind=EvidenceKind.STDOUT,
        )

    def _persist(
        self,
        plan: _Plan,
        result: EngineResult | None,
        failure: str | None,
        control: RunControl,
        logs: LogSink,
    ) -> None:
        cancelled = control.cancelled
        with session_scope() as session:
            run = session.get(ValidationRun, plan.run.id)
            if run is None:
                logger.error("run %s vanished before its result could be stored", plan.run.id)
                return

            facts: list[Fact] = []
            stdout_evidence_id = None

            if result is not None:
                run.argv = result.argv or None
                run.tool_versions = result.tool_versions or None
                run.exit_code = result.exit_code

                stdout_evidence_id = self._store_capture(
                    session, run, plan, result.stdout, EvidenceKind.STDOUT, "stdout.txt"
                )
                self._store_capture(
                    session, run, plan, result.stderr, EvidenceKind.STDERR, "stderr.txt"
                )
                self._store_artifacts(session, run, plan, result)
                if stdout_evidence_id is None:
                    # Engines that observe in-process rather than by running a
                    # tool leave no captured output behind. Their facts are what
                    # they saw, so the facts themselves are written down as the
                    # evidence - a fact with nothing behind it cannot be
                    # audited, and a verdict resting on one cannot be defended.
                    stdout_evidence_id = self._store_observation(session, run, plan, result)

                for draft in result.facts:
                    fact = Fact(
                        run_id=run.id,
                        target_id=plan.target.id,
                        evidence_id=stdout_evidence_id,
                        fact_type=draft.fact_type,
                        subject=draft.subject,
                        key=draft.key,
                        value=draft.value,
                        confidence=draft.confidence,
                        detail=draft.detail,
                    )
                    session.add(fact)
                    facts.append(fact)
                session.flush()

            by_type: dict[str, int] = {}
            for fact in facts:
                by_type[fact.fact_type] = by_type.get(fact.fact_type, 0) + 1

            if cancelled:
                # An operator's stop outranks whatever the tool reported on its
                # way out: the run was stopped, and a partial observation is
                # not a verdict.
                run.status = RunStatus.CANCELLED
                run.error_message = "cancelled while running; the observation is incomplete"
                self._store_assertion(
                    session,
                    plan,
                    run,
                    status=AssertionStatus.INCONCLUSIVE,
                    reason=(
                        "the run was cancelled before it finished, so the assertion "
                        "was not evaluated against a complete observation"
                    ),
                    observed={"facts": len(facts)},
                )
            elif failure is not None:
                run.status = RunStatus.ERROR
                run.error_message = failure[:4000]
                logs.system("error", f"run failed: {failure}")
            else:
                incomplete = result.incomplete_reason if result is not None else None
                if result is not None and result.incomplete and incomplete is None:
                    incomplete = "the engine reported an incomplete observation"
                if incomplete:
                    run.status = RunStatus.INCONCLUSIVE
                    run.error_message = incomplete[:4000]
                    logs.system("warning", incomplete)
                    self._store_assertion(
                        session,
                        plan,
                        run,
                        status=AssertionStatus.INCONCLUSIVE,
                        reason=incomplete,
                        observed={"facts": len(facts)},
                    )
                else:
                    self._decide(session, plan, run, facts, logs)

            run.finished_at = jobs.now()
            run.heartbeat_at = None
            run.lease_until = None
            run.observed_summary = {
                "facts": len(facts),
                "by_type": by_type,
                "notes": list(result.notes) if result is not None else [],
            }
            logs.system("info", f"run finished: {run.status.value}")

    def _decide(
        self,
        session: Session,
        plan: _Plan,
        run: ValidationRun,
        facts: list[Fact],
        logs: LogSink,
    ) -> None:
        """Evaluate the assertion against the stored facts and act on the result."""
        outcome: AssertionOutcome = evaluate(
            plan.version.assertion, facts, default_severity=plan.version.severity
        )
        self._store_assertion(
            session,
            plan,
            run,
            status=outcome.status,
            reason=outcome.reason,
            observed={"matched": outcome.matched, "unobserved": outcome.unobserved},
            fact_ids=list(outcome.fact_ids),
            outcome=outcome,
        )
        run.status = findings_engine.status_for_run(outcome)
        logs.system(
            "info" if outcome.status is AssertionStatus.PASS else "warning",
            f"{outcome.status.value}: {outcome.reason}",
        )

        finding = findings_engine.record_outcome(
            session,
            run=run,
            version=plan.version,
            control=plan.control,
            target=plan.target,
            outcome=outcome,
        )
        if finding is not None:
            logs.system("warning", f"finding #{finding.id} {finding.status.value}: {finding.title}")

    # -- storage helpers -----------------------------------------------------

    def _store_capture(
        self,
        session: Session,
        run: ValidationRun,
        plan: _Plan,
        text: str,
        kind: EvidenceKind,
        filename: str,
    ) -> int | None:
        if not text:
            return None
        return self._store(
            session,
            run,
            plan,
            data=text.encode("utf-8", errors="replace"),
            kind=kind,
            filename=filename,
            content_type="text/plain; charset=utf-8",
        )

    def _store_observation(
        self, session: Session, run: ValidationRun, plan: _Plan, result: EngineResult
    ) -> int | None:
        if not result.facts:
            return None
        transcript = {
            "engine": run.engine_id,
            "target": {
                "name": plan.target.name,
                "host": plan.target.host,
                "port": plan.view.port,
                "path": plan.view.path,
            },
            "observed_at": jobs.now().isoformat(),
            "notes": list(result.notes),
            "facts": [
                {
                    "fact_type": fact.fact_type,
                    "subject": fact.subject,
                    "key": fact.key,
                    "value": fact.value,
                    "confidence": fact.confidence,
                    "detail": fact.detail,
                }
                for fact in result.facts
            ],
        }
        data = json.dumps(transcript, indent=2, sort_keys=True, default=str).encode()
        return self._store(
            session,
            run,
            plan,
            data=data,
            kind=EvidenceKind.ARTIFACT,
            filename="observation.json",
            content_type="application/json",
        )

    def _store_artifacts(
        self, session: Session, run: ValidationRun, plan: _Plan, result: EngineResult
    ) -> None:
        for artifact in result.artifacts:
            self._store(
                session,
                run,
                plan,
                data=artifact.data,
                kind=EvidenceKind.ARTIFACT,
                filename=artifact.filename,
                content_type=artifact.content_type,
            )

    def _store(
        self,
        session: Session,
        run: ValidationRun,
        plan: _Plan,
        *,
        data: bytes,
        kind: EvidenceKind,
        filename: str,
        content_type: str,
    ) -> int | None:
        detail = {
            "engine": run.engine_id,
            "target": plan.target.name,
            "argv": (run.argv or [])[:64],
        }
        try:
            evidence = store_bytes(
                run_id=run.id,
                kind=kind,
                filename=filename,
                data=data,
                content_type=content_type,
                detail=detail,
                settings=self.settings,
                session=session,
            )
        except EvidenceError as exc:
            # The bytes exist but could not be stored. That is fatal to the
            # run's value: an evaluation whose evidence is missing cannot be
            # audited, so it must not be reported as an observation.
            logger.error("run %s: evidence could not be stored: %s", run.id, exc)
            raise EngineError(f"evidence could not be stored: {exc}") from exc
        return evidence.id

    def _store_assertion(
        self,
        session: Session,
        plan: _Plan,
        run: ValidationRun,
        *,
        status: AssertionStatus,
        reason: str,
        observed: dict | None = None,
        fact_ids: list[int] | None = None,
        outcome: AssertionOutcome | None = None,
    ) -> None:
        session.add(
            AssertionResult(
                run_id=run.id,
                test_version_id=plan.version.id,
                target_id=plan.target.id,
                control_id=plan.control.id,
                assertion_index=0,
                assertion=plan.version.assertion,
                status=status,
                severity=outcome.severity if outcome else plan.version.severity,
                reason=reason[:4000],
                expected={"assertion": plan.version.assertion},
                observed=observed,
                fact_ids=fact_ids,
            )
        )

    # -- misc ----------------------------------------------------------------

    def _finish_skipped(self, run_id: int, skip: RunSkipped, logs: LogSink) -> None:
        with session_scope() as session:
            run = session.get(ValidationRun, run_id)
            if run is None:
                return
            run.status = skip.status
            run.finished_at = jobs.now()
            run.heartbeat_at = None
            run.lease_until = None
            run.error_message = str(skip)[:4000]
            jobs.log(
                session,
                run_id,
                "system",
                "error" if skip.status is RunStatus.ERROR else "warning",
                str(skip),
            )

    def _fail_safely(self, run_id: int, message: str) -> None:
        try:
            with session_scope() as session:
                run = session.get(ValidationRun, run_id)
                if run is not None and not run.status.is_terminal:
                    run.status = RunStatus.ERROR
                    run.finished_at = jobs.now()
                    run.error_message = message
                    run.lease_until = None
                    run.heartbeat_at = None
                    jobs.log(session, run_id, "system", "error", message)
        except Exception:
            # The reaper will collect it once the lease lapses.
            logger.exception("run %s could not be marked as failed", run_id)

    def _make_workdir(self, run_id: int) -> Path:
        root = Path(self.settings.evidence_dir).parent / "work"
        root.mkdir(parents=True, exist_ok=True)
        workdir = root / f"run-{run_id}"
        shutil.rmtree(workdir, ignore_errors=True)
        workdir.mkdir(mode=0o700)
        return workdir


def _effective_port(target: Target) -> int:
    """The port a target means when it does not name one."""
    if target.port:
        return target.port
    if target.protocol == "https":
        return 443
    if target.protocol == "ssh":
        return 22
    return 80


def _hostname() -> str:
    import socket

    return socket.gethostname()


def _pid() -> int:
    import os

    return os.getpid()
