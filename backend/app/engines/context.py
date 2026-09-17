"""What an engine is allowed to know, and what it must hand back.

The contract is deliberately narrow in one direction: an engine receives an
already-authorized **IP address**, never a hostname to resolve. Resolution
happened once, in the scope layer, and the addresses it produced were checked
against the allowlist. If an engine re-resolved the name it would reopen the
rebinding window the pinning exists to close. The hostname is still supplied,
but only as something to put in a ``Host:`` header or a TLS SNI extension.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from app.models.enums import EvidenceKind, TargetType

LogLevel = Literal["debug", "info", "warning", "error"]

# Engines cap how much of a target's response they will read. A target that
# streams an endless body must not be able to fill the worker's disk.
MAX_HTTP_BODY_BYTES = 512 * 1024


class EngineError(RuntimeError):
    """The engine could not produce facts at all.

    Raising this marks the run ``error`` rather than ``passed``. An engine that
    observed nothing must never look like a control that held.

    An engine that already ran its tool attaches the partial ``EngineResult`` it
    built - the argv, the tool versions, the captured output. A run that failed
    is precisely the run whose command line and tool version an operator needs,
    so discarding them at the moment of failure would be exactly backwards. An
    engine that failed before running anything (an unusable parameter set, a
    missing template tree) attaches nothing.
    """

    def __init__(self, message: str, *, result: EngineResult | None = None) -> None:
        super().__init__(message)
        self.result = result


class EngineUnavailable(EngineError):
    """The underlying tool is missing or unusable on this host."""


@dataclass(frozen=True, slots=True)
class TargetView:
    """The pinned, authorized view of a target."""

    ip: str
    port: int
    protocol: str
    hostname: str
    path: str
    target_type: TargetType

    @property
    def is_default_port(self) -> bool:
        return self.port in (0, 80, 443)

    def authority(self, *, default_port: int) -> str:
        """``hostname:port`` for a Host header, omitting the scheme default."""
        if self.port in (0, default_port):
            return self.hostname
        return f"{self.hostname}:{self.port}"

    def url(self, *, scheme: str, default_port: int) -> str:
        authority = self.authority(default_port=default_port)
        path = self.path or "/"
        if not path.startswith("/"):
            path = "/" + path
        return f"{scheme}://{authority}{path}"


@dataclass(slots=True)
class FactDraft:
    """A typed observable, before it is written to the database.

    ``subject`` is what the fact is about (normally the host) and ``key``
    distinguishes several facts of one type (a header name, a port). Assertions
    select on both, so they have to be stable.
    """

    fact_type: str
    value: dict[str, Any]
    subject: str = ""
    key: str = ""
    confidence: float = 1.0
    detail: str | None = None


@dataclass(slots=True)
class ArtifactDraft:
    """Extra evidence worth storing alongside the run's output."""

    filename: str
    data: bytes
    content_type: str = "text/plain"


@dataclass(slots=True)
class EngineResult:
    facts: list[FactDraft] = field(default_factory=list)
    artifacts: list[ArtifactDraft] = field(default_factory=list)
    argv: list[str] = field(default_factory=list)
    tool_versions: dict[str, str] = field(default_factory=dict)
    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = None
    error: str | None = None
    notes: list[str] = field(default_factory=list)
    # Set when the observation is known to be partial: the tool was stopped, it
    # timed out, or it said itself that it did not finish. A partial observation
    # may not be evaluated as if it were a complete one - ports that were not
    # scanned are not ports that are closed - so the runner records an
    # inconclusive result instead of a verdict.
    incomplete: bool = False
    incomplete_reason: str | None = None

    def add(self, *facts: FactDraft) -> None:
        self.facts.extend(facts)


@dataclass(slots=True)
class EngineContext:
    """The runner hands the engine one of these and nothing else."""

    run_id: int
    timeout_seconds: int
    max_output_bytes: int
    safe_mode: bool
    workdir: Path
    should_cancel: Callable[[], bool] | None = None
    log: Callable[[LogLevel, str], None] = lambda level, message: None
    # Lets an engine pass tool output through to the run's live view while it is
    # still being produced. The runner decides whether to keep it.
    on_output: Callable[[str, str], None] | None = None
    evidence_kind: EvidenceKind = EvidenceKind.ARTIFACT

    def emit(self, level: LogLevel, message: str) -> None:
        self.log(level, message)
