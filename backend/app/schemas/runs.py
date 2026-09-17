"""Schemas for runs, their logs, facts and assertion outcomes.

Mirrors the ``runs`` and SSE sections of the frontend's ``lib/types.ts``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.enums import (
    AssertionStatus,
    EvidenceKind,
    RunStatus,
    Severity,
    StreamKind,
    TriggerKind,
)


class RunSummary(BaseModel):
    id: int
    test_id: int
    test_key: str
    test_name: str
    target_id: int
    target_name: str
    target_host: str
    target_port: int
    engine_id: str
    status: RunStatus
    trigger: TriggerKind
    # Who put the work on the queue. Null for a run started by something other
    # than a person, and for one whose authorizing account has since been
    # deleted (the actor is preserved on the audit row regardless).
    authorized_by_username: str | None = None
    attempt: int
    queued_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_seconds: float | None = None
    exit_code: int | None = None
    assertion_status: AssertionStatus | None = None
    error_message: str | None = None
    findings_count: int = 0


class RunFactSummary(BaseModel):
    fact_type: str
    count: int


class AssertionResultOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    assertion_index: int
    assertion: dict[str, Any]
    status: AssertionStatus
    severity: Severity
    reason: str | None = None
    fact_ids: list[int] = Field(default_factory=list)
    evaluated_at: datetime

    @field_validator("fact_ids", mode="before")
    @classmethod
    def _absent_fact_ids_are_empty(cls, value: Any) -> Any:
        return value or []


class RunEvidenceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    kind: EvidenceKind
    filename: str
    sha256: str
    size_bytes: int
    mime: str
    truncated: bool
    created_at: datetime


class RunDetail(RunSummary):
    argv: list[str] | None = None
    tool_versions: dict[str, Any] | None = None
    resolved_ips: list[str] | None = None
    scope_snapshot: dict[str, Any] | None = None
    timeout_seconds: int | None = None
    observed_summary: dict[str, Any] | None = None
    cancel_requested: bool = False
    retest_of_finding_id: int | None = None
    facts_summary: list[RunFactSummary] = Field(default_factory=list)
    assertion_results: list[AssertionResultOut] = Field(default_factory=list)
    evidence: list[RunEvidenceOut] = Field(default_factory=list)


class LogLineOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ts: datetime
    stream: StreamKind
    level: str
    message: str


class FactOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    fact_type: str
    subject: str
    key: str
    value: Any
    confidence: float
    detail: str | None = None
    evidence_id: int | None = None


class RunPage(BaseModel):
    items: list[RunSummary]
    total: int


class RunStartRequest(BaseModel):
    test_id: int
    target_ids: list[int] = Field(min_length=1, max_length=256)

    @field_validator("target_ids")
    @classmethod
    def _no_duplicates(cls, value: list[int]) -> list[int]:
        if len(set(value)) != len(value):
            raise ValueError("target_ids contains duplicates")
        return value


class RunStartResponse(BaseModel):
    runs: list[RunSummary]
