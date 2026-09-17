"""Schemas for findings, their remediation timeline and retests.

Field names mirror the SPA contract in ``frontend/src/lib/types.ts`` exactly. A
finding summary is a flattened view over three joined tables plus two derived
values (occurrences, last assertion status), so the router builds these models
explicitly rather than validating them off ORM attributes.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import (
    AssertionStatus,
    EvidenceKind,
    FindingStatus,
    RemediationActionKind,
    Severity,
)


class FactOut(BaseModel):
    """A fact referenced by the assertion that produced the finding."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    fact_type: str
    subject: str
    key: str
    value: Any
    confidence: float
    detail: str | None = None
    evidence_id: int | None = None


class EvidenceItemOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    run_id: int
    kind: EvidenceKind
    filename: str
    sha256: str
    size_bytes: int
    mime: str
    truncated: bool
    created_at: datetime
    detail: dict[str, Any] | None = None


class FindingTimelineEntry(BaseModel):
    id: int
    kind: RemediationActionKind
    note: str | None = None
    created_at: datetime
    actor: str | None = None
    from_status: FindingStatus | None = None
    to_status: FindingStatus | None = None
    due_at: datetime | None = None


class FindingSummary(BaseModel):
    id: int
    status: FindingStatus
    severity: Severity
    title: str
    control_id: int
    control_key: str
    control_title: str
    test_id: int
    test_key: str
    target_id: int
    target_name: str
    first_seen_at: datetime
    last_seen_at: datetime
    last_run_id: int | None = None
    occurrences: int
    last_status: AssertionStatus | None = None
    assigned_to: int | None = None
    retest_of_finding_id: int | None = None
    resolved_at: datetime | None = None


class FindingDetail(FindingSummary):
    description: str | None = None
    expected: Any = None
    observed: Any = None
    reason: str | None = None
    facts: list[FactOut] = Field(default_factory=list)
    evidence: list[EvidenceItemOut] = Field(default_factory=list)
    timeline: list[FindingTimelineEntry] = Field(default_factory=list)
    remediation_guidance: str | None = None


class FindingListOut(BaseModel):
    items: list[FindingSummary]
    total: int


class FindingUpdate(BaseModel):
    """A triage edit. Omitted fields are left alone; unknown ones are refused
    so a typo cannot silently drop the change a human believes they made."""

    model_config = ConfigDict(extra="forbid")

    status: FindingStatus | None = None
    severity: Severity | None = None
    assigned_to: int | None = Field(default=None, ge=1)
    note: str | None = Field(default=None, max_length=2000)


class FindingSummaryStats(BaseModel):
    by_severity: dict[str, int]
    by_status: dict[str, int]
    open_total: int
    overdue_total: int


class FindingRetestOut(BaseModel):
    run_id: int
