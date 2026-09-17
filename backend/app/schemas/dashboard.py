"""Response models for the dashboard: summary, trend and per-control posture.

The wire names match the SPA's types.ts exactly. ``pass`` is a reserved word in
Python, so the fields carrying it are aliased; FastAPI serialises response
models by alias, so the JSON keys are ``pass`` either way.
"""

from __future__ import annotations

from datetime import date, datetime

from pydantic import BaseModel, ConfigDict, Field


class AssertionCounts(BaseModel):
    """Current assertion posture, one bucket per status."""

    model_config = ConfigDict(populate_by_name=True)

    passed: int = Field(default=0, alias="pass")
    fail: int = 0
    inconclusive: int = 0
    not_applicable: int = 0


class FindingsCounts(BaseModel):
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)


class TargetCounts(BaseModel):
    total: int = 0
    scoped: int = 0


class RunCounts(BaseModel):
    last_24h: int = 0
    running: int = 0
    queued: int = 0
    failed: int = 0


class CoverageCounts(BaseModel):
    controls_total: int = 0
    controls_with_recent_results: int = 0
    controls_stale: int = 0


class DashboardSummary(BaseModel):
    assertions: AssertionCounts = Field(default_factory=AssertionCounts)
    findings: FindingsCounts = Field(default_factory=FindingsCounts)
    targets: TargetCounts = Field(default_factory=TargetCounts)
    runs: RunCounts = Field(default_factory=RunCounts)
    coverage: CoverageCounts = Field(default_factory=CoverageCounts)
    last_updated: datetime


class TrendDay(BaseModel):
    """One calendar day of assertion outcomes."""

    model_config = ConfigDict(populate_by_name=True)

    date: date
    passed: int = Field(default=0, alias="pass")
    fail: int = 0
    inconclusive: int = 0
    not_applicable: int = 0


class DashboardTrend(BaseModel):
    days: list[TrendDay] = Field(default_factory=list)


class PostureRow(BaseModel):
    """Latest outcome of one control across every target it was evaluated on."""

    model_config = ConfigDict(populate_by_name=True)

    control_id: int
    control_key: str
    control_title: str
    category: str | None = None
    passed: int = Field(default=0, alias="pass")
    fail: int = 0
    inconclusive: int = 0
    not_applicable: int = 0
    coverage_ratio: float = 0.0
    last_evaluated_at: datetime | None = None
