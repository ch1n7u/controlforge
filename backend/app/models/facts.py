from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models.enums import AssertionStatus, Severity, enum_col


class Fact(Base):
    """A typed observable emitted by an engine.

    Assertions evaluate facts, never raw tool text. This is what keeps parsing
    out of the assertion layer and makes trends across runs possible.
    """

    __tablename__ = "facts"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    run_id: Mapped[int] = mapped_column(
        ForeignKey("validation_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_id: Mapped[int] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    evidence_id: Mapped[int | None] = mapped_column(
        ForeignKey("evidence.id", ondelete="SET NULL")
    )

    fact_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    subject: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    key: Mapped[str] = mapped_column(String(160), nullable=False, default="")
    value: Mapped[dict] = mapped_column(JSONB, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    detail: Mapped[str | None] = mapped_column(Text)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        Index("ix_facts_target_type", "target_id", "fact_type"),
        Index("ix_facts_run_type", "run_id", "fact_type"),
    )


class AssertionResult(Base):
    """Outcome of evaluating one assertion against one run's facts.

    Tri-state by design: PASS / FAIL / INCONCLUSIVE / NOT_APPLICABLE. An
    engine that could not observe anything must not be reported as a pass.
    """

    __tablename__ = "assertion_results"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    run_id: Mapped[int] = mapped_column(
        ForeignKey("validation_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    test_version_id: Mapped[int] = mapped_column(
        ForeignKey("validation_test_versions.id", ondelete="RESTRICT"), nullable=False
    )
    target_id: Mapped[int] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    control_id: Mapped[int] = mapped_column(
        ForeignKey("controls.id", ondelete="RESTRICT"), nullable=False, index=True
    )

    assertion_index: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    assertion: Mapped[dict] = mapped_column(JSONB, nullable=False)
    status: Mapped[AssertionStatus] = mapped_column(
        enum_col(AssertionStatus), nullable=False, index=True
    )
    severity: Mapped[Severity] = mapped_column(enum_col(Severity), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text)
    expected: Mapped[dict | None] = mapped_column(JSONB)
    observed: Mapped[dict | None] = mapped_column(JSONB)
    fact_ids: Mapped[list | None] = mapped_column(JSONB)

    evaluated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )

    __table_args__ = (
        UniqueConstraint("run_id", "assertion_index", name="uq_assertion_result_run_index"),
        Index("ix_assertion_results_control_status", "control_id", "status"),
    )
