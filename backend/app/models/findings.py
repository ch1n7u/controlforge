from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base
from app.models.enums import FindingStatus, RemediationActionKind, Severity, enum_col
from app.models.mixins import TimestampMixin


class Finding(Base, TimestampMixin):
    """A control that failed validation on a specific target.

    Deduplicated by fingerprint (test + target + assertion) so the same
    weakness observed on repeated runs stays one finding with a history rather
    than a stream of duplicates.
    """

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(300), nullable=False)

    control_id: Mapped[int] = mapped_column(
        ForeignKey("controls.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    test_id: Mapped[int] = mapped_column(
        ForeignKey("validation_tests.id", ondelete="RESTRICT"), nullable=False
    )
    test_version_id: Mapped[int] = mapped_column(
        ForeignKey("validation_test_versions.id", ondelete="RESTRICT"), nullable=False
    )
    target_id: Mapped[int] = mapped_column(
        ForeignKey("targets.id", ondelete="RESTRICT"), nullable=False, index=True
    )

    assertion_index: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    assertion: Mapped[dict] = mapped_column(JSONB, nullable=False)
    severity: Mapped[Severity] = mapped_column(enum_col(Severity), nullable=False, index=True)
    status: Mapped[FindingStatus] = mapped_column(
        enum_col(FindingStatus), nullable=False, default=FindingStatus.OPEN, index=True
    )

    expected: Mapped[dict | None] = mapped_column(JSONB)
    observed: Mapped[dict | None] = mapped_column(JSONB)
    detail: Mapped[str | None] = mapped_column(Text)

    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
    last_failed_run_id: Mapped[int | None] = mapped_column(
        ForeignKey("validation_runs.id", ondelete="SET NULL")
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_by_run_id: Mapped[int | None] = mapped_column(
        ForeignKey("validation_runs.id", ondelete="SET NULL")
    )
    retest_of_finding_id: Mapped[int | None] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL")
    )

    assigned_to_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    risk_note: Mapped[str | None] = mapped_column(Text)

    actions: Mapped[list["RemediationAction"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan", order_by="RemediationAction.id"
    )

    __table_args__ = (Index("ix_findings_target_status", "target_id", "status"),)


class RemediationAction(Base):
    """Append-only history of what people did about a finding."""

    __tablename__ = "remediation_actions"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    kind: Mapped[RemediationActionKind] = mapped_column(
        enum_col(RemediationActionKind), nullable=False
    )
    from_status: Mapped[FindingStatus | None] = mapped_column(enum_col(FindingStatus))
    to_status: Mapped[FindingStatus | None] = mapped_column(enum_col(FindingStatus))
    note: Mapped[str | None] = mapped_column(Text)
    detail: Mapped[dict | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    finding: Mapped[Finding] = relationship(back_populates="actions")
