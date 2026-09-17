from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base
from app.models.enums import EvidenceKind, RunStatus, Severity, StreamKind, TriggerKind, enum_col
from app.models.mixins import TimestampMixin


class ValidationTest(Base, TimestampMixin):
    """A named validation test. The executable definition lives in its versions."""

    __tablename__ = "validation_tests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(String(80), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    control_id: Mapped[int] = mapped_column(
        ForeignKey("controls.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    tags: Mapped[list[str]] = mapped_column(ARRAY(String(64)), nullable=False, default=list)
    target_selector: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    current_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    versions: Mapped[list["ValidationTestVersion"]] = relationship(
        back_populates="test", cascade="all, delete-orphan", order_by="ValidationTestVersion.version"
    )


class ValidationTestVersion(Base):
    """Immutable snapshot of what a test actually executes.

    Runs and findings reference the version, never the mutable test row, so a
    result recorded last month keeps meaning what it meant last month.
    """

    __tablename__ = "validation_test_versions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    test_id: Mapped[int] = mapped_column(
        ForeignKey("validation_tests.id", ondelete="CASCADE"), nullable=False, index=True
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    engine_id: Mapped[str] = mapped_column(String(64), nullable=False)
    engine_params: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    assertion: Mapped[dict] = mapped_column(JSONB, nullable=False)
    control_id: Mapped[int] = mapped_column(
        ForeignKey("controls.id", ondelete="RESTRICT"), nullable=False
    )
    severity: Mapped[Severity] = mapped_column(enum_col(Severity), nullable=False)
    note: Mapped[str | None] = mapped_column(Text)
    created_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    test: Mapped[ValidationTest] = relationship(back_populates="versions")

    __table_args__ = (UniqueConstraint("test_id", "version", name="uq_test_version"),)


class ValidationRun(Base):
    __tablename__ = "validation_runs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    test_id: Mapped[int] = mapped_column(
        ForeignKey("validation_tests.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    test_version_id: Mapped[int] = mapped_column(
        ForeignKey("validation_test_versions.id", ondelete="RESTRICT"), nullable=False
    )
    target_id: Mapped[int] = mapped_column(
        ForeignKey("targets.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    engine_id: Mapped[str] = mapped_column(String(64), nullable=False)

    status: Mapped[RunStatus] = mapped_column(
        enum_col(RunStatus), nullable=False, default=RunStatus.QUEUED, index=True
    )
    trigger: Mapped[TriggerKind] = mapped_column(
        enum_col(TriggerKind), nullable=False, default=TriggerKind.MANUAL
    )

    attempt: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=2)
    queued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    run_after: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    worker_id: Mapped[str | None] = mapped_column(String(120))

    # Safety snapshot: what was authorized, and where the packets were allowed to go.
    resolved_ips: Mapped[list | None] = mapped_column(JSONB)
    scope_snapshot: Mapped[dict | None] = mapped_column(JSONB)
    authorized_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    authorization_ref: Mapped[str | None] = mapped_column(Text)

    argv: Mapped[list | None] = mapped_column(JSONB)
    tool_versions: Mapped[dict | None] = mapped_column(JSONB)
    timeout_seconds: Mapped[int | None] = mapped_column(Integer)
    exit_code: Mapped[int | None] = mapped_column(Integer)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    error_message: Mapped[str | None] = mapped_column(Text)
    observed_summary: Mapped[dict | None] = mapped_column(JSONB)

    retest_of_finding_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("findings.id", ondelete="SET NULL", use_alter=True, name="fk_run_retest_finding"),
        nullable=True,
        index=True,
    )

    __table_args__ = (
        Index("ix_runs_status_run_after", "status", "run_after"),
        Index("ix_runs_target_status", "target_id", "status"),
        Index(
            "ix_runs_queued",
            "run_after",
            postgresql_where=text("status = 'queued'"),
        ),
    )


class RunLog(Base):
    """Incremental output of a run, streamed to the UI by cursor."""

    __tablename__ = "run_logs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    run_id: Mapped[int] = mapped_column(
        ForeignKey("validation_runs.id", ondelete="CASCADE"), nullable=False
    )
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    stream: Mapped[StreamKind] = mapped_column(enum_col(StreamKind), nullable=False)
    level: Mapped[str] = mapped_column(String(16), nullable=False, default="info")
    message: Mapped[str] = mapped_column(Text, nullable=False)

    __table_args__ = (Index("ix_run_logs_run_id_id", "run_id", "id"),)


class Evidence(Base):
    """A captured artifact. Content-addressed, hashed at write time, never deleted."""

    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    run_id: Mapped[int] = mapped_column(
        ForeignKey("validation_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    kind: Mapped[EvidenceKind] = mapped_column(enum_col(EvidenceKind), nullable=False)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    rel_path: Mapped[str] = mapped_column(String(500), nullable=False, unique=True)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    mime: Mapped[str] = mapped_column(String(120), nullable=False, default="text/plain")
    truncated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    detail: Mapped[dict | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (Index("ix_evidence_run_kind", "run_id", "kind"),)
