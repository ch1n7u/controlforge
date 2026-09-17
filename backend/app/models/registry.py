from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base
from app.models.enums import ScopeEntryKind, Severity, TargetType, enum_col
from app.models.mixins import TimestampMixin


class Framework(Base, TimestampMixin):
    __tablename__ = "frameworks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str | None] = mapped_column(String(64))
    description: Mapped[str | None] = mapped_column(Text)
    source: Mapped[str | None] = mapped_column(String(255))
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    refs: Mapped[list["FrameworkRef"]] = relationship(
        back_populates="framework", cascade="all, delete-orphan"
    )


class Control(Base, TimestampMixin):
    """A framework-agnostic technical control that can be validated by tests."""

    __tablename__ = "controls"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(String(80), unique=True, nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str | None] = mapped_column(String(80), index=True)
    description: Mapped[str | None] = mapped_column(Text)
    expected_state: Mapped[str | None] = mapped_column(Text)
    default_severity: Mapped[Severity] = mapped_column(
        enum_col(Severity), nullable=False, default=Severity.MEDIUM
    )
    remediation: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    refs: Mapped[list["FrameworkRef"]] = relationship(
        back_populates="control", cascade="all, delete-orphan"
    )


class FrameworkRef(Base):
    """Maps a canonical control onto a framework's own identifier (e.g. AC-2)."""

    __tablename__ = "framework_refs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    framework_id: Mapped[int] = mapped_column(
        ForeignKey("frameworks.id", ondelete="CASCADE"), nullable=False, index=True
    )
    control_id: Mapped[int] = mapped_column(
        ForeignKey("controls.id", ondelete="CASCADE"), nullable=False, index=True
    )
    ref_code: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str | None] = mapped_column(String(255))
    note: Mapped[str | None] = mapped_column(Text)

    framework: Mapped[Framework] = relationship(back_populates="refs")
    control: Mapped[Control] = relationship(back_populates="refs")

    __table_args__ = (UniqueConstraint("framework_id", "ref_code", name="uq_framework_ref_code"),)


class Target(Base, TimestampMixin):
    """A canonical asset under test: host + port + protocol + optional path.

    Targets are never free-form strings at execution time; the tuple below is
    the identity the whole system agrees on.
    """

    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    target_type: Mapped[TargetType] = mapped_column(enum_col(TargetType), nullable=False)
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    protocol: Mapped[str] = mapped_column(String(16), nullable=False, default="tcp")
    path: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    tags: Mapped[list[str]] = mapped_column(ARRAY(String(64)), nullable=False, default=list)
    criticality: Mapped[Severity] = mapped_column(
        enum_col(Severity), nullable=False, default=Severity.MEDIUM
    )
    owner: Mapped[str | None] = mapped_column(String(160))
    notes: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    scopes: Mapped[list["TargetScope"]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint("host", "port", "protocol", "path", name="uq_target_identity"),
        CheckConstraint("port >= 0 AND port <= 65535", name="ck_target_port_range"),
    )

    def endpoint(self) -> str:
        if self.protocol in ("http", "https"):
            suffix = f":{self.port}" if self.port not in (80, 443) else ""
            return f"{self.protocol}://{self.host}{suffix}{self.path}"
        if self.port:
            return f"{self.protocol}://{self.host}:{self.port}"
        return f"{self.protocol}://{self.host}"


class Scope(Base, TimestampMixin):
    """An authorization boundary: the only targets the platform may ever touch."""

    __tablename__ = "scopes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(160), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    authorization_ref: Mapped[str | None] = mapped_column(Text)
    approved_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    allow_broad: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_lab: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    entries: Mapped[list["ScopeEntry"]] = relationship(
        back_populates="scope", cascade="all, delete-orphan"
    )
    targets: Mapped[list["TargetScope"]] = relationship(
        back_populates="scope", cascade="all, delete-orphan"
    )


class ScopeEntry(Base):
    __tablename__ = "scope_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scope_id: Mapped[int] = mapped_column(
        ForeignKey("scopes.id", ondelete="CASCADE"), nullable=False, index=True
    )
    kind: Mapped[ScopeEntryKind] = mapped_column(enum_col(ScopeEntryKind), nullable=False)
    value: Mapped[str] = mapped_column(String(255), nullable=False)
    ports: Mapped[str] = mapped_column(String(255), nullable=False, default="any")
    protocol: Mapped[str] = mapped_column(String(16), nullable=False, default="tcp")
    note: Mapped[str | None] = mapped_column(Text)

    scope: Mapped[Scope] = relationship(back_populates="entries")


class TargetScope(Base):
    __tablename__ = "target_scopes"

    target_id: Mapped[int] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), primary_key=True
    )
    scope_id: Mapped[int] = mapped_column(
        ForeignKey("scopes.id", ondelete="CASCADE"), primary_key=True
    )
    linked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default="now()"
    )
    linked_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )

    target: Mapped[Target] = relationship(back_populates="scopes")
    scope: Mapped[Scope] = relationship(back_populates="targets")

    __table_args__ = (Index("ix_target_scopes_scope", "scope_id"),)


class Setting(Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    value: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default="now()"
    )
    updated_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
