"""Schemas for the control registry: frameworks, controls, targets, scopes."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.enums import ScopeEntryKind, Severity, TargetType


class FrameworkOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    key: str
    name: str
    version: str | None = None
    description: str | None = None
    source: str | None = None
    enabled: bool
    created_at: datetime


class FrameworkCreate(BaseModel):
    key: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    name: str = Field(min_length=1, max_length=255)
    version: str | None = Field(default=None, max_length=64)
    description: str | None = None
    source: str | None = Field(default=None, max_length=255)
    enabled: bool = True


class FrameworkUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    version: str | None = Field(default=None, max_length=64)
    description: str | None = None
    source: str | None = Field(default=None, max_length=255)
    enabled: bool | None = None


class FrameworkRefOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    framework_id: int
    control_id: int
    ref_code: str
    title: str | None = None


class ControlOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    key: str
    title: str
    category: str | None = None
    description: str | None = None
    expected_state: str | None = None
    default_severity: Severity
    remediation: str | None = None
    enabled: bool
    created_at: datetime
    refs: list[FrameworkRefOut] = Field(default_factory=list)


class ControlCreate(BaseModel):
    key: str = Field(min_length=1, max_length=80)
    title: str = Field(min_length=1, max_length=255)
    category: str | None = Field(default=None, max_length=80)
    description: str | None = None
    expected_state: str | None = None
    default_severity: Severity = Severity.MEDIUM
    remediation: str | None = None
    enabled: bool = True


class ControlUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=255)
    category: str | None = Field(default=None, max_length=80)
    description: str | None = None
    expected_state: str | None = None
    default_severity: Severity | None = None
    remediation: str | None = None
    enabled: bool | None = None


class FrameworkRefCreate(BaseModel):
    framework_id: int
    ref_code: str = Field(min_length=1, max_length=64)
    title: str | None = Field(default=None, max_length=255)


# ------------------------------------------------------------------ targets ---


class TargetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    target_type: TargetType
    host: str
    port: int
    protocol: str
    path: str
    tags: list[str] = Field(default_factory=list)
    criticality: Severity
    owner: str | None = None
    notes: str | None = None
    enabled: bool
    created_at: datetime


class TargetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    target_type: TargetType = TargetType.HOST
    host: str = Field(min_length=1, max_length=255)
    # 0 means "no port", which is legitimate for a host-level target
    port: int = Field(default=0, ge=0, le=65535)
    protocol: str = Field(default="tcp", max_length=16)
    path: str = Field(default="", max_length=255)
    tags: list[str] = Field(default_factory=list, max_length=32)
    criticality: Severity = Severity.MEDIUM
    owner: str | None = Field(default=None, max_length=160)
    notes: str | None = None
    enabled: bool = True

    @field_validator("tags")
    @classmethod
    def _clean_tags(cls, value: list[str]) -> list[str]:
        return [tag.strip()[:64] for tag in value if tag.strip()]


class TargetUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=160)
    host: str | None = Field(default=None, min_length=1, max_length=255)
    port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = Field(default=None, max_length=16)
    path: str | None = Field(default=None, max_length=255)
    tags: list[str] | None = None
    criticality: Severity | None = None
    owner: str | None = Field(default=None, max_length=160)
    notes: str | None = None
    enabled: bool | None = None


# ------------------------------------------------------------------- scopes ---


class ScopeEntryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    kind: ScopeEntryKind
    value: str
    ports: str
    protocol: str
    note: str | None = None


class ScopeEntryCreate(BaseModel):
    kind: ScopeEntryKind
    value: str = Field(min_length=1, max_length=255)
    ports: str = Field(min_length=1, max_length=255)
    protocol: str = Field(default="tcp", max_length=16)
    note: str | None = None


class ScopeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str | None = None
    authorization_ref: str | None = None
    approved_by_user_id: int | None = None
    allow_broad: bool
    is_lab: bool
    active: bool
    expires_at: datetime | None = None
    created_at: datetime
    entries: list[ScopeEntryOut] = Field(default_factory=list)


class ScopeCreate(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    description: str | None = None
    authorization_ref: str | None = None
    allow_broad: bool = False
    is_lab: bool = False
    expires_at: datetime | None = None
    entries: list[ScopeEntryCreate] = Field(default_factory=list, max_length=256)


class ScopeUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=160)
    description: str | None = None
    authorization_ref: str | None = None
    allow_broad: bool | None = None
    is_lab: bool | None = None
    active: bool | None = None
    expires_at: datetime | None = None


class TargetScopeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    target_id: int
    scope_id: int
    linked_at: datetime
