"""Schemas for validation tests, their immutable versions, and the catalogue."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.core.assertions import AssertionInvalid, validate_assertion
from app.engines.catalogue import ENGINES, EngineSpec, get_engine
from app.models.enums import Severity, TargetType

MAX_ENGINE_PARAMS_BYTES = 8192
MAX_ASSERTION_BYTES = 32768


def _validate_engine_params(spec: EngineSpec, params: dict[str, Any]) -> dict[str, Any]:
    import json

    blob = json.dumps(params, default=str)
    if len(blob) > MAX_ENGINE_PARAMS_BYTES:
        raise ValueError(
            f"engine parameters exceed {MAX_ENGINE_PARAMS_BYTES} bytes of JSON"
        )
    try:
        validated = spec.params.model_validate(params)
    except Exception as exc:  # pydantic ValidationError -> readable 400
        raise ValueError(f"{spec.id} rejected these parameters: {_short(exc)}") from exc
    return validated.model_dump(mode="json")


def _validate_assertion_size(assertion: dict[str, Any]) -> None:
    import json

    if len(json.dumps(assertion, default=str)) > MAX_ASSERTION_BYTES:
        raise ValueError(
            f"assertion exceeds {MAX_ASSERTION_BYTES} bytes of JSON"
        )


def _short(exc: Exception) -> str:
    """Collapse a pydantic ValidationError into one line for an API message."""
    return " ".join(str(exc).split())[:600]


class TargetSelector(BaseModel):
    """Which targets a test applies to. Empty means "any target the engine accepts".

    The three fields are ANDed. Target types are intersected with what the
    engine can actually run against, so a test cannot be aimed at a target the
    engine would refuse.
    """

    model_config = ConfigDict(extra="forbid")

    target_ids: list[int] = Field(default_factory=list, max_length=256)
    tags: list[str] = Field(default_factory=list, max_length=32)
    target_types: list[TargetType] = Field(default_factory=list, max_length=8)

    @model_validator(mode="after")
    def _no_duplicates(self) -> "TargetSelector":
        if len(set(self.target_ids)) != len(self.target_ids):
            raise ValueError("target_ids contains duplicates")
        if len(set(self.tags)) != len(self.tags):
            raise ValueError("tags contains duplicates")
        if len(set(self.target_types)) != len(self.target_types):
            raise ValueError("target_types contains duplicates")
        return self


class EngineOut(BaseModel):
    id: str
    title: str
    description: str
    fact_types: list[str]
    target_types: list[str]
    default_timeout: int
    mutating: bool
    internal: bool
    notes: str
    params_schema: dict[str, Any]


class TestVersionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    test_id: int
    version: int
    engine_id: str
    engine_params: dict[str, Any]
    assertion: dict[str, Any]
    control_id: int
    severity: Severity
    note: str | None = None
    created_by_user_id: int | None = None
    created_at: datetime


class TestVersionCreate(BaseModel):
    """The executable definition. There is no update schema on purpose.

    Changing what a test runs means publishing a new version, because runs and
    findings point at a version - editing one in place would silently rewrite
    the meaning of every result already recorded against it.
    """

    engine_id: str = Field(min_length=1, max_length=64)
    engine_params: dict[str, Any] = Field(default_factory=dict)
    assertion: dict[str, Any]
    severity: Severity | None = Field(
        default=None,
        description="Defaults to the control's severity when omitted.",
    )
    note: str | None = Field(default=None, max_length=2000)

    @model_validator(mode="after")
    def _engine_and_assertion_agree(self) -> "TestVersionCreate":
        spec = get_engine(self.engine_id)
        if spec is None:
            known = ", ".join(sorted(ENGINES))
            raise ValueError(f"unknown engine {self.engine_id!r} (available: {known})")

        self.engine_params = _validate_engine_params(spec, self.engine_params)

        _validate_assertion_size(self.assertion)
        try:
            validate_assertion(self.assertion, frozenset(spec.fact_types))
        except AssertionInvalid as exc:
            raise ValueError(str(exc)) from exc
        return self


class ValidationTestOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    key: str
    name: str
    description: str | None = None
    control_id: int
    tags: list[str] = Field(default_factory=list)
    target_selector: dict[str, Any] = Field(default_factory=dict)
    enabled: bool
    current_version: int
    created_at: datetime
    updated_at: datetime | None = None


class ValidationTestDetail(ValidationTestOut):
    versions: list[TestVersionOut] = Field(default_factory=list)


class ValidationTestCreate(BaseModel):
    key: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9._-]+$")
    name: str = Field(min_length=1, max_length=200)
    description: str | None = None
    control_id: int
    tags: list[str] = Field(default_factory=list, max_length=32)
    target_selector: TargetSelector = Field(default_factory=TargetSelector)
    enabled: bool = True
    version: TestVersionCreate

    @model_validator(mode="after")
    def _selector_matches_the_engine(self) -> "ValidationTestCreate":
        spec = get_engine(self.version.engine_id)
        if spec is None:  # already reported by TestVersionCreate
            return self
        chosen = self.target_selector.target_types
        if not chosen:
            return self
        runnable = set(spec.target_types)
        impossible = [t.value for t in chosen if t not in runnable]
        if impossible:
            raise ValueError(
                f"engine {spec.id!r} cannot run against target type(s) "
                f"{', '.join(impossible)}; it accepts "
                f"{', '.join(t.value for t in spec.target_types)}"
            )
        return self


class ValidationTestUpdate(BaseModel):
    """Metadata only. The executable definition changes through a new version."""

    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = None
    tags: list[str] | None = Field(default=None, max_length=32)
    target_selector: TargetSelector | None = None
    enabled: bool | None = None
