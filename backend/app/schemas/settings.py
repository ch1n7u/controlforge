"""Settings that an administrator can change without a redeploy.

Each key has a schema, so a typo produces a readable 400 instead of a row of
JSON that the runner silently ignores. Every write is audited.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.config import get_settings
from app.models.enums import Severity


class StrictSettings(BaseModel):
    """Strict on purpose.

    Lax mode turns ``"yes"`` into ``True`` and ``"3"`` into ``3``. For an
    operator-facing kill switch, silently interpreting a value the operator did
    not write is the wrong kind of helpful - the settings page should say the
    value is wrong, not quietly do something else.
    """

    model_config = ConfigDict(extra="forbid", strict=True)


class SafetySettings(StrictSettings):
    """Runtime switches an operator can throw without touching the host."""

    kill_switch: bool = Field(
        default=False,
        description="Stop claiming new runs. In-flight runs finish or are cancelled by hand.",
    )
    safe_mode: bool = Field(
        default=True,
        description="Restrict engines to their non-intrusive argument templates.",
    )
    max_concurrent_runs: int = Field(default=2, ge=1, le=16)


class RunnerSettings(StrictSettings):
    default_timeout_seconds: int = Field(default=300, ge=10, le=3600)
    max_attempts: int = Field(default=2, ge=1, le=5)
    lease_seconds: int = Field(default=120, ge=30, le=1800)
    max_output_bytes: int = Field(
        default=4 * 1024 * 1024,
        ge=64 * 1024,
        le=64 * 1024 * 1024,
        description="Hard cap on captured stdout/stderr per run.",
    )


class StalenessSettings(StrictSettings):
    """How long a validation result stays meaningful before it is called stale."""

    max_age_hours: int = Field(default=168, ge=1, le=8760)
    on_breach: str = Field(default="mark_stale", pattern=r"^(mark_stale|queue_run)$")
    # Enum fields stay lax: strict mode would demand the enum member, and the
    # API speaks to clients that send the value as a plain string.
    severity_floor: Severity = Field(default=Severity.MEDIUM, strict=False)


SETTING_SCHEMAS: dict[str, type[BaseModel]] = {
    "safety": SafetySettings,
    "runner": RunnerSettings,
    "staleness": StalenessSettings,
}

SETTING_KEYS = tuple(sorted(SETTING_SCHEMAS))


def defaults() -> dict[str, dict[str, Any]]:
    """The values a missing row falls back to.

    ``safety`` is seeded from the environment so a boot-time kill switch is
    honoured, but once a row exists the database is the single source of truth -
    otherwise the UI could flip the switch and have the API disagree.
    """
    env = get_settings()
    safety = SafetySettings(
        kill_switch=env.kill_switch,
        safe_mode=env.safe_mode,
    )
    return {
        "safety": safety.model_dump(mode="json"),
        "runner": RunnerSettings().model_dump(mode="json"),
        "staleness": StalenessSettings().model_dump(mode="json"),
    }


def validate_value(key: str, value: Any) -> dict[str, Any]:
    schema = SETTING_SCHEMAS.get(key)
    if schema is None:
        raise KeyError(key)
    try:
        return schema.model_validate(value).model_dump(mode="json")
    except Exception as exc:
        raise ValueError(f"{key} rejected this value: {' '.join(str(exc).split())[:600]}")


class SettingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    key: str
    value: dict[str, Any]
    updated_at: datetime
    updated_by_user_id: int | None = None
    is_default: bool = False


class SettingUpdate(BaseModel):
    value: dict[str, Any]
