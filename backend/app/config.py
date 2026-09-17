"""Runtime configuration, loaded from the environment.

In production the systemd units supply these via EnvironmentFile=
/etc/valtros/valtros.env. For local development the same file is
read directly when the process is allowed to see it.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

ENV_FILE_CANDIDATES = tuple(
    path
    for path in (
        # The systemd units pass the settings in as real environment variables,
        # so this path only matters for command-line runs (alembic, the seeder)
        # that are started without a unit. VALTROS_ENV_FILE lets those runs work
        # when the install did not use the default config directory.
        os.environ.get("VALTROS_ENV_FILE", "/etc/valtros/valtros.env"),
        os.path.join(os.path.dirname(__file__), "..", "..", ".env"),
    )
    if path
)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="VALTROS_",
        env_file=ENV_FILE_CANDIDATES,
        env_file_encoding="utf-8",
        extra="ignore",
    )

    env: str = "production"
    db_url: str = "postgresql+psycopg://valtros@127.0.0.1:5432/valtros"
    secret_key: str = ""
    evidence_dir: Path = Path("/var/lib/valtros/evidence")
    audit_jsonl_path: Path = Path("/var/log/valtros/audit.jsonl")
    admin_initial_password: str | None = None

    # --- sessions -----------------------------------------------------------
    session_ttl_hours: int = 12
    session_idle_timeout_minutes: int = 60
    cookie_name: str = "cf_session"
    csrf_cookie_name: str = "cf_csrf"
    cookie_secure: bool = False  # local HTTP deployment; set true behind TLS

    # --- execution limits ---------------------------------------------------
    max_concurrent_runs: int = 2
    per_target_concurrency: int = 1
    max_run_attempts: int = 2
    lease_seconds: int = 120
    heartbeat_seconds: int = 15
    worker_poll_seconds: float = 2.0
    reaper_interval_seconds: int = 30
    run_log_max_lines: int = 20000
    evidence_max_bytes: int = 64 * 1024 * 1024  # per artifact cap
    stream_byte_cap: int = 8 * 1024 * 1024  # captured stdout+stderr per run

    # --- safety -------------------------------------------------------------
    safe_mode: bool = True
    allow_private_ranges: bool = True  # RFC1918/loopback allowed only when scoped
    kill_switch: bool = False

    # --- bootstrap ----------------------------------------------------------
    seed_admin_username: str = "admin"
    autoseed: bool = True

    api_host: str = "127.0.0.1"
    api_port: int = 8000
    cors_origins: list[str] = Field(default_factory=list)

    @property
    def is_dev(self) -> bool:
        return self.env.lower() in {"dev", "development", "local"}


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    settings = Settings()
    if not settings.secret_key:
        raise RuntimeError(
            "VALTROS_SECRET_KEY is not set. Run scripts/bootstrap_db.sh to "
            "generate /etc/valtros/valtros.env, or export the variable."
        )
    return settings
