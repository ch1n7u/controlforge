"""CONTROLFORGE API application."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from app.config import get_settings
from app.db import SessionLocal, engine

VERSION = "0.1.0"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("controlforge")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    logger.info(
        "CONTROLFORGE %s starting (env=%s, safe_mode=%s, evidence=%s)",
        VERSION,
        settings.env,
        settings.safe_mode,
        settings.evidence_dir,
    )
    yield
    engine.dispose()
    logger.info("CONTROLFORGE stopped")


_settings = get_settings()

app = FastAPI(
    title="CONTROLFORGE",
    version=VERSION,
    description="Continuous security control validation and effectiveness testing.",
    # A platform built to constrain what may reach a target should not publish
    # its own full API surface to everyone who can open the dashboard on the
    # LAN. The interactive schema is a development convenience, so it is served
    # only when CONTROLFORGE_ENV says this is a development instance; the SPA
    # talks to the API directly and never reads the schema.
    docs_url="/api/docs" if _settings.is_dev else None,
    redoc_url=None,
    openapi_url="/api/openapi.json" if _settings.is_dev else None,
    lifespan=lifespan,
)
if _settings.cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


@app.get("/api/health", tags=["system"])
def health() -> dict:
    """Liveness plus a real database round-trip."""
    db_ok = True
    db_error = None
    try:
        with SessionLocal() as session:
            session.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001 - reported, not raised
        db_ok = False
        db_error = str(exc)[:200]

    return {
        "status": "ok" if db_ok else "degraded",
        "version": VERSION,
        "database": {"ok": db_ok, "error": db_error},
        "safe_mode": _settings.safe_mode,
        "kill_switch": _settings.kill_switch,
    }


from app.api import audit as audit_api  # noqa: E402  (import after app construction)
from app.api import auth as auth_api  # noqa: E402
from app.api import dashboard as dashboard_api  # noqa: E402
from app.api import evidence as evidence_api  # noqa: E402
from app.api import findings as findings_api  # noqa: E402
from app.api import registry as registry_api  # noqa: E402
from app.api import runs as runs_api  # noqa: E402
from app.api import system as system_api  # noqa: E402
from app.api import testing as testing_api  # noqa: E402

app.include_router(auth_api.router)
app.include_router(auth_api.directory_router)
app.include_router(registry_api.router)
app.include_router(testing_api.router)
app.include_router(runs_api.router)
app.include_router(findings_api.router)
app.include_router(evidence_api.router)
app.include_router(dashboard_api.router)
app.include_router(audit_api.router)
app.include_router(system_api.router)
