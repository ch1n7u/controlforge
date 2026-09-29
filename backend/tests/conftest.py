"""Pytest fixtures.

Tests run against a dedicated ``controlforge_test`` database, with evidence and
audit output redirected to a temporary directory, so a test run can never touch
production data or the real append-only audit trail.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

BACKEND_DIR = Path(__file__).resolve().parent.parent

# Redirect configuration *before* anything imports the settings singleton.
from sqlalchemy.engine import make_url  # noqa: E402

from app.config import Settings, get_settings  # noqa: E402
from app.core.security import hash_password  # noqa: E402

_base = Settings()
_url = make_url(_base.db_url)
# Idempotent: a second import of this module must not append the suffix twice.
_test_database = _url.database if _url.database.endswith("_test") else f"{_url.database}_test"
# Lets a second test run (an agent working on another part of the tree, say) use
# its own database instead of deadlocking with this one over TRUNCATE.
if override := os.environ.get("CONTROLFORGE_TEST_DB"):
    _test_database = override
TEST_DB_URL = _url.set(database=_test_database).render_as_string(hide_password=False)
_TMP = Path(tempfile.mkdtemp(prefix="controlforge-tests-"))

os.environ["CONTROLFORGE_DB_URL"] = TEST_DB_URL
os.environ["CONTROLFORGE_AUDIT_JSONL_PATH"] = str(_TMP / "audit.jsonl")
os.environ["CONTROLFORGE_EVIDENCE_DIR"] = str(_TMP / "evidence")
os.environ.setdefault("CONTROLFORGE_SECRET_KEY", _base.secret_key)
get_settings.cache_clear()

from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import text  # noqa: E402

from app.db import SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.models import User  # noqa: E402
from app.models.enums import Role  # noqa: E402
from app.seed import ensure_admin  # noqa: E402

TEST_ADMIN_PASSWORD = "TestAdminPassword123"


def _alembic_config() -> Config:
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    return config


@pytest.fixture(scope="session", autouse=True)
def migrated_database() -> None:
    command.upgrade(_alembic_config(), "head")


def _truncate_all() -> None:
    with engine.begin() as conn:
        tables = conn.execute(
            text(
                "SELECT tablename FROM pg_tables WHERE schemaname = 'public' "
                "AND tablename <> 'alembic_version'"
            )
        ).scalars().all()
        if tables:
            conn.execute(text("TRUNCATE " + ", ".join(f'"{t}"' for t in tables) + " CASCADE"))


@pytest.fixture(autouse=True)
def clean_database():
    _truncate_all()
    yield
    _truncate_all()


@pytest.fixture
def db():
    with SessionLocal() as session:
        yield session


@pytest.fixture
def admin_user(db) -> User:
    user = User(
        username="admin",
        role=Role.ADMIN,
        full_name="Test Administrator",
        password_hash=hash_password(TEST_ADMIN_PASSWORD),
        must_change_password=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def analyst_user(db) -> User:
    user = User(
        username="analyst",
        role=Role.ANALYST,
        full_name="Test Analyst",
        password_hash=hash_password(TEST_ADMIN_PASSWORD),
        must_change_password=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def viewer_user(db) -> User:
    user = User(
        username="viewer",
        role=Role.VIEWER,
        full_name="Test Viewer",
        password_hash=hash_password(TEST_ADMIN_PASSWORD),
        must_change_password=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def client() -> TestClient:
    with TestClient(app) as test_client:
        yield test_client


def login(client: TestClient, username: str = "admin", password: str = TEST_ADMIN_PASSWORD):
    response = client.post(
        "/api/auth/login", json={"username": username, "password": password}
    )
    assert response.status_code == 200, response.text
    return response.json()


def csrf_headers(client: TestClient) -> dict[str, str]:
    """Headers for a state-changing request by the currently logged-in client.

    The token is read from ``/api/auth/me`` rather than reused from the login
    response, so tests exercise the same path the SPA uses after a reload.
    """
    response = client.get("/api/auth/me")
    assert response.status_code == 200, response.text
    return {"X-CSRF-Token": response.json()["csrf_token"]}


@pytest.fixture
def admin_client(client, admin_user) -> TestClient:
    login(client, admin_user.username)
    return client


@pytest.fixture
def settings_paths() -> dict[str, str]:
    """Where this test run redirects evidence and the audit mirror."""
    return {
        "evidence_dir": os.environ["CONTROLFORGE_EVIDENCE_DIR"],
        "audit_jsonl_path": os.environ["CONTROLFORGE_AUDIT_JSONL_PATH"],
    }
