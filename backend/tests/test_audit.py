"""Audit trail: every meaningful action leaves a database row and a JSONL line."""

from __future__ import annotations

import json

from sqlalchemy import select

from app.models.audit import AuditLog
from tests.conftest import TEST_ADMIN_PASSWORD, csrf_headers


def _actions(db) -> list[str]:
    return db.execute(select(AuditLog.action).order_by(AuditLog.id)).scalars().all()


def test_successful_login_is_audited_with_actor_and_ip(client, db, admin_user):
    login = client.post(
        "/api/auth/login",
        json={"username": admin_user.username, "password": TEST_ADMIN_PASSWORD},
        headers={"X-Forwarded-For": "203.0.113.9, 127.0.0.1"},
    )
    assert login.status_code == 200

    rows = db.execute(select(AuditLog).where(AuditLog.action == "auth.login")).scalars().all()
    assert len(rows) == 1
    row = rows[0]
    assert row.actor_username == admin_user.username
    assert row.actor_user_id == admin_user.id
    # the left-most X-Forwarded-For entry is the originating client
    assert row.actor_ip == "203.0.113.9"
    assert row.outcome == "success"
    assert row.object_type == "user"
    # object_id is a string: audit rows reference heterogeneous object types
    assert row.object_id == str(admin_user.id)


def test_failed_login_is_audited_without_the_password(client, db, admin_user):
    response = client.post(
        "/api/auth/login",
        json={"username": admin_user.username, "password": "wrong-password-here"},
    )
    assert response.status_code == 401

    rows = db.execute(select(AuditLog).where(AuditLog.action == "auth.login")).scalars().all()
    assert len(rows) == 1
    assert rows[0].outcome == "failure"

    serialised = json.dumps(rows[0].detail or {}) + json.dumps(rows[0].before or {})
    assert "wrong-password-here" not in serialised


def test_failed_login_records_actor_for_a_known_account(client, db, admin_user):
    """A wrong password still identifies which real account was targeted."""
    client.post(
        "/api/auth/login",
        json={"username": admin_user.username, "password": "wrong-password-here"},
    )
    rows = db.execute(select(AuditLog).where(AuditLog.action == "auth.login")).scalars().all()
    assert len(rows) == 1
    assert rows[0].outcome == "failure"
    assert rows[0].actor_user_id == admin_user.id
    assert rows[0].actor_username == admin_user.username


def test_unknown_user_failure_does_not_claim_an_actor(client, db):
    """An unverified username must not be written as the acting identity.

    Anyone can type any name into the login form; recording it as ``actor``
    would let an attacker plant audit rows that look like another user's
    activity. The attempted name is kept in ``detail``, where it is clearly
    an input rather than an identity.
    """
    client.post(
        "/api/auth/login", json={"username": "ghost", "password": "wrong-password-here"}
    )
    rows = db.execute(select(AuditLog).where(AuditLog.action == "auth.login")).scalars().all()
    assert len(rows) == 1
    row = rows[0]
    assert row.outcome == "failure"
    assert row.actor_user_id is None
    assert row.actor_username is None
    assert row.detail["username"] == "ghost"
    assert row.detail["reason"] == "unknown_user"


def test_logout_and_password_change_are_audited(admin_client, db, admin_user):
    admin_client.post("/api/auth/logout", headers=csrf_headers(admin_client))
    assert "auth.logout" in _actions(db)

    admin_client.post(
        "/api/auth/login",
        json={"username": admin_user.username, "password": TEST_ADMIN_PASSWORD},
    )
    admin_client.post(
        "/api/auth/change-password",
        json={"current_password": TEST_ADMIN_PASSWORD, "new_password": "AnotherPassword789"},
        headers=csrf_headers(admin_client),
    )
    assert "auth.change_password" in _actions(db)


def test_audit_rows_are_append_only(admin_client, db):
    """The application never updates or deletes an audit row."""
    from app.core import audit as audit_module
    from app.models.audit import AuditLog as Model

    assert not hasattr(audit_module, "delete")
    assert not hasattr(audit_module, "update")
    # and the ORM model has no updated_at column to mutate
    assert not hasattr(Model, "updated_at")


def test_jsonl_sink_receives_every_event(client, db, admin_user, settings_paths):
    """The JSONL mirror is written for offline/tamper-evident retention."""
    import os

    client.post(
        "/api/auth/login",
        json={"username": admin_user.username, "password": TEST_ADMIN_PASSWORD},
    )
    path = settings_paths["audit_jsonl_path"]
    assert os.path.exists(path), f"audit JSONL not written to {path}"

    with open(path, encoding="utf-8") as handle:
        lines = [json.loads(line) for line in handle if line.strip()]
    assert any(entry.get("action") == "auth.login" for entry in lines)


def test_seeding_the_catalogue_is_audited(db):
    """Bootstrapping the catalogue changes what the platform will validate, so
    it is recorded like any other configuration change."""
    from app.seed.lab import seed_lab

    seed_lab(db)

    rows = db.execute(select(AuditLog).where(AuditLog.action == "catalog.seed")).scalars().all()
    assert len(rows) == 1
    row = rows[0]
    assert row.actor_user_id is None
    assert row.object_type == "catalog"
    assert set(row.detail) == {"framework", "control", "target", "scope", "test"}
    assert "cis-linux" in row.detail["framework"]
    assert "lab-headers" in row.detail["target"]


def test_reseeding_an_unchanged_catalogue_records_nothing(db):
    """The seeder is idempotent; a run that creates nothing has nothing to record."""
    from app.seed.lab import seed_lab

    seed_lab(db)
    seed_lab(db)

    rows = db.execute(select(AuditLog).where(AuditLog.action == "catalog.seed")).scalars().all()
    assert len(rows) == 1
