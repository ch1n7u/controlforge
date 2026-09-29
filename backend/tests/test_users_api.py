"""User administration: creating accounts and editing them.

Both writes are administrator-only and CSRF-checked; these tests exercise the
policy refusals, the self-protection rules and the session revocation that
accompanies deactivation and password resets.
"""

from __future__ import annotations

import json
from datetime import timedelta

from fastapi.testclient import TestClient

from app.core import sessions
from app.core.security import verify_password
from app.main import app
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.enums import Role
from tests.conftest import csrf_headers, login

NEW_PASSWORD = "CreatedPassword123"
ROTATED_PASSWORD = "RotatedPassword456"


def create_user(client, **overrides):
    """POST /api/users as the client's current session; returns the response."""
    payload = {
        "username": "new-user",
        "full_name": "New User",
        "role": "viewer",
        "password": NEW_PASSWORD,
    }
    payload.update(overrides)
    return client.post("/api/users", json=payload, headers=csrf_headers(client))


def make_user(client, **overrides) -> dict:
    response = create_user(client, **overrides)
    assert response.status_code == 201, response.text
    return response.json()


# ---------------------------------------------------------------- creating --


def test_admin_creates_a_user(admin_client):
    response = create_user(admin_client, username="casey", full_name="Casey Quinn", role="analyst")
    assert response.status_code == 201, response.text
    assert "scrypt$" not in response.text
    created = response.json()

    assert set(created) == {
        "id",
        "username",
        "email",
        "full_name",
        "role",
        "is_active",
        "must_change_password",
        "last_login_at",
        "created_at",
    }
    assert created["username"] == "casey"
    assert created["full_name"] == "Casey Quinn"
    assert created["role"] == "analyst"
    assert created["is_active"] is True
    assert created["must_change_password"] is True

    assert "casey" in {row["username"] for row in admin_client.get("/api/users").json()}
    assert "casey" in {
        row["username"]
        for row in admin_client.get("/api/users?active_only=false").json()
    }


def test_a_created_account_can_sign_in_with_its_temporary_password(admin_client, db):
    make_user(admin_client, username="jamie", password=NEW_PASSWORD)

    with TestClient(app) as user_client:
        body = login(user_client, "jamie", NEW_PASSWORD)
    assert body["user"]["must_change_password"] is True

    stored = db.query(User).filter_by(username="jamie").one()
    assert stored.password_hash.startswith("scrypt$")
    assert verify_password(NEW_PASSWORD, stored.password_hash)


def test_duplicate_username_is_a_conflict(admin_client, db):
    make_user(admin_client, username="taken")

    response = create_user(admin_client, username="taken")
    assert response.status_code == 409
    assert "taken" in response.json()["detail"]
    assert db.query(User).filter_by(username="taken").count() == 1


def test_a_rejected_password_leaves_no_account_behind(admin_client):
    response = create_user(admin_client, username="weak-user", password="weak")
    assert response.status_code == 400
    assert "policy" in response.json()["detail"]

    # The refused request must not have left a half-created row in the session.
    assert "weak-user" not in {
        row["username"]
        for row in admin_client.get("/api/users?active_only=false").json()
    }


def test_creating_a_user_requires_an_administrator(client, analyst_user, viewer_user):
    for username in (analyst_user.username, viewer_user.username):
        login(client, username)
        response = create_user(client, username="sneaky")
        assert response.status_code == 403
        assert "administrator" in response.json()["detail"]


def test_user_writes_require_a_csrf_token(admin_client, admin_user):
    created = admin_client.post(
        "/api/users",
        json={"username": "no-csrf", "role": "viewer", "password": NEW_PASSWORD},
    )
    assert created.status_code == 403
    assert "CSRF" in created.json()["detail"]

    patched = admin_client.patch(f"/api/users/{admin_user.id}", json={"full_name": "Nope"})
    assert patched.status_code == 403

    assert "no-csrf" not in {
        row["username"]
        for row in admin_client.get("/api/users?active_only=false").json()
    }


# ----------------------------------------------------------------- editing --


def test_patch_changes_the_role(admin_client):
    created = make_user(admin_client, username="riley", role="viewer")

    response = admin_client.patch(
        f"/api/users/{created['id']}",
        json={"role": "analyst"},
        headers=csrf_headers(admin_client),
    )
    assert response.status_code == 200
    assert response.json()["role"] == "analyst"


def test_patch_only_applies_supplied_fields(admin_client):
    created = make_user(admin_client, username="sky", full_name="Sky Blue", role="viewer")

    response = admin_client.patch(
        f"/api/users/{created['id']}",
        json={"role": "admin"},
        headers=csrf_headers(admin_client),
    )
    assert response.status_code == 200
    assert response.json()["role"] == "admin"
    assert response.json()["full_name"] == "Sky Blue"


def test_patch_can_clear_full_name(admin_client):
    created = make_user(admin_client, username="dana", full_name="Dana Doe")

    response = admin_client.patch(
        f"/api/users/{created['id']}",
        json={"full_name": None},
        headers=csrf_headers(admin_client),
    )
    assert response.status_code == 200
    assert response.json()["full_name"] is None


def test_updating_an_unknown_user_is_a_404(admin_client):
    response = admin_client.patch(
        "/api/users/999999", json={"full_name": "Nobody"}, headers=csrf_headers(admin_client)
    )
    assert response.status_code == 404
    assert "999999" in response.json()["detail"]


def test_updating_a_user_requires_an_administrator(client, admin_user, analyst_user):
    login(client, analyst_user.username)
    response = client.patch(
        f"/api/users/{admin_user.id}",
        json={"full_name": "Hacked"},
        headers=csrf_headers(client),
    )
    assert response.status_code == 403
    assert "administrator" in response.json()["detail"]


def test_deactivating_a_user_revokes_their_session(admin_client, analyst_user):
    with TestClient(app) as analyst_client:
        login(analyst_client, analyst_user.username)
        assert analyst_client.get("/api/auth/me").status_code == 200

        response = admin_client.patch(
            f"/api/users/{analyst_user.id}",
            json={"is_active": False},
            headers=csrf_headers(admin_client),
        )
        assert response.status_code == 200
        assert response.json()["is_active"] is False

        # The live session dies with the account, not at its idle timeout.
        assert analyst_client.get("/api/auth/me").status_code == 401


def test_reactivating_a_user_lifts_a_lockout(admin_client, viewer_user, db):
    viewer_user.is_active = False
    viewer_user.locked_until = sessions.utcnow() + timedelta(minutes=15)
    viewer_user.failed_login_count = 3
    db.commit()

    response = admin_client.patch(
        f"/api/users/{viewer_user.id}",
        json={"is_active": True},
        headers=csrf_headers(admin_client),
    )
    assert response.status_code == 200
    assert response.json()["is_active"] is True

    db.refresh(viewer_user)
    assert viewer_user.locked_until is None
    assert viewer_user.failed_login_count == 0


def test_resetting_a_password_enforces_policy_and_revokes_sessions(
    admin_client, analyst_user, db
):
    with TestClient(app) as analyst_client:
        login(analyst_client, analyst_user.username)
        assert analyst_client.get("/api/auth/me").status_code == 200

        refused = admin_client.patch(
            f"/api/users/{analyst_user.id}",
            json={"password": "weak"},
            headers=csrf_headers(admin_client),
        )
        assert refused.status_code == 400
        assert "policy" in refused.json()["detail"]
        # A refused reset must not disturb the account or its live session.
        assert analyst_client.get("/api/auth/me").status_code == 200

        rotated = admin_client.patch(
            f"/api/users/{analyst_user.id}",
            json={"password": ROTATED_PASSWORD},
            headers=csrf_headers(admin_client),
        )
        assert rotated.status_code == 200
        assert rotated.json()["must_change_password"] is True

        # An administrator-set password is temporary and kills every session.
        assert analyst_client.get("/api/auth/me").status_code == 401

    db.refresh(analyst_user)
    assert verify_password(ROTATED_PASSWORD, analyst_user.password_hash)
    assert analyst_user.must_change_password is True


# ------------------------------------------------------- self-protection ----


def test_an_admin_cannot_demote_or_deactivate_themselves(admin_client, admin_user, db):
    demote = admin_client.patch(
        f"/api/users/{admin_user.id}",
        json={"role": Role.VIEWER},
        headers=csrf_headers(admin_client),
    )
    assert demote.status_code == 400
    assert "own role" in demote.json()["detail"]

    deactivate = admin_client.patch(
        f"/api/users/{admin_user.id}",
        json={"is_active": False},
        headers=csrf_headers(admin_client),
    )
    assert deactivate.status_code == 400
    assert "own account" in deactivate.json()["detail"]

    db.refresh(admin_user)
    assert admin_user.role == Role.ADMIN
    assert admin_user.is_active is True

    # Editing their own name is still allowed.
    renamed = admin_client.patch(
        f"/api/users/{admin_user.id}",
        json={"full_name": "Renamed Administrator"},
        headers=csrf_headers(admin_client),
    )
    assert renamed.status_code == 200
    assert renamed.json()["full_name"] == "Renamed Administrator"


# ------------------------------------------------------------------ audit ----


def test_user_writes_are_audited_without_password_values(admin_client, db):
    created = make_user(admin_client, username="audited")
    response = admin_client.patch(
        f"/api/users/{created['id']}",
        json={"password": "AuditedPassword789", "full_name": "Audited Person"},
        headers=csrf_headers(admin_client),
    )
    assert response.status_code == 200

    rows = {
        row.action: row
        for row in db.query(AuditLog)
        .filter(AuditLog.action.in_(["user.create", "user.update"]))
        .all()
    }
    assert set(rows) == {"user.create", "user.update"}
    assert rows["user.create"].object_id == str(created["id"])
    assert rows["user.create"].after["username"] == "audited"
    assert "password" not in rows["user.create"].after

    update = rows["user.update"]
    assert update.object_id == str(created["id"])
    assert "password" in update.detail["fields"]
    assert "full_name" in update.detail["fields"]
    for row in rows.values():
        logged = json.dumps({"before": row.before, "after": row.after, "detail": row.detail})
        assert "AuditedPassword789" not in logged
        assert "CreatedPassword123" not in logged
