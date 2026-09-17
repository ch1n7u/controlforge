"""Authentication, session, CSRF and RBAC behaviour."""

from __future__ import annotations

import pytest

from app.core.security import check_password_policy, hash_password, verify_password
from app.models.auth import User, UserSession
from app.models.enums import Role
from tests.conftest import TEST_ADMIN_PASSWORD, csrf_headers, login


def test_health_is_public(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["database"]["ok"] is True


def test_login_sets_httponly_cookie_and_returns_csrf(client, admin_user):
    response = client.post(
        "/api/auth/login",
        json={"username": admin_user.username, "password": TEST_ADMIN_PASSWORD},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["user"]["username"] == "admin"
    assert body["csrf_token"]

    set_cookie = response.headers["set-cookie"]
    assert "HttpOnly" in set_cookie
    assert "samesite=lax" in set_cookie.lower()
    # the raw password hash must never be serialised
    assert "scrypt$" not in response.text


def test_login_rejects_bad_password(client, admin_user):
    response = client.post(
        "/api/auth/login", json={"username": admin_user.username, "password": "wrong-password"}
    )
    assert response.status_code == 401


def test_login_rejects_unknown_user(client):
    response = client.post(
        "/api/auth/login", json={"username": "nobody", "password": "whatever-password"}
    )
    assert response.status_code == 401


def test_login_locks_account_after_repeated_failures(client, admin_user, db):
    for _ in range(5):
        client.post(
            "/api/auth/login",
            json={"username": admin_user.username, "password": "wrong-password"},
        )
    db.refresh(admin_user)
    assert admin_user.locked_until is not None

    # Correct password is refused while locked.
    response = client.post(
        "/api/auth/login",
        json={"username": admin_user.username, "password": TEST_ADMIN_PASSWORD},
    )
    assert response.status_code == 401
    assert "locked" in response.json()["detail"]


def test_me_requires_session(client):
    assert client.get("/api/auth/me").status_code == 401


def test_me_returns_user_and_csrf(admin_client):
    response = admin_client.get("/api/auth/me")
    assert response.status_code == 200
    assert response.json()["user"]["username"] == "admin"


def test_logout_revokes_session(admin_client, db):
    assert admin_client.get("/api/auth/me").status_code == 200
    response = admin_client.post("/api/auth/logout", headers=csrf_headers(admin_client))
    assert response.status_code == 200
    assert admin_client.get("/api/auth/me").status_code == 401

    sessions = db.query(UserSession).all()
    assert sessions and all(s.revoked_at is not None for s in sessions)


def test_logout_without_csrf_token_is_rejected(admin_client):
    """Logout is a state change, so it must carry the CSRF token."""
    response = admin_client.post("/api/auth/logout")
    assert response.status_code == 403
    assert "CSRF" in response.json()["detail"]
    # the session must survive the rejected request
    assert admin_client.get("/api/auth/me").status_code == 200


def test_csrf_token_must_match_the_session(admin_client):
    response = admin_client.post(
        "/api/auth/logout", headers={"X-CSRF-Token": "not-the-real-token"}
    )
    assert response.status_code == 403


def test_change_password_requires_current_password(admin_client):
    response = admin_client.post(
        "/api/auth/change-password",
        json={"current_password": "not-the-password", "new_password": "BrandNewPassword123"},
        headers=csrf_headers(admin_client),
    )
    assert response.status_code == 400


def test_change_password_enforces_policy(admin_client):
    response = admin_client.post(
        "/api/auth/change-password",
        json={"current_password": TEST_ADMIN_PASSWORD, "new_password": "weak"},
        headers=csrf_headers(admin_client),
    )
    assert response.status_code == 400
    assert "policy" in response.json()["detail"]


def test_change_password_succeeds_and_revokes_sessions(admin_client, db, admin_user):
    new_password = "RotatedPassword456"
    response = admin_client.post(
        "/api/auth/change-password",
        json={"current_password": TEST_ADMIN_PASSWORD, "new_password": new_password},
        headers=csrf_headers(admin_client),
    )
    assert response.status_code == 200

    db.refresh(admin_user)
    assert verify_password(new_password, admin_user.password_hash)
    assert admin_user.must_change_password is False
    # every session, including the one that made the change, is revoked
    assert admin_client.get("/api/auth/me").status_code == 401


def test_viewer_cannot_use_writer_dependency(viewer_user):
    """A viewer can authenticate, but ``require_writer`` must refuse them."""
    from fastapi import HTTPException

    from app.api.deps import AuthContext, require_writer

    # The role check runs before CSRF, so the request argument is never reached.
    context = AuthContext(user=viewer_user, session_record=None)
    with pytest.raises(HTTPException) as excinfo:
        require_writer(None, context)
    assert excinfo.value.status_code == 403


def test_password_hash_is_scrypt_and_verifies(db, admin_user):
    assert admin_user.password_hash.startswith("scrypt$")
    assert verify_password(TEST_ADMIN_PASSWORD, admin_user.password_hash)
    assert not verify_password("other", admin_user.password_hash)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("short", False),
        ("alllowercase123", False),
        ("NoDigitsHereAtAll", False),
        ("GoodPassword123", True),
    ],
)
def test_password_policy(raw, expected):
    problems = check_password_policy(raw)
    assert (problems == []) is expected
    if not expected:
        assert problems, "a rejected password must explain why"


def test_password_policy_accepts_a_hash_round_trip():
    encoded = hash_password("GoodPassword123")
    assert verify_password("GoodPassword123", encoded)
    assert not verify_password("GoodPassword124", encoded)


# ------------------------------------------------------- user directory ----


def test_the_user_directory_lists_active_accounts(admin_client, admin_user, viewer_user):
    response = admin_client.get("/api/users")
    assert response.status_code == 200, response.text
    usernames = {row["username"] for row in response.json()}
    assert {admin_user.username, viewer_user.username} <= usernames
    row = response.json()[0]
    assert set(row) == {
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


def test_the_user_directory_hides_deactivated_accounts_by_default(
    admin_client, db, viewer_user
):
    viewer_user.is_active = False
    db.commit()

    assert viewer_user.username not in {
        row["username"] for row in admin_client.get("/api/users").json()
    }
    assert viewer_user.username in {
        row["username"] for row in admin_client.get("/api/users?active_only=false").json()
    }


def test_the_user_directory_never_exposes_a_password_hash(admin_client):
    assert "password_hash" not in admin_client.get("/api/users").text


def test_the_user_directory_requires_a_session(client):
    assert client.get("/api/users").status_code == 401
