"""The audit API: the read side of an append-only trail.

The trail is written by ``app.core.audit`` and this router only lists it, so the
tests insert rows directly and check two things: that the storage vocabulary is
translated to the frontend's names exactly once (and correctly), and that the
filters mean equality rather than something fuzzier - a partial match on an
audit log reads as a complete answer when it is not one.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import delete

from app.main import app
from app.models.audit import AuditLog

BASE = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)

CONTRACT_FIELDS = {
    "id",
    "ts",
    "actor",
    "actor_user_id",
    "action",
    "entity_type",
    "entity_id",
    "summary",
    "detail",
    "ip_address",
    "user_agent",
    "request_id",
}


@pytest.fixture
def trail(db, admin_client):
    """An empty trail to write into.

    Logging in is itself audited, and these tests count rows, so the login's own
    entry is cleared before the test body inserts what it means to assert on.
    """
    db.execute(delete(AuditLog))
    db.commit()
    return db


def add_entry(
    db,
    *,
    action: str = "test.create",
    ts: datetime | None = None,
    actor=None,
    object_type: str | None = None,
    object_id: str | None = None,
    outcome: str = "success",
    actor_ip: str | None = None,
    correlation_id: str | None = None,
    detail: dict | None = None,
) -> AuditLog:
    row = AuditLog(
        ts=ts or BASE,
        actor_user_id=actor.id if actor else None,
        actor_username=actor.username if actor else None,
        actor_ip=actor_ip,
        action=action,
        object_type=object_type,
        object_id=object_id,
        outcome=outcome,
        correlation_id=correlation_id,
        detail=detail,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def parsed(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


# ------------------------------------------------------------------ shape --


def test_list_maps_the_audit_row_to_the_frontend_contract(trail, admin_client, admin_user):
    row = add_entry(
        trail,
        action="test.create",
        ts=BASE,
        actor=admin_user,
        object_type="test",
        object_id="42",
        actor_ip="203.0.113.9",
        correlation_id="req-abc",
        detail={"key": "hdr-hsts"},
    )

    response = admin_client.get("/api/audit")
    assert response.status_code == 200, response.text
    body = response.json()

    assert body["total"] == 1
    entry = body["items"][0]
    assert set(entry) == CONTRACT_FIELDS
    assert entry["id"] == row.id
    assert parsed(entry["ts"]) == BASE
    assert entry["actor"] == admin_user.username
    assert entry["actor_user_id"] == admin_user.id
    assert entry["action"] == "test.create"
    assert entry["entity_type"] == "test"
    assert entry["entity_id"] == "42"
    assert entry["summary"] == "test.create · test 42"
    assert entry["detail"] == {"key": "hdr-hsts"}
    assert entry["ip_address"] == "203.0.113.9"
    assert entry["user_agent"] is None, "not captured yet; the field is still in the contract"
    assert entry["request_id"] == "req-abc"


@pytest.mark.parametrize(
    "object_type,object_id,expected",
    [
        ("test", "42", "test.create · test 42"),
        ("test", None, "test.create · test"),
        (None, "42", "test.create · 42"),
        (None, None, "test.create"),
    ],
)
def test_summary_is_one_predictable_line(
    trail, admin_client, object_type, object_id, expected
):
    add_entry(trail, action="test.create", object_type=object_type, object_id=object_id)

    entry = admin_client.get("/api/audit").json()["items"][0]
    assert entry["summary"] == expected


def test_a_failed_action_is_still_listed(trail, admin_client, admin_user):
    """Failures are the entries most worth reading; nothing filters them out."""
    add_entry(trail, action="auth.login", actor=admin_user, outcome="failure")

    entry = admin_client.get("/api/audit").json()["items"][0]
    assert entry["action"] == "auth.login"
    assert entry["summary"] == "auth.login"


# ------------------------------------------------------------------ order --


def test_list_is_newest_first(trail, admin_client):
    oldest = add_entry(trail, action="auth.login", ts=BASE)
    middle = add_entry(trail, action="test.create", ts=BASE + timedelta(minutes=1))
    newest = add_entry(trail, action="test.update", ts=BASE + timedelta(minutes=2))

    items = admin_client.get("/api/audit").json()["items"]
    assert [item["id"] for item in items] == [newest.id, middle.id, oldest.id]


# ---------------------------------------------------------------- filters --


def test_list_filters(trail, admin_client, admin_user, analyst_user):
    add_entry(trail, action="test.create", actor=admin_user, object_type="test", object_id="1")
    add_entry(
        trail, action="finding.update", actor=analyst_user, object_type="finding", object_id="7"
    )
    add_entry(trail, action="test.create", object_type="test", object_id="2")

    by_actor = admin_client.get(f"/api/audit?actor_user_id={admin_user.id}").json()
    assert by_actor["total"] == 1
    assert by_actor["items"][0]["actor"] == admin_user.username

    by_action = admin_client.get("/api/audit?action=finding.update").json()
    assert by_action["total"] == 1
    assert by_action["items"][0]["entity_type"] == "finding"

    by_entity = admin_client.get("/api/audit?entity_type=test").json()
    assert by_entity["total"] == 2

    combined = admin_client.get(
        f"/api/audit?actor_user_id={admin_user.id}&action=test.create&entity_type=test"
    ).json()
    assert combined["total"] == 1
    assert combined["items"][0]["entity_id"] == "1"

    # Equality, not a substring search: "test" must not match "test.create",
    # or the reader would be handed a partial answer as if it were the whole.
    assert admin_client.get("/api/audit?action=test").json()["total"] == 0
    assert admin_client.get("/api/audit?action=nothing.here").json() == {
        "items": [],
        "total": 0,
    }


def test_list_paginates_without_losing_the_total(trail, admin_client):
    for index in range(3):
        add_entry(
            trail,
            action="test.create",
            object_type="test",
            object_id=str(index),
            ts=BASE + timedelta(minutes=index),
        )

    page = admin_client.get("/api/audit?limit=1&offset=1").json()
    assert page["total"] == 3
    assert [item["entity_id"] for item in page["items"]] == ["1"]

    assert admin_client.get("/api/audit?limit=201").status_code == 422
    assert admin_client.get("/api/audit?limit=0").status_code == 422


# ------------------------------------------------------------------- auth --


def test_audit_requires_authentication(client):
    assert client.get("/api/audit").status_code == 401
