"""Registry CRUD over HTTP, with attention to where policy meets the API.

The scope endpoints are the interesting ones: they are the only place a request
can be refused for *policy* reasons rather than schema reasons, and the refusal
has to arrive as a readable 400 at the moment a human is looking at the screen.
"""

from __future__ import annotations

from app.models.enums import RunStatus, Severity
from app.models.registry import Control, Scope
from app.models.testing import ValidationRun, ValidationTest, ValidationTestVersion
from tests.conftest import csrf_headers, login


def make_scope(client, **overrides) -> dict:
    payload = {
        "name": overrides.pop("name", "lab"),
        "description": "local test lab",
        "is_lab": True,
        "entries": [
            {"kind": "host", "value": "127.0.0.1", "ports": "8081-8084,8443", "protocol": "tcp"}
        ],
    }
    payload.update(overrides)
    response = client.post("/api/scopes", json=payload, headers=csrf_headers(client))
    assert response.status_code == 201, response.text
    return response.json()


# ---------------------------------------------------------------- frameworks --


def test_framework_crud(admin_client, db):
    created = admin_client.post(
        "/api/frameworks",
        json={"key": "NIST-800-53", "name": "NIST SP 800-53", "version": "r5"},
        headers=csrf_headers(admin_client),
    )
    assert created.status_code == 201
    framework = created.json()

    assert admin_client.get("/api/frameworks").json()[0]["key"] == "NIST-800-53"
    assert admin_client.get(f"/api/frameworks/{framework['id']}").json()["version"] == "r5"

    patched = admin_client.patch(
        f"/api/frameworks/{framework['id']}",
        json={"version": "r5.1"},
        headers=csrf_headers(admin_client),
    )
    assert patched.status_code == 200
    assert patched.json()["version"] == "r5.1"

    assert (
        admin_client.delete(
            f"/api/frameworks/{framework['id']}", headers=csrf_headers(admin_client)
        ).status_code
        == 204
    )


def test_duplicate_framework_code_conflicts(admin_client):
    payload = {"key": "CIS", "name": "CIS Benchmarks"}
    first = admin_client.post("/api/frameworks", json=payload, headers=csrf_headers(admin_client))
    assert first.status_code == 201
    second = admin_client.post("/api/frameworks", json=payload, headers=csrf_headers(admin_client))
    assert second.status_code == 409


def test_framework_write_requires_authentication(client):
    assert client.post("/api/frameworks", json={"key": "X", "name": "X"}).status_code == 401


# ------------------------------------------------------------------ controls --


def test_control_crud_and_framework_mapping(admin_client):
    framework = admin_client.post(
        "/api/frameworks", json={"key": "ASVS", "name": "OWASP ASVS"},
        headers=csrf_headers(admin_client),
    ).json()

    control = admin_client.post(
        "/api/controls",
        json={
            "key": "ASVS-14.4.1",
            "title": "HTTP security headers present",
            "category": "headers",
            "expected_state": "HSTS, CSP and X-Content-Type-Options are set",
        },
        headers=csrf_headers(admin_client),
    )
    assert control.status_code == 201
    control_id = control.json()["id"]

    mapping = admin_client.post(
        f"/api/controls/{control_id}/refs",
        json={"framework_id": framework["id"], "ref_code": "14.4.1"},
        headers=csrf_headers(admin_client),
    )
    assert mapping.status_code == 201

    detail = admin_client.get(f"/api/controls/{control_id}").json()
    assert [ref["ref_code"] for ref in detail["refs"]] == ["14.4.1"]

    # a control still mapped into a framework cannot be deleted
    blocked = admin_client.delete(
        f"/api/controls/{control_id}", headers=csrf_headers(admin_client)
    )
    assert blocked.status_code == 409

    assert (
        admin_client.delete(
            f"/api/controls/{control_id}/refs/{mapping.json()['id']}",
            headers=csrf_headers(admin_client),
        ).status_code
        == 204
    )
    assert (
        admin_client.delete(
            f"/api/controls/{control_id}", headers=csrf_headers(admin_client)
        ).status_code
        == 204
    )


def test_control_search_and_filter(admin_client):
    for code, category in (("A-1", "tls"), ("B-2", "headers"), ("C-3", "tls")):
        admin_client.post(
            "/api/controls",
            json={"key": code, "title": f"Control {code}", "category": category},
            headers=csrf_headers(admin_client),
        )
    assert len(admin_client.get("/api/controls?category=tls").json()) == 2
    assert len(admin_client.get("/api/controls?q=B-2").json()) == 1


# ------------------------------------------------------------------- targets --


def test_target_crud(admin_client):
    created = admin_client.post(
        "/api/targets",
        json={
            "name": "lab-headers",
            "target_type": "webapp",
            "host": "127.0.0.1",
            "port": 8081,
            "protocol": "tcp",
            "tags": ["lab", "web"],
            "criticality": "low",
        },
        headers=csrf_headers(admin_client),
    )
    assert created.status_code == 201
    target = created.json()
    assert target["host"] == "127.0.0.1"

    assert len(admin_client.get("/api/targets?tag=lab").json()) == 1
    assert len(admin_client.get("/api/targets?tag=nope").json()) == 0

    patched = admin_client.patch(
        f"/api/targets/{target['id']}",
        json={"criticality": "high", "enabled": False},
        headers=csrf_headers(admin_client),
    )
    assert patched.json()["criticality"] == "high"

    assert (
        admin_client.delete(
            f"/api/targets/{target['id']}", headers=csrf_headers(admin_client)
        ).status_code
        == 204
    )


def test_duplicate_target_endpoint_conflicts(admin_client):
    payload = {"name": "dup", "host": "10.0.0.9", "port": 443}
    assert (
        admin_client.post("/api/targets", json=payload, headers=csrf_headers(admin_client)).status_code
        == 201
    )
    assert (
        admin_client.post("/api/targets", json=payload, headers=csrf_headers(admin_client)).status_code
        == 409
    )


# -------------------------------------------------------------------- scopes --


def test_scope_with_lab_loopback_entry_is_accepted(admin_client):
    scope = make_scope(admin_client)
    assert scope["is_lab"] is True
    assert len(scope["entries"]) == 1
    assert scope["entries"][0]["value"] == "127.0.0.1"


def test_scope_creation_is_admin_only(analyst_user, client, db):
    """An analyst may run tests but may not widen the authorization boundary."""
    login(client, analyst_user.username)
    response = client.post(
        "/api/scopes",
        json={
            "name": "analyst-scope",
            "is_lab": True,
            "entries": [{"kind": "host", "value": "127.0.0.1", "ports": "8081"}],
        },
        headers=csrf_headers(client),
    )
    assert response.status_code == 403
    assert "administrator" in response.json()["detail"]


def test_scope_refuses_metadata_address(admin_client):
    response = admin_client.post(
        "/api/scopes",
        json={
            "name": "bad",
            "is_lab": True,
            "entries": [{"kind": "host", "value": "169.254.169.254", "ports": "80"}],
        },
        headers=csrf_headers(admin_client),
    )
    assert response.status_code == 400
    assert "metadata" in response.json()["detail"]


def test_scope_refuses_broad_range_without_the_flag(admin_client):
    response = admin_client.post(
        "/api/scopes",
        json={
            "name": "wide",
            "is_lab": True,
            "entries": [{"kind": "cidr", "value": "10.0.0.0/8", "ports": "443"}],
        },
        headers=csrf_headers(admin_client),
    )
    assert response.status_code == 400
    assert "allow_broad" in response.json()["detail"]


def test_scope_refuses_public_range_without_authorization(admin_client):
    response = admin_client.post(
        "/api/scopes",
        json={
            "name": "public",
            "allow_broad": True,
            "entries": [{"kind": "cidr", "value": "8.8.8.0/24", "ports": "443"}],
        },
        headers=csrf_headers(admin_client),
    )
    assert response.status_code == 400
    assert "authorization_ref" in response.json()["detail"]


def test_scope_refuses_loopback_without_lab_flag(admin_client):
    response = admin_client.post(
        "/api/scopes",
        json={
            "name": "notlab",
            "entries": [{"kind": "host", "value": "127.0.0.1", "ports": "8081"}],
        },
        headers=csrf_headers(admin_client),
    )
    assert response.status_code == 400
    assert "lab scope" in response.json()["detail"]


def test_a_refused_entry_leaves_no_partial_scope(admin_client, db):
    """A scope with one good and one refused entry must not be half-created."""
    response = admin_client.post(
        "/api/scopes",
        json={
            "name": "partial",
            "is_lab": True,
            "entries": [
                {"kind": "host", "value": "127.0.0.1", "ports": "8081"},
                {"kind": "host", "value": "169.254.169.254", "ports": "80"},
            ],
        },
        headers=csrf_headers(admin_client),
    )
    assert response.status_code == 400
    assert db.query(Scope).filter(Scope.name == "partial").first() is None


def test_adding_an_entry_to_an_existing_scope_is_validated(admin_client):
    scope = make_scope(admin_client, name="growable")
    refused = admin_client.post(
        f"/api/scopes/{scope['id']}/entries",
        json={"kind": "host", "value": "100.100.100.200", "ports": "80"},
        headers=csrf_headers(admin_client),
    )
    assert refused.status_code == 400
    assert "metadata" in refused.json()["detail"]

    accepted = admin_client.post(
        f"/api/scopes/{scope['id']}/entries",
        json={"kind": "host", "value": "127.0.0.2", "ports": "9000"},
        headers=csrf_headers(admin_client),
    )
    assert accepted.status_code == 201


def test_dropping_the_lab_flag_revalidates_existing_entries(admin_client):
    """Loosening or tightening flags must not leave entries that no longer hold."""
    scope = make_scope(admin_client, name="revalidate")
    response = admin_client.patch(
        f"/api/scopes/{scope['id']}",
        json={"is_lab": False},
        headers=csrf_headers(admin_client),
    )
    assert response.status_code == 400
    assert "lab scope" in response.json()["detail"]

    # the scope is unchanged after the refusal
    assert admin_client.get(f"/api/scopes/{scope['id']}").json()["is_lab"] is True


def test_target_can_be_authorized_by_linking_a_scope(admin_client):
    scope = make_scope(admin_client, name="linkable")
    target = admin_client.post(
        "/api/targets",
        json={"name": "lab-web", "host": "127.0.0.1", "port": 8081},
        headers=csrf_headers(admin_client),
    ).json()

    linked = admin_client.put(
        f"/api/targets/{target['id']}/scopes/{scope['id']}",
        headers=csrf_headers(admin_client),
    )
    assert linked.status_code == 204

    scopes = admin_client.get(f"/api/targets/{target['id']}/scopes").json()
    assert [s["name"] for s in scopes] == ["linkable"]

    # linking twice is idempotent rather than an error
    again = admin_client.put(
        f"/api/targets/{target['id']}/scopes/{scope['id']}",
        headers=csrf_headers(admin_client),
    )
    assert again.status_code == 204

    unlinked = admin_client.delete(
        f"/api/targets/{target['id']}/scopes/{scope['id']}",
        headers=csrf_headers(admin_client),
    )
    assert unlinked.status_code == 204
    assert admin_client.get(f"/api/targets/{target['id']}/scopes").json() == []


# --------------------------------------------- changing authorization stops work


def _authorized_target(admin_client, *, scope_name="stoppable", port=8081) -> tuple[dict, dict]:
    scope = make_scope(admin_client, name=scope_name)
    target = admin_client.post(
        "/api/targets",
        json={"name": f"t-{scope_name}", "host": "127.0.0.1", "port": port},
        headers=csrf_headers(admin_client),
    ).json()
    admin_client.put(
        f"/api/targets/{target['id']}/scopes/{scope['id']}", headers=csrf_headers(admin_client)
    )
    return scope, target


def _queued_run(db, target):
    """A run waiting in the queue, of the shape a worker would claim."""
    control = Control(key=f"ctl-{target['id']}", title=f"Control {target['id']}", category="tls")
    db.add(control)
    db.flush()
    test = ValidationTest(
        key=f"t-{target['id']}", name=f"Test {target['id']}", control_id=control.id,
        current_version=1,
    )
    db.add(test)
    db.flush()
    version = ValidationTestVersion(
        test_id=test.id, version=1, engine_id="http_headers", engine_params={},
        assertion={"fact": "http_header"}, control_id=control.id, severity=Severity.MEDIUM,
    )
    db.add(version)
    db.flush()
    run = ValidationRun(
        test_id=test.id, test_version_id=version.id, target_id=target["id"],
        engine_id="http_headers", status=RunStatus.QUEUED,
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def test_deactivating_a_scope_cancels_runs_it_was_authorizing(admin_client, db):
    """The kernel allow-list and the run queue both follow the scope: a run that
    was queued under the old authorization must not execute under the new one."""
    scope, target = _authorized_target(admin_client)
    run = _queued_run(db, target)

    patched = admin_client.patch(
        f"/api/scopes/{scope['id']}",
        json={"active": False},
        headers=csrf_headers(admin_client),
    )
    assert patched.status_code == 200

    db.refresh(run)
    assert run.status is RunStatus.CANCELLED
    assert "scope" in run.error_message


def test_removing_a_scope_entry_cancels_runs_for_its_targets(admin_client, db):
    scope, target = _authorized_target(admin_client, scope_name="entry-removal")
    run = _queued_run(db, target)

    removed = admin_client.delete(
        f"/api/scopes/{scope['id']}/entries/{scope['entries'][0]['id']}",
        headers=csrf_headers(admin_client),
    )
    assert removed.status_code == 204

    db.refresh(run)
    assert run.status is RunStatus.CANCELLED


def test_unlinking_a_target_cancels_runs_that_relied_on_the_link(admin_client, db):
    scope, target = _authorized_target(admin_client, scope_name="unlink")
    run = _queued_run(db, target)

    unlinked = admin_client.delete(
        f"/api/targets/{target['id']}/scopes/{scope['id']}", headers=csrf_headers(admin_client)
    )
    assert unlinked.status_code == 204

    db.refresh(run)
    assert run.status is RunStatus.CANCELLED


def test_a_running_run_is_flagged_rather_than_rewritten(admin_client, db):
    """A run already in a worker's hands cannot be un-started, so it is flagged
    for cancellation and its worker stops it on its next poll."""
    scope, target = _authorized_target(admin_client, scope_name="in-flight")
    run = _queued_run(db, target)
    run.status = RunStatus.RUNNING
    db.commit()

    patched = admin_client.patch(
        f"/api/scopes/{scope['id']}",
        json={"description": "narrowed while a scan was in flight"},
        headers=csrf_headers(admin_client),
    )
    assert patched.status_code == 200

    body = admin_client.get(f"/api/runs/{run.id}").json()
    assert body["status"] == "running"
    assert body["cancel_requested"] is True


def test_creating_a_scope_does_not_touch_unrelated_runs(admin_client, db):
    """Only the changed scope's targets stop - widening or adding elsewhere
    must not interrupt work."""
    _, target = _authorized_target(admin_client, scope_name="untouched")
    run = _queued_run(db, target)

    make_scope(admin_client, name="somewhere-else")

    db.refresh(run)
    assert run.status is RunStatus.QUEUED


# --------------------------------------------------------------- read access --

def test_viewer_can_read_but_not_write(viewer_user, admin_client, client, db):
    # admin_client and client are the same TestClient; the admin session is
    # used to seed the data, then the viewer login replaces it.
    admin_client.post(
        "/api/targets", json={"name": "readable", "host": "10.1.1.1", "port": 443},
        headers=csrf_headers(admin_client),
    )
    assert len(admin_client.get("/api/targets").json()) == 1

    login(client, viewer_user.username)
    assert client.get("/api/targets").status_code == 200
    assert len(client.get("/api/targets").json()) == 1
    assert client.get("/api/frameworks").status_code == 200

    refused = client.post(
        "/api/targets",
        json={"name": "nope", "host": "10.1.1.2", "port": 443},
        headers=csrf_headers(client),
    )
    assert refused.status_code == 403
    assert "analyst" in refused.json()["detail"]


def test_listing_requires_authentication(client):
    for path in ("/api/targets", "/api/scopes", "/api/controls", "/api/frameworks"):
        assert client.get(path).status_code == 401


def test_writes_without_a_csrf_token_are_refused(admin_client):
    response = admin_client.post(
        "/api/targets", json={"name": "no-csrf", "host": "10.1.1.3", "port": 443}
    )
    assert response.status_code == 403
    assert "CSRF" in response.json()["detail"]
