"""Validation test authoring and settings over HTTP.

Two properties get most of the attention here:

* a test cannot be authored into a state that could only ever be
  INCONCLUSIVE, nor into one whose typo silently weakens a condition;
* a published version is immutable, because runs and findings point at it.
"""

from __future__ import annotations

import pytest

from app.main import app
from tests.conftest import csrf_headers, login


def make_control(client, **overrides) -> dict:
    payload = {
        "key": overrides.pop("key", "ASVS-14.4.1"),
        "title": overrides.pop("title", "HTTP security headers present"),
        "category": "headers",
        "default_severity": overrides.pop("default_severity", "medium"),
        "expected_state": "HSTS, CSP and X-Content-Type-Options are set",
    }
    payload.update(overrides)
    response = client.post("/api/controls", json=payload, headers=csrf_headers(client))
    assert response.status_code == 201, response.text
    return response.json()


def make_test(client, control_id: int, **overrides) -> dict:
    payload = {
        "key": overrides.pop("key", "hdr-hsts"),
        "name": overrides.pop("name", "HSTS header present"),
        "control_id": control_id,
        "tags": ["headers", "web"],
        "target_selector": {"target_types": ["webapp"]},
        "version": {
            "engine_id": "http_headers",
            "engine_params": {"path": "/"},
            "assertion": {
                "fact": "http_header",
                "where": {"value.name": "strict-transport-security"},
                "op": "exists",
            },
        },
    }
    payload.update(overrides)
    response = client.post("/api/tests", json=payload, headers=csrf_headers(client))
    return response


def created_test(client, control_id: int, **overrides) -> dict:
    response = make_test(client, control_id, **overrides)
    assert response.status_code == 201, response.text
    return response.json()


# ------------------------------------------------------------------- engines --


def test_engine_catalogue_is_exposed_for_authoring(admin_client):
    engines = admin_client.get("/api/engines").json()
    by_id = {engine["id"]: engine for engine in engines}
    assert set(by_id) == {
        "nmap",
        "tls_config",
        "http_headers",
        "http_exposure",
        "nuclei",
        "local_baseline",
    }
    # the UI renders parameter forms from this, so it has to be present
    assert "properties" in by_id["nmap"]["params_schema"]
    assert by_id["tls_config"]["mutating"] is False


def test_engine_catalogue_requires_authentication(client):
    assert client.get("/api/engines").status_code == 401


# --------------------------------------------------------- creating a test --


def test_create_test_publishes_version_one(admin_client):
    control = make_control(admin_client)
    test = created_test(admin_client, control["id"])
    assert test["current_version"] == 1
    assert [v["version"] for v in test["versions"]] == [1]
    assert test["versions"][0]["engine_id"] == "http_headers"


def test_version_severity_defaults_to_the_controls_severity(admin_client):
    control = make_control(admin_client, default_severity="high")
    test = created_test(admin_client, control["id"])
    assert test["versions"][0]["severity"] == "high"


def test_an_explicit_version_severity_wins(admin_client):
    control = make_control(admin_client, default_severity="high")
    test = created_test(
        admin_client, control["id"], version={
            "engine_id": "http_headers",
            "assertion": {"fact": "http_header"},
            "severity": "low",
        },
    )
    assert test["versions"][0]["severity"] == "low"


def test_duplicate_test_key_conflicts(admin_client):
    control = make_control(admin_client)
    created_test(admin_client, control["id"], key="dup-test")
    assert make_test(admin_client, control["id"], key="dup-test").status_code == 409


def test_a_test_needs_a_real_control(admin_client):
    response = make_test(admin_client, 999_999)
    assert response.status_code == 400
    assert "does not exist" in response.json()["detail"]


def test_an_unknown_engine_is_refused(admin_client):
    control = make_control(admin_client)
    response = make_test(
        admin_client,
        control["id"],
        version={"engine_id": "sqlmap", "assertion": {"fact": "http_header"}},
    )
    assert response.status_code == 422
    assert "unknown engine" in response.text


def test_an_assertion_over_a_fact_the_engine_cannot_emit_is_refused(admin_client):
    """Such a test could only ever be INCONCLUSIVE, so it is refused at authoring."""
    control = make_control(admin_client)
    response = make_test(
        admin_client,
        control["id"],
        version={
            "engine_id": "http_headers",
            "assertion": {"fact": "tls_certificate", "op": "exists"},
        },
    )
    assert response.status_code == 422
    assert "never emits" in response.text


def test_a_selector_aimed_at_a_target_type_the_engine_cannot_run_is_refused(admin_client):
    control = make_control(admin_client)
    response = make_test(
        admin_client,
        control["id"],
        target_selector={"target_types": ["ssh"]},
    )
    assert response.status_code == 422
    assert "cannot run against target type" in response.text


def test_an_unknown_engine_parameter_is_refused(admin_client):
    """A typo must not be dropped, or the engine would run with silent defaults."""
    control = make_control(admin_client)
    response = make_test(
        admin_client,
        control["id"],
        version={
            "engine_id": "http_headers",
            "engine_params": {"paths": "/wrong-name"},
            "assertion": {"fact": "http_header"},
        },
    )
    assert response.status_code == 422
    assert "rejected these parameters" in response.text


def test_unparseable_nmap_ports_are_refused(admin_client):
    control = make_control(admin_client)
    response = make_test(
        admin_client,
        control["id"],
        version={
            "engine_id": "nmap",
            "engine_params": {"ports": "not-ports"},
            "assertion": {"fact": "port_state"},
        },
    )
    assert response.status_code == 422


def test_nuclei_refuses_intrusive_template_classes(admin_client):
    """The engine catalogue is what keeps brute-force and fuzzing out."""
    control = make_control(admin_client)
    response = make_test(
        admin_client,
        control["id"],
        version={
            "engine_id": "nuclei",
            "engine_params": {"template_tags": ["fuzz", "brute-force"]},
            "assertion": {"fact": "nuclei_finding"},
        },
    )
    assert response.status_code == 422
    assert "unsupported template tags" in response.text


def test_local_baseline_refuses_a_path_outside_its_allowlist(admin_client):
    control = make_control(admin_client)
    response = make_test(
        admin_client,
        control["id"],
        version={
            "engine_id": "local_baseline",
            "engine_params": {"paths": ["/etc/shadow", "/root/.ssh/id_rsa"]},
            "assertion": {"fact": "file_mode"},
        },
    )
    assert response.status_code == 422
    assert "unsupported paths" in response.text


def test_an_overlong_assertion_is_refused(admin_client):
    control = make_control(admin_client)
    huge = {
        "all": [
            {
                "fact": "http_header",
                "where": {"value.name": f"header-{i}"},
                "reason": "x" * 480,
            }
            for i in range(64)
        ]
    }
    response = make_test(
        admin_client, control["id"], version={"engine_id": "http_headers", "assertion": huge}
    )
    assert response.status_code == 422


# ---------------------------------------------------------------- filtering --


def test_tests_can_be_filtered(admin_client):
    control = make_control(admin_client)
    created_test(admin_client, control["id"], key="a-one", tags=["headers"])
    created_test(admin_client, control["id"], key="b-two", tags=["tls"], enabled=False)

    assert len(admin_client.get("/api/tests").json()) == 2
    assert [t["key"] for t in admin_client.get("/api/tests?tag=tls").json()] == ["b-two"]
    assert [t["key"] for t in admin_client.get("/api/tests?enabled=false").json()] == ["b-two"]
    assert [t["key"] for t in admin_client.get(f"/api/tests?control_id={control['id']}").json()] == [
        "a-one",
        "b-two",
    ]
    assert [t["key"] for t in admin_client.get("/api/tests?q=A-ONE").json()] == ["a-one"]


# ---------------------------------------------------------- version control --


def test_editing_a_test_does_not_touch_its_version(admin_client):
    control = make_control(admin_client)
    test = created_test(admin_client, control["id"])

    patched = admin_client.patch(
        f"/api/tests/{test['id']}",
        json={"name": "Renamed", "enabled": False},
        headers=csrf_headers(admin_client),
    )
    assert patched.status_code == 200
    body = patched.json()
    assert body["name"] == "Renamed"
    assert body["enabled"] is False
    assert body["current_version"] == 1
    assert len(body["versions"]) == 1


def test_publishing_a_version_leaves_the_old_one_intact(admin_client):
    control = make_control(admin_client)
    test = created_test(admin_client, control["id"])
    original = test["versions"][0]

    published = admin_client.post(
        f"/api/tests/{test['id']}/versions",
        json={
            "engine_id": "http_exposure",
            "engine_params": {"profile": "web"},
            "assertion": {
                "fact": "path_exposed",
                "where": {"value.path": "/.git/HEAD"},
                "op": "not_exists",
            },
            "severity": "high",
        },
        headers=csrf_headers(admin_client),
    )
    assert published.status_code == 201, published.text
    assert published.json()["version"] == 2

    detail = admin_client.get(f"/api/tests/{test['id']}").json()
    assert detail["current_version"] == 2
    assert [v["version"] for v in detail["versions"]] == [1, 2]

    old = admin_client.get(f"/api/tests/{test['id']}/versions/1").json()
    assert old["engine_id"] == "http_headers"
    assert old["id"] == original["id"]


def test_a_published_version_cannot_be_edited_or_deleted(admin_client):
    """Immutability is structural: the routes do not exist."""
    paths = app.openapi()["paths"]
    assert "/api/tests/{test_id}/versions/{version}" in paths
    assert set(paths["/api/tests/{test_id}/versions/{version}"]) == {"get"}


def test_an_unknown_version_is_a_404(admin_client):
    control = make_control(admin_client)
    test = created_test(admin_client, control["id"])
    assert admin_client.get(f"/api/tests/{test['id']}/versions/7").status_code == 404


def test_deleting_a_test_that_has_never_run_succeeds(admin_client):
    control = make_control(admin_client)
    test = created_test(admin_client, control["id"])
    assert (
        admin_client.delete(
            f"/api/tests/{test['id']}", headers=csrf_headers(admin_client)
        ).status_code
        == 204
    )
    assert admin_client.get(f"/api/tests/{test['id']}").status_code == 404


def test_deleting_a_test_with_runs_is_refused(admin_client, db):
    """Runs and findings point at the test, so deleting it would orphan history."""
    from app.models.enums import TargetType
    from app.models.registry import Target
    from app.models.testing import ValidationRun

    control = make_control(admin_client)
    test = created_test(admin_client, control["id"])

    target = Target(
        name="lab-web",
        target_type=TargetType.WEBAPP,
        host="127.0.0.1",
        port=8081,
    )
    db.add(target)
    db.flush()
    db.add(
        ValidationRun(
            test_id=test["id"],
            test_version_id=test["versions"][0]["id"],
            target_id=target.id,
            engine_id="http_headers",
        )
    )
    db.commit()

    response = admin_client.delete(
        f"/api/tests/{test['id']}", headers=csrf_headers(admin_client)
    )
    assert response.status_code == 409
    assert "disable it instead" in response.json()["detail"]


# ------------------------------------------------------------------- RBAC --


def test_a_viewer_can_read_tests_but_not_author_them(viewer_user, admin_client, client):
    control = make_control(admin_client)
    created_test(admin_client, control["id"], key="readable")

    login(client, viewer_user.username)
    assert len(client.get("/api/tests").json()) == 1
    assert client.get("/api/engines").status_code == 200

    refused = make_test(client, control["id"], key="sneaky")
    assert refused.status_code == 403


def test_authoring_requires_csrf(admin_client):
    control = make_control(admin_client)
    response = admin_client.post(
        "/api/tests",
        json={
            "key": "no-csrf",
            "name": "No CSRF",
            "control_id": control["id"],
            "version": {"engine_id": "http_headers", "assertion": {"fact": "http_header"}},
        },
    )
    assert response.status_code == 403
    assert "CSRF" in response.json()["detail"]


def test_tests_require_authentication(client):
    for path in ("/api/tests", "/api/engines"):
        assert client.get(path).status_code == 401


# ----------------------------------------------------------------- settings --


def test_settings_report_defaults_without_storing_them(admin_client, db):
    from app.models.registry import Setting

    rows = admin_client.get("/api/settings").json()
    assert {row["key"] for row in rows} == {"safety", "runner", "staleness"}
    assert all(row["is_default"] for row in rows)
    # reading must not materialise rows, or the environment's kill switch would
    # be frozen at first page load
    assert db.query(Setting).count() == 0


def test_writing_a_setting_stores_it_and_clears_the_default_flag(admin_client):
    response = admin_client.put(
        "/api/settings/safety",
        json={"value": {"kill_switch": True, "safe_mode": True, "max_concurrent_runs": 1}},
        headers=csrf_headers(admin_client),
    )
    assert response.status_code == 200, response.text
    assert response.json()["value"]["kill_switch"] is True
    assert response.json()["is_default"] is False

    rows = admin_client.get("/api/settings").json()
    safety = next(row for row in rows if row["key"] == "safety")
    assert safety["value"]["kill_switch"] is True


def test_a_setting_write_is_audited_with_who_and_when(admin_client, db):
    from app.models.audit import AuditLog

    admin_client.put(
        "/api/settings/safety",
        json={"value": {"kill_switch": True}},
        headers=csrf_headers(admin_client),
    )
    row = db.query(AuditLog).filter(AuditLog.action == "setting.update").one()
    assert row.actor_username == "admin"
    assert row.object_id == "safety"
    assert row.after["value"]["kill_switch"] is True


def test_an_unknown_setting_key_is_a_404(admin_client):
    assert admin_client.get("/api/settings/nonsense").status_code == 404
    assert (
        admin_client.put(
            "/api/settings/nonsense", json={"value": {}}, headers=csrf_headers(admin_client)
        ).status_code
        == 404
    )


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("safety", {"kill_switch": "yes"}),
        ("safety", {"max_concurrent_runs": 999}),
        ("runner", {"max_attempts": 0}),
        ("runner", {"default_timeout_seconds": 5}),
        ("staleness", {"on_breach": "delete_everything"}),
        ("safety", {"unknown_field": True}),
    ],
)
def test_an_invalid_setting_value_is_refused(admin_client, key, value):
    response = admin_client.put(
        f"/api/settings/{key}", json={"value": value}, headers=csrf_headers(admin_client)
    )
    assert response.status_code == 400
    assert key in response.json()["detail"]


def test_a_put_replaces_rather_than_merges(admin_client):
    """Half of an old configuration surviving under a new one is how a kill
    switch ends up both on and off."""
    admin_client.put(
        "/api/settings/runner",
        json={"value": {"default_timeout_seconds": 600, "max_attempts": 3}},
        headers=csrf_headers(admin_client),
    )
    replaced = admin_client.put(
        "/api/settings/runner",
        json={"value": {"default_timeout_seconds": 120}},
        headers=csrf_headers(admin_client),
    ).json()
    assert replaced["value"] == {
        "default_timeout_seconds": 120,
        "max_attempts": 2,
        "lease_seconds": 120,
        "max_output_bytes": 4 * 1024 * 1024,
    }


def test_a_staleness_write_accepts_a_severity_as_a_plain_string(admin_client):
    """The settings models are strict, but severity is given a deliberate
    exception: the API speaks to clients that send an enum as a string."""
    response = admin_client.put(
        "/api/settings/staleness",
        json={"value": {"max_age_hours": 720, "severity_floor": "high"}},
        headers=csrf_headers(admin_client),
    )
    assert response.status_code == 200, response.text
    assert response.json()["value"]["severity_floor"] == "high"


def test_settings_writes_are_admin_only(analyst_user, admin_client, client):
    login(client, analyst_user.username)
    assert client.get("/api/settings").status_code == 200
    refused = client.put(
        "/api/settings/safety", json={"value": {}}, headers=csrf_headers(client)
    )
    assert refused.status_code == 403
