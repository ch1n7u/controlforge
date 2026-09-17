"""The evidence API: the record, the disk check, and the bytes.

The cases worth having are the ones where the file on disk stops agreeing with
its record. The list must still answer from the database, the detail must say
"not intact" rather than raise, and the content endpoint must refuse a vanished
file (410) while labelling a rewritten one (``X-Evidence-Intact: false``)
instead of serving it as the original.
"""

from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

import pytest

from app.config import get_settings
from app.core import evidence as store
from app.main import app
from app.models.enums import EvidenceKind, TargetType
from app.models.registry import Target
from app.models.testing import Evidence, ValidationRun
from tests.conftest import csrf_headers
from tests.test_testing_api import created_test, make_control


@pytest.fixture(autouse=True)
def _tmp_evidence_root():
    """These tests write real files; they must never land in the real store."""
    assert str(get_settings().evidence_dir).startswith(tempfile.gettempdir())


@pytest.fixture
def run(db, admin_client) -> ValidationRun:
    control = make_control(admin_client)
    test = created_test(admin_client, control["id"])

    target = Target(
        name="lab-web", target_type=TargetType.WEBAPP, host="127.0.0.1", port=8081
    )
    db.add(target)
    db.flush()

    run = ValidationRun(
        test_id=test["id"],
        test_version_id=test["versions"][0]["id"],
        target_id=target.id,
        engine_id="http_headers",
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def another_run(db, run: ValidationRun) -> ValidationRun:
    other = ValidationRun(
        test_id=run.test_id,
        test_version_id=run.test_version_id,
        target_id=run.target_id,
        engine_id=run.engine_id,
    )
    db.add(other)
    db.commit()
    db.refresh(other)
    return other


def captured(
    db,
    run: ValidationRun,
    data: bytes,
    *,
    kind: EvidenceKind = EvidenceKind.STDOUT,
    filename: str = "stdout.txt",
    content_type: str = "text/plain",
) -> Evidence:
    """Write through the app's own store so the API reads a genuine capture."""
    row = store.store_bytes(
        run_id=run.id,
        kind=kind,
        filename=filename,
        data=data,
        content_type=content_type,
        session=db,
    )
    db.commit()
    return row


def stored_path(row: Evidence) -> Path:
    return Path(get_settings().evidence_dir) / row.rel_path


def overwrite(row: Evidence, payload: bytes) -> None:
    """Simulate tampering: the store makes files read-only for the writer."""
    path = stored_path(row)
    path.chmod(0o640)
    path.write_bytes(payload)


# -------------------------------------------------------------- the listing --


def test_list_returns_the_page_envelope_newest_first(db, run, admin_client):
    first = captured(db, run, b"first", filename="one.txt")
    second = captured(db, run, b"second", filename="two.txt")

    response = admin_client.get("/api/evidence")
    assert response.status_code == 200, response.text
    body = response.json()

    assert body["total"] == 2
    assert [item["id"] for item in body["items"]] == [second.id, first.id]
    assert body["items"][0] == {
        "id": second.id,
        "run_id": run.id,
        "kind": "stdout",
        "filename": "two.txt",
        "sha256": hashlib.sha256(b"second").hexdigest(),
        "size_bytes": 6,
        "mime": "text/plain",
        "truncated": False,
        "created_at": body["items"][0]["created_at"],
        "detail": None,
    }
    assert body["items"][0]["created_at"], "created_at is serialised for the UI"


def test_list_filters_by_run_and_kind(db, run, admin_client):
    other = another_run(db, run)
    stdout = captured(db, run, b"same bytes", kind=EvidenceKind.STDOUT)
    artifact = captured(
        db,
        run,
        b"report",
        kind=EvidenceKind.ARTIFACT,
        filename="report.json",
        content_type="application/json",
    )
    elsewhere = captured(db, other, b"same bytes", kind=EvidenceKind.STDOUT)

    by_run = admin_client.get(f"/api/evidence?run_id={run.id}").json()
    assert by_run["total"] == 2
    assert {item["id"] for item in by_run["items"]} == {stdout.id, artifact.id}

    by_kind = admin_client.get("/api/evidence?kind=artifact").json()
    assert by_kind["total"] == 1
    assert by_kind["items"][0]["id"] == artifact.id

    combined = admin_client.get(f"/api/evidence?run_id={other.id}&kind=stdout").json()
    assert combined["total"] == 1
    assert combined["items"][0]["id"] == elsewhere.id

    assert admin_client.get("/api/evidence?kind=not-a-kind").status_code == 422


def test_list_paginates_without_losing_the_total(db, run, admin_client):
    captured(db, run, b"one", filename="one.txt")
    captured(db, run, b"two", filename="two.txt")
    captured(db, run, b"three", filename="three.txt")

    page = admin_client.get("/api/evidence?limit=1&offset=1").json()
    assert page["total"] == 3
    assert [item["filename"] for item in page["items"]] == ["two.txt"]

    assert admin_client.get("/api/evidence?limit=201").status_code == 422
    assert admin_client.get("/api/evidence?limit=0").status_code == 422


# ------------------------------------------------------------- the disk check --


def test_detail_verifies_an_intact_file(db, run, admin_client):
    blob = b"HTTP/1.1 200 OK\n"
    row = captured(db, run, blob)

    response = admin_client.get(f"/api/evidence/{row.id}")
    assert response.status_code == 200, response.text
    body = response.json()

    assert body["sha256"] == row.sha256
    assert body["verification"] == {
        "exists": True,
        "sha256": row.sha256,
        "size_bytes": len(blob),
        "digest_matches": True,
        "size_matches": True,
        "intact": True,
    }


def test_detail_reports_a_rewritten_file_as_not_intact(db, run, admin_client):
    row = captured(db, run, b"original", filename="report.txt")
    overwrite(row, b"tampered")  # same length: only the digest can catch this

    verification = admin_client.get(f"/api/evidence/{row.id}").json()["verification"]
    assert verification["exists"] is True
    assert verification["sha256"] == hashlib.sha256(b"tampered").hexdigest()
    assert verification["size_bytes"] == len(b"tampered")
    assert verification["digest_matches"] is False
    assert verification["size_matches"] is True
    assert verification["intact"] is False


def test_detail_reports_a_missing_file_without_raising(db, run, admin_client):
    row = captured(db, run, b"gone soon")
    stored_path(row).unlink()

    response = admin_client.get(f"/api/evidence/{row.id}")
    assert response.status_code == 200
    assert response.json()["verification"] == {
        "exists": False,
        "sha256": None,
        "size_bytes": None,
        "digest_matches": False,
        "size_matches": False,
        "intact": False,
    }


def test_detail_404s_for_an_unknown_id(admin_client):
    response = admin_client.get("/api/evidence/999999")
    assert response.status_code == 404
    assert "999999" in response.json()["detail"]


# ---------------------------------------------------------------- the bytes --


def test_content_serves_the_bytes_with_integrity_headers(db, run, admin_client):
    blob = b'{"entries": [1, 2, 3]}'
    row = captured(db, run, blob, filename="testssl.json", content_type="application/json")

    response = admin_client.get(f"/api/evidence/{row.id}/content")
    assert response.status_code == 200, response.text
    assert response.content == blob
    assert response.headers["x-content-sha256"] == hashlib.sha256(blob).hexdigest()
    assert response.headers["x-evidence-intact"] == "true"
    assert response.headers["content-type"].startswith("application/json")
    assert response.headers["content-disposition"] == 'attachment; filename="testssl.json"'


def test_content_labels_a_rewritten_file_instead_of_hiding_it(db, run, admin_client):
    row = captured(db, run, b"AAAA", filename="report.txt")
    overwrite(row, b"BBBB")

    response = admin_client.get(f"/api/evidence/{row.id}/content")
    assert response.status_code == 200
    assert response.content == b"BBBB", "the bytes on disk are what is served"
    assert response.headers["x-evidence-intact"] == "false"
    assert (
        response.headers["x-content-sha256"] == hashlib.sha256(b"BBBB").hexdigest()
    ), "the header describes the bytes actually served"


def test_content_of_a_missing_file_is_gone_and_makes_no_integrity_claim(db, run, admin_client):
    row = captured(db, run, b"gone soon")
    stored_path(row).unlink()

    response = admin_client.get(f"/api/evidence/{row.id}/content")
    assert response.status_code == 410
    assert str(row.id) in response.json()["detail"]
    assert "x-evidence-intact" not in response.headers
    assert "x-content-sha256" not in response.headers


def test_content_of_a_row_that_escapes_the_store_is_gone(db, run, admin_client):
    row = captured(db, run, b"inside")
    row.rel_path = "../../etc/passwd"
    db.commit()

    assert admin_client.get(f"/api/evidence/{row.id}/content").status_code == 410


def test_content_headers_stay_safe_for_a_hand_built_row(db, run, admin_client):
    """Names like this are refused at capture; the read path must survive them anyway."""
    blob = b"hand built"
    digest = hashlib.sha256(blob).hexdigest()
    rel_path = f"runs/{run.id}/artifact/{digest}.txt"
    path = Path(get_settings().evidence_dir) / rel_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(blob)

    row = Evidence(
        run_id=run.id,
        kind=EvidenceKind.ARTIFACT,
        filename='we\nird"name.txt',
        rel_path=rel_path,
        sha256=digest,
        size_bytes=len(blob),
        mime="",
    )
    db.add(row)
    db.commit()

    response = admin_client.get(f"/api/evidence/{row.id}/content")
    assert response.status_code == 200
    assert response.content == blob
    assert response.headers["x-evidence-intact"] == "true"
    assert response.headers["content-type"] == "application/octet-stream"
    assert response.headers["content-disposition"] == (
        'attachment; filename="we ird\\"name.txt"'
    )


# -------------------------------------------------------------------- auth --


def test_evidence_endpoints_require_authentication(admin_client, run, db):
    row = captured(db, run, b"x")
    admin_client.post("/api/auth/logout", headers=csrf_headers(admin_client))

    assert admin_client.get("/api/evidence").status_code == 401
    assert admin_client.get(f"/api/evidence/{row.id}").status_code == 401
    assert admin_client.get(f"/api/evidence/{row.id}/content").status_code == 401
