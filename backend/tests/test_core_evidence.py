"""The evidence store: hashed at capture, content-addressed, append-only.

The tests worth having here are the ones where a store that *looked* fine would
still hand back the wrong answer - a file edited in place, a file replaced with
different bytes of the same length, a name that tries to escape the directory.
Each of those has to be caught by the digest rather than assumed away.
"""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

import pytest

from app.config import Settings
from app.core import evidence as store
from app.core.evidence import EvidenceError
from app.models.enums import EvidenceKind, Severity, TargetType
from app.models.registry import Target
from app.models.testing import Evidence, ValidationRun
from tests.conftest import csrf_headers
from tests.test_testing_api import created_test, make_control


@pytest.fixture
def maybe_settings(tmp_path, settings_paths) -> Settings:
    """Settings pointed at the test evidence directory, with a small cap."""
    return Settings(
        evidence_dir=Path(settings_paths["evidence_dir"]),
        evidence_max_bytes=1024,
    )


@pytest.fixture
def run(db, admin_client) -> ValidationRun:
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


def _stored_file(settings: Settings, row: Evidence) -> Path:
    return Path(settings.evidence_dir) / row.rel_path


# ------------------------------------------------------------------ capture --


def test_an_artifact_is_stored_under_its_own_digest(db, run, maybe_settings):
    blob = b'{"entries": [1, 2, 3]}'
    digest = hashlib.sha256(blob).hexdigest()

    row = store.store_bytes(
        run_id=run.id,
        kind=EvidenceKind.ARTIFACT,
        filename="testssl.json",
        data=blob,
        content_type="application/json",
        session=db,
    )

    assert row.sha256 == digest
    assert row.size_bytes == len(blob)
    assert row.truncated is False

    path = _stored_file(maybe_settings, row)
    assert path.is_file()
    assert path.stem == digest, "the file name is the integrity claim"
    assert path.read_bytes() == blob


def test_stored_evidence_cannot_be_rewritten_by_the_writer(db, run, maybe_settings):
    row = store.store_bytes(
        run_id=run.id,
        kind=EvidenceKind.STDOUT,
        filename="stdout.txt",
        data=b"logged output\n",
        session=db,
    )

    mode = stat.S_IMODE(_stored_file(maybe_settings, row).stat().st_mode)
    assert mode == store.FILE_MODE
    assert not mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH), "no write bit is set"


def test_the_run_directory_is_not_readable_by_other_local_users(db, run, maybe_settings):
    row = store.store_bytes(
        run_id=run.id,
        kind=EvidenceKind.STDERR,
        filename="stderr.txt",
        data=b"a warning\n",
        session=db,
    )

    directory = _stored_file(maybe_settings, row).parent
    mode = stat.S_IMODE(directory.stat().st_mode)
    assert mode == store.DIR_MODE
    assert not mode & stat.S_IROTH


def test_a_second_identical_capture_stores_one_row_and_one_file(db, run, maybe_settings):
    kwargs = dict(
        run_id=run.id,
        kind=EvidenceKind.ARTIFACT,
        filename="nmap.xml",
        data=b"<nmaprun/>",
        session=db,
    )
    first = store.store_bytes(**kwargs)
    second = store.store_bytes(**kwargs)

    assert first.id == second.id
    assert first.rel_path == second.rel_path

    directory = _stored_file(maybe_settings, first).parent
    assert len(list(directory.iterdir())) == 1


def test_output_and_artifacts_are_kept_apart(db, run, maybe_settings):
    stdout = store.store_bytes(
        run_id=run.id, kind=EvidenceKind.STDOUT, filename="stdout.txt", data=b"a", session=db
    )
    artifact = store.store_bytes(
        run_id=run.id, kind=EvidenceKind.ARTIFACT, filename="testssl.json", data=b"b", session=db
    )

    assert stdout.rel_path != artifact.rel_path
    assert _stored_file(maybe_settings, stdout).parent.name == "stdout"
    assert _stored_file(maybe_settings, artifact).parent.name == "artifact"


def test_evidence_belongs_to_the_run_that_captured_it(db, run, maybe_settings):
    other = ValidationRun(
        test_id=run.test_id,
        test_version_id=run.test_version_id,
        target_id=run.target_id,
        engine_id="http_headers",
    )
    db.add(other)
    db.commit()
    db.refresh(other)

    blob = b"same bytes, different run"
    one = store.store_bytes(
        run_id=run.id, kind=EvidenceKind.STDOUT, filename="stdout.txt", data=blob, session=db
    )
    two = store.store_bytes(
        run_id=other.id, kind=EvidenceKind.STDOUT, filename="stdout.txt", data=blob, session=db
    )

    assert one.rel_path != two.rel_path
    assert _stored_file(maybe_settings, one).is_file()
    assert _stored_file(maybe_settings, two).is_file()


# --------------------------------------------------------------------- read --


def test_reading_returns_the_bytes_with_their_digest_confirmed(db, run, maybe_settings):
    blob = b"HTTP/1.1 200 OK\n"
    row = store.store_bytes(
        run_id=run.id, kind=EvidenceKind.STDOUT, filename="stdout.txt", data=blob, session=db
    )

    data, check = store.read(row, maybe_settings)
    assert data == blob
    assert check.intact
    assert check.sha256 == row.sha256


def test_an_edited_artifact_is_reported_as_changed_not_served(db, run, maybe_settings):
    row = store.store_bytes(
        run_id=run.id, kind=EvidenceKind.ARTIFACT, filename="testssl.json", data=b"original", session=db
    )
    path = _stored_file(maybe_settings, row)
    os.chmod(path, 0o640)
    path.write_bytes(b"tampered")

    _, check = store.read(row, maybe_settings)
    assert check.exists
    assert not check.digest_matches
    assert not check.intact


def test_a_swap_that_preserves_the_length_is_still_caught(db, run, maybe_settings):
    """The case a size check alone would wave through."""
    row = store.store_bytes(
        run_id=run.id, kind=EvidenceKind.ARTIFACT, filename="nmap.xml", data=b"AAAA", session=db
    )
    path = _stored_file(maybe_settings, row)
    os.chmod(path, 0o640)
    path.write_bytes(b"BBBB")

    check = store.verify(row, maybe_settings)
    assert check.size_matches
    assert not check.digest_matches
    assert not check.intact


def test_a_deleted_artifact_is_reported_rather_than_raising(db, run, maybe_settings):
    row = store.store_bytes(
        run_id=run.id, kind=EvidenceKind.STDOUT, filename="stdout.txt", data=b"gone soon", session=db
    )
    _stored_file(maybe_settings, row).unlink()

    check = store.verify(row, maybe_settings)
    assert not check.exists
    assert not check.intact


# ------------------------------------------------------------------- limits --


def test_an_oversized_artifact_is_kept_truncated_and_says_so(db, run, maybe_settings):
    data = b"x" * 4096
    row = store.store_bytes(
        run_id=run.id,
        kind=EvidenceKind.ARTIFACT,
        filename="big.txt",
        data=data,
        session=db,
        settings=maybe_settings,
    )

    assert row.truncated is True
    assert row.size_bytes == maybe_settings.evidence_max_bytes
    assert row.detail["original_size_bytes"] == len(data)
    assert row.detail["original_sha256"] == hashlib.sha256(data).hexdigest()

    stored = _stored_file(maybe_settings, row).read_bytes()
    assert stored == data[: maybe_settings.evidence_max_bytes]
    # The digest describes what is on disk, so verification still works...
    assert store.verify(row, maybe_settings).intact
    # ...and the shortfall is measurable rather than lost.
    assert row.detail["stored_size_bytes"] < row.detail["original_size_bytes"]


# ---------------------------------------------------------------- the names --


@pytest.mark.parametrize(
    "filename",
    ["../../etc/passwd", "runs/1/artifact/x.txt", "..\\windows", "/etc/shadow", ".hidden"],
)
def test_a_name_that_is_a_path_is_refused(filename, db, run):
    with pytest.raises(EvidenceError):
        store.store_bytes(
            run_id=run.id,
            kind=EvidenceKind.ARTIFACT,
            filename=filename,
            data=b"nope",
            session=db,
        )


def test_a_name_with_characters_outside_the_allowlist_is_refused(db, run):
    with pytest.raises(EvidenceError):
        store.store_bytes(
            run_id=run.id,
            kind=EvidenceKind.ARTIFACT,
            filename="test ssl;rm -rf.json",
            data=b"nope",
            session=db,
        )


def test_content_planted_under_the_expected_name_is_refused(db, run, maybe_settings):
    """A file already sitting at the digest path is an integrity alarm."""
    blob = b"the real thing"
    digest = hashlib.sha256(blob).hexdigest()
    planted = (
        Path(maybe_settings.evidence_dir)
        / "runs"
        / str(run.id)
        / "artifact"
        / f"{digest}.txt"
    )
    planted.parent.mkdir(parents=True, exist_ok=True)
    planted.write_bytes(b"something else")

    with pytest.raises(EvidenceError, match="modified outside the platform"):
        store.store_bytes(
            run_id=run.id,
            kind=EvidenceKind.ARTIFACT,
            filename="artifact.txt",
            data=blob,
            session=db,
        )


def test_a_stored_path_cannot_be_used_to_escape_the_store(db, maybe_settings):
    row = Evidence(
        run_id=1,
        kind=EvidenceKind.ARTIFACT,
        filename="stdout.txt",
        rel_path="../../etc/passwd",
        sha256="0" * 64,
        size_bytes=0,
        mime="text/plain",
    )

    with pytest.raises(EvidenceError, match="escapes the evidence directory"):
        store.read(row, maybe_settings)
