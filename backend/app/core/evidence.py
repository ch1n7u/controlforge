"""Where a run's evidence lands, and why it cannot be quietly rewritten.

Evidence is the part of this platform that has to still be believable weeks
later, so the store is built around three properties:

* **hashed at capture** - every artifact is SHA-256'd as it is written and the
  digest is stored beside it. The read path recomputes the digest, so a file
  that changed on disk is reported as changed rather than served as if it were
  original;
* **content-addressed** - the file name *is* its digest, so identical bytes are
  written once and the name itself carries the integrity claim;
* **append-only** - there is no update and no delete in this module, and a file
  is made read-only once it is complete. A run cannot retract what it observed,
  and neither can the process that wrote it.

A run's stdout and stderr go through the same path as engine artifacts: the
reasoning a tool produced is evidence too, and it deserves the same treatment as
the JSON that was parsed out of it.

Nothing in here ever writes file *content* to the log or to the database. A
digest, a size and a path are enough to prove what was stored, and they cannot
leak a secret that happened to be inside the artifact.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.models.enums import EvidenceKind
from app.models.testing import Evidence

# A file name that is a name and nothing else: no separators, no traversal, no
# leading dot. Engines choose their own artifact names, and this is the boundary
# where that choice stops being able to mean anything outside the run directory.
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,150}$")
_SAFE_EXT = re.compile(r"^\.[A-Za-z0-9]{1,16}$")

FILE_MODE = 0o440  # owner and group read only; the writer cannot rewrite it
DIR_MODE = 0o750


class EvidenceError(RuntimeError):
    """Evidence could not be stored, or what is on disk is not what was stored."""


@dataclass(frozen=True, slots=True)
class StoredBlob:
    rel_path: str
    sha256: str
    size_bytes: int
    truncated: bool
    original_size: int
    original_sha256: str

    @property
    def lost_bytes(self) -> int:
        return self.original_size - self.size_bytes


@dataclass(frozen=True, slots=True)
class EvidenceCheck:
    """The result of re-reading an artifact and comparing it to its record."""

    exists: bool
    sha256: str | None
    size_bytes: int | None
    digest_matches: bool
    size_matches: bool

    @property
    def intact(self) -> bool:
        return self.exists and self.digest_matches and self.size_matches


def evidence_root(settings: Settings | None = None) -> Path:
    return Path((settings or get_settings()).evidence_dir)


def _digest_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _split_name(filename: str) -> tuple[str, str]:
    if Path(filename).name != filename:
        raise EvidenceError(f"{filename!r} is a path, not a file name")
    if not _SAFE_NAME.match(filename):
        raise EvidenceError(
            f"{filename!r} is not an acceptable artifact name "
            "(letters, digits, dot, dash and underscore only)"
        )
    stem, dot, ext = filename.rpartition(".")
    if dot and stem and _SAFE_EXT.match("." + ext):
        return stem, "." + ext.lower()
    return filename, ".txt"


def _resolve_under(root: Path, rel_path: str) -> Path:
    """Join a stored relative path onto the root, and refuse to leave it."""
    candidate = (root / rel_path).resolve()
    resolved_root = root.resolve()
    if candidate != resolved_root and resolved_root not in candidate.parents:
        raise EvidenceError(f"{rel_path!r} escapes the evidence directory")
    return candidate


def _write_once(path: Path, payload: bytes) -> None:
    """Write only if the name is free, atomically, and never overwrite.

    The name is the content digest, so an existing file with that name is
    either the same bytes - in which case there is nothing to do - or something
    has gone wrong on disk, which the caller is told about rather than being
    allowed to paper over.

    The bytes are written to a temporary name in the same directory first and
    then hard-linked into place, so a crash mid-write cannot leave a partial
    file sitting under a digest that claims to describe it.
    """
    if path.exists():
        existing, _ = _digest_file(path)
        if existing != path.stem:
            raise EvidenceError(
                f"{path} already exists and does not match its own name; the "
                "evidence store has been modified outside the platform"
            )
        return

    temp = path.with_name(f".{path.name}.{os.getpid()}.part")
    try:
        handle = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, FILE_MODE)
        with os.fdopen(handle, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temp, path)
        except FileExistsError:
            # Another worker stored the same bytes at the same moment. Both
            # writes agreed on the content; verify and move on.
            existing, _ = _digest_file(path)
            if existing != path.stem:
                raise EvidenceError(f"{path} appeared during the write and does not match")
        else:
            os.chmod(path, FILE_MODE)
    finally:
        if temp.exists():
            temp.unlink()


def _ensure_dir(root: Path, directory: Path) -> None:
    """Create the run's directory tree, no more permissive than the root.

    ``mkdir`` filters its mode through the process umask, so the modes are set
    again explicitly rather than left to whatever the worker's umask happens to
    be. The store's own root is left alone: it is created by the installer with
    the ownership the service needs.
    """
    directory.mkdir(parents=True, exist_ok=True)
    resolved_root = root.resolve()
    current = directory
    while current.resolve() != resolved_root:
        os.chmod(current, DIR_MODE)
        if current.parent == current:
            break
        current = current.parent


def store_bytes(
    *,
    run_id: int,
    kind: EvidenceKind,
    filename: str,
    data: bytes,
    content_type: str = "text/plain",
    detail: dict | None = None,
    settings: Settings | None = None,
    session: Session | None = None,
) -> Evidence:
    """Hash, write and record one artifact.

    Oversized data is stored truncated rather than refused - a partial capture
    is still evidence, and losing it entirely would be worse - but the record
    says so, and keeps the digest and size of the whole thing so the shortfall
    is measurable rather than invisible.
    """
    settings = settings or get_settings()
    root = evidence_root(settings)
    cap = settings.evidence_max_bytes

    stem, ext = _split_name(filename)
    truncated = len(data) > cap
    payload = data[:cap] if truncated else data

    digest = hashlib.sha256(payload).hexdigest()
    original_sha256 = hashlib.sha256(data).hexdigest()
    rel_path = f"runs/{run_id}/{kind.value}/{digest}{ext}"

    if session is not None:
        existing = session.execute(
            select(Evidence).where(Evidence.rel_path == rel_path)
        ).scalar_one_or_none()
        if existing is not None:
            return existing

    directory = root / "runs" / str(run_id) / kind.value
    _ensure_dir(root, directory)
    target = _resolve_under(root, rel_path)
    _write_once(target, payload)

    stored_detail = dict(detail or {})
    if truncated:
        stored_detail["truncated"] = True
        stored_detail["original_size_bytes"] = len(data)
        stored_detail["original_sha256"] = original_sha256
        stored_detail["stored_size_bytes"] = len(payload)

    row = Evidence(
        run_id=run_id,
        kind=kind,
        filename=_split_name(filename)[0] + ext,
        rel_path=rel_path,
        sha256=digest,
        size_bytes=len(payload),
        mime=content_type,
        truncated=truncated,
        detail=stored_detail or None,
    )
    if session is None:
        return row

    session.add(row)
    session.flush()
    return row


def store_artifact(
    *,
    run_id: int,
    draft,
    settings: Settings | None = None,
    session: Session | None = None,
) -> Evidence:
    return store_bytes(
        run_id=run_id,
        kind=EvidenceKind.ARTIFACT,
        filename=draft.filename,
        data=draft.data,
        content_type=draft.content_type,
        settings=settings,
        session=session,
    )


def verify(evidence: Evidence, settings: Settings | None = None) -> EvidenceCheck:
    """Re-read an artifact from disk and compare it with its record."""
    root = evidence_root(settings)
    try:
        path = _resolve_under(root, evidence.rel_path)
    except EvidenceError:
        return EvidenceCheck(False, None, None, False, False)

    if not path.is_file():
        return EvidenceCheck(False, None, None, False, False)

    digest, size = _digest_file(path)
    return EvidenceCheck(
        exists=True,
        sha256=digest,
        size_bytes=size,
        digest_matches=digest == evidence.sha256,
        size_matches=size == evidence.size_bytes,
    )


def read(evidence: Evidence, settings: Settings | None = None) -> tuple[bytes, EvidenceCheck]:
    """Return the stored bytes and whether they still match their record.

    The check is computed from the same bytes that are returned, so a caller
    cannot accidentally serve a body it did not verify.
    """
    root = evidence_root(settings)
    path = _resolve_under(root, evidence.rel_path)
    if not path.is_file():
        return b"", EvidenceCheck(False, None, None, False, False)

    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    check = EvidenceCheck(
        exists=True,
        sha256=digest,
        size_bytes=len(data),
        digest_matches=digest == evidence.sha256,
        size_matches=len(data) == evidence.size_bytes,
    )
    return data, check
