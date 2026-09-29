"""Evidence over HTTP: what was captured, whether it still is that, and the bytes.

Three questions, three endpoints. The list answers from the database, the detail
adds a fresh read of the disk, and the content endpoint serves the bytes with
the digest it computed while serving them. A file whose bytes no longer hash to
the recorded digest is still downloadable - pretending it vanished would hide
the tampering - but it is never served without saying so.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session as OrmSession

from app.api.deps import require_user
from app.core import evidence as store
from app.db import get_db
from app.models.auth import User
from app.models.enums import EvidenceKind
from app.models.testing import Evidence
from app.schemas.evidence import (
    EvidenceDetail,
    EvidenceItem,
    EvidenceListOut,
    EvidenceVerification,
)

router = APIRouter(prefix="/api", tags=["evidence"])
logger = logging.getLogger("controlforge.api.evidence")

_CHUNK = 64 * 1024


def _not_found(evidence_id: int) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND, detail=f"evidence {evidence_id} not found"
    )


def _load(db: OrmSession, evidence_id: int) -> Evidence:
    row = db.get(Evidence, evidence_id)
    if row is None:
        raise _not_found(evidence_id)
    return row


@router.get("/evidence", response_model=EvidenceListOut)
def list_evidence(
    run_id: int | None = None,
    kind: EvidenceKind | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: OrmSession = Depends(get_db),
    _: User = Depends(require_user),
) -> EvidenceListOut:
    """Captures, newest first. ``total`` counts the filtered set, not the page."""
    conditions = []
    if run_id is not None:
        conditions.append(Evidence.run_id == run_id)
    if kind is not None:
        conditions.append(Evidence.kind == kind)

    statement = select(Evidence)
    counter = select(func.count()).select_from(Evidence)
    for condition in conditions:
        statement = statement.where(condition)
        counter = counter.where(condition)

    rows = db.execute(
        statement.order_by(Evidence.created_at.desc(), Evidence.id.desc())
        .limit(limit)
        .offset(offset)
    ).scalars()
    return EvidenceListOut(
        items=[EvidenceItem.model_validate(row) for row in rows],
        total=db.execute(counter).scalar_one(),
    )


@router.get("/evidence/{evidence_id}", response_model=EvidenceDetail)
def get_evidence(
    evidence_id: int, db: OrmSession = Depends(get_db), _: User = Depends(require_user)
) -> EvidenceDetail:
    """The record plus a fresh check of the file on disk.

    A missing or rewritten file is a fact to report, not an error - the answer
    the reviewer needs is exactly "this is no longer what was captured".
    """
    row = _load(db, evidence_id)
    check = store.verify(row)
    return EvidenceDetail(
        **EvidenceItem.model_validate(row).model_dump(),
        verification=EvidenceVerification.from_check(check),
    )


def _stored_path(row: Evidence) -> Path | None:
    """Resolve through the store's own logic, so the API cannot be laxer than it.

    ``rel_path`` is re-checked against the root here exactly as the store does
    it; a row that escapes the directory is treated as a file that is not there.
    """
    try:
        path = store._resolve_under(store.evidence_root(), row.rel_path)
    except store.EvidenceError:
        return None
    return path if path.is_file() else None


def _one_line(value: str) -> str:
    """Header values must not carry line breaks, whatever the record says."""
    return " ".join(value.split())


def _content_disposition(filename: str) -> str:
    """A quoted ASCII filename, plus the UTF-8 form for anything non-ASCII."""
    name = _one_line(filename)
    fallback = name.encode("ascii", "ignore").decode() or "download"
    quoted = fallback.replace("\\", "\\\\").replace('"', '\\"')
    header = f'attachment; filename="{quoted}"'
    if fallback != name:
        header += f"; filename*=UTF-8''{quote(name, safe='')}"
    return header


def _served_bytes(path: Path, expected_sha256: str) -> Iterator[bytes]:
    """Yield the file in chunks, re-hashing exactly what is sent.

    The pre-flight digest decided the headers; this pass cannot change them, so
    a file swapped between the two reads is at least recorded loudly rather than
    silently mislabelled.
    """
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(_CHUNK):
            digest.update(chunk)
            yield chunk
    if digest.hexdigest() != expected_sha256:
        logger.error("evidence changed between the digest pass and the read: %s", path)


@router.get("/evidence/{evidence_id}/content")
def download_evidence(
    evidence_id: int, db: OrmSession = Depends(get_db), _: User = Depends(require_user)
) -> StreamingResponse:
    """Serve the stored bytes with the integrity result in the response headers.

    The digest is computed in a streaming pre-pass so the headers can be honest
    before the first byte leaves; the body is then streamed in chunks. A file
    that no longer hashes to the recorded digest is served with
    ``X-Evidence-Intact: false``. A file that is gone is 410, with no integrity
    headers at all - there is nothing there to make a claim about.
    """
    row = _load(db, evidence_id)
    path = _stored_path(row)
    if path is None:
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail=(
                f"evidence {evidence_id} is recorded, but its file is not on disk "
                f"({row.rel_path}); the capture cannot be served"
            ),
        )

    digest, size = store._digest_file(path)
    intact = digest == row.sha256 and size == row.size_bytes
    mime = _one_line(row.mime)
    if not mime.isascii():  # a header value Starlette cannot encode is a 500
        mime = ""
    return StreamingResponse(
        _served_bytes(path, digest),
        media_type=mime or "application/octet-stream",
        headers={
            "X-Content-SHA256": digest,
            "X-Evidence-Intact": "true" if intact else "false",
            "Content-Disposition": _content_disposition(row.filename),
        },
    )
