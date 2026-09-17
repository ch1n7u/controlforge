"""Schemas for evidence records and the on-disk verification of their bytes.

A record and a file are two different claims. The row says what was captured;
``verification`` says what a fresh read found on disk *now*. Keeping them apart
is what lets a rewritten or vanished file be reported as such instead of being
served as if it were still the capture.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from app.core.evidence import EvidenceCheck
from app.models.enums import EvidenceKind


class EvidenceItem(BaseModel):
    """One evidence record. Answers entirely from the database."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    run_id: int
    kind: EvidenceKind
    filename: str
    sha256: str
    size_bytes: int
    mime: str
    truncated: bool
    created_at: datetime
    detail: dict[str, Any] | None = None


class EvidenceVerification(BaseModel):
    """The result of re-reading the stored file and comparing it with the record."""

    model_config = ConfigDict(from_attributes=True)

    exists: bool
    sha256: str | None = None
    size_bytes: int | None = None
    digest_matches: bool
    size_matches: bool
    intact: bool

    @classmethod
    def from_check(cls, check: EvidenceCheck) -> "EvidenceVerification":
        return cls.model_validate(check)


class EvidenceDetail(EvidenceItem):
    verification: EvidenceVerification


class EvidenceListOut(BaseModel):
    """The ``{items, total}`` envelope the frontend paginates over."""

    items: list[EvidenceItem]
    total: int
