"""Enumerations shared by the ORM models and the API schemas.

Every enum is persisted as a plain VARCHAR. Enum *columns* are not given CHECK
constraints on purpose: the vocabulary lives in these Python enums, which are
validated on write, and keeping the constraint out of the schema means adding a
status is a code change rather than type surgery on a live table.
"""

from __future__ import annotations

from enum import StrEnum

from sqlalchemy import Enum as SAEnum


class Role(StrEnum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class TargetType(StrEnum):
    HOST = "host"
    WEBAPP = "webapp"
    API = "api"
    TLS = "tls"
    SSH = "ssh"
    LOCAL = "local"


class ScopeEntryKind(StrEnum):
    CIDR = "cidr"
    HOST = "host"


class RunStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    # The run executed but the assertion could not be decided - the tool was
    # stopped, timed out, or could not observe what it was asked about. It is
    # kept separate from both passed and failed because reporting it as either
    # one would be a claim the platform cannot support.
    INCONCLUSIVE = "inconclusive"
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"
    CANCELLED = "cancelled"
    DEAD = "dead"

    @property
    def is_terminal(self) -> bool:
        return self in {
            RunStatus.PASSED,
            RunStatus.FAILED,
            RunStatus.INCONCLUSIVE,
            RunStatus.NOT_APPLICABLE,
            RunStatus.ERROR,
            RunStatus.CANCELLED,
            RunStatus.DEAD,
        }


class AssertionStatus(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    INCONCLUSIVE = "inconclusive"
    NOT_APPLICABLE = "not_applicable"


class FindingStatus(StrEnum):
    OPEN = "open"
    TRIAGED = "triaged"
    REMEDIATING = "remediating"
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"
    RESOLVED = "resolved"

    @property
    def is_closed(self) -> bool:
        return self in {
            FindingStatus.ACCEPTED_RISK,
            FindingStatus.FALSE_POSITIVE,
            FindingStatus.RESOLVED,
        }


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]


class TriggerKind(StrEnum):
    MANUAL = "manual"
    RETEST = "retest"
    SCHEDULED = "scheduled"


class EvidenceKind(StrEnum):
    STDOUT = "stdout"
    STDERR = "stderr"
    ARTIFACT = "artifact"


class StreamKind(StrEnum):
    STDOUT = "stdout"
    STDERR = "stderr"
    SYSTEM = "system"


class RemediationActionKind(StrEnum):
    COMMENT = "comment"
    STATUS_CHANGE = "status_change"
    ASSIGNMENT = "assignment"
    RETEST_REQUESTED = "retest_requested"
    RISK_ACCEPTED = "risk_accepted"


def enum_col(enum_cls: type[StrEnum], name: str | None = None) -> SAEnum:
    """VARCHAR + CHECK column type that stores enum *values* (lowercase)."""
    return SAEnum(
        enum_cls,
        name=name or enum_cls.__name__.lower(),
        native_enum=False,
        length=32,
        values_callable=lambda e: [member.value for member in e],
        validate_strings=True,
    )
