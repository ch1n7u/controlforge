"""ORM models. Importing this package registers every table on ``Base.metadata``."""

from app.models.audit import AuditLog
from app.models.auth import User, UserSession
from app.models.enums import (
    AssertionStatus,
    EvidenceKind,
    FindingStatus,
    RemediationActionKind,
    Role,
    RunStatus,
    ScopeEntryKind,
    Severity,
    StreamKind,
    TargetType,
    TriggerKind,
)
from app.models.facts import AssertionResult, Fact
from app.models.findings import Finding, RemediationAction
from app.models.registry import (
    Control,
    Framework,
    FrameworkRef,
    Scope,
    ScopeEntry,
    Setting,
    Target,
    TargetScope,
)
from app.models.testing import (
    Evidence,
    RunLog,
    ValidationRun,
    ValidationTest,
    ValidationTestVersion,
)

__all__ = [
    "AssertionResult",
    "AssertionStatus",
    "AuditLog",
    "Control",
    "Evidence",
    "EvidenceKind",
    "Fact",
    "Finding",
    "FindingStatus",
    "Framework",
    "FrameworkRef",
    "RemediationAction",
    "RemediationActionKind",
    "Role",
    "RunLog",
    "RunStatus",
    "Scope",
    "ScopeEntry",
    "ScopeEntryKind",
    "Setting",
    "Severity",
    "StreamKind",
    "Target",
    "TargetScope",
    "TargetType",
    "TriggerKind",
    "User",
    "UserSession",
    "ValidationRun",
    "ValidationTest",
    "ValidationTestVersion",
]
