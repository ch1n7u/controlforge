"""Loading the scope rules that apply to a target, at the moment of running.

The rules are read from the database immediately before a run and are never
cached. A cached authorization is one that keeps working after the scope was
narrowed, which is exactly the property an allowlist must not have.

A scope only contributes rules while it is active and unexpired. An expired
authorization is not an authorization.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.registry import Scope, ScopeEntry, TargetScope
from app.scope.authorize import ScopeRule
from app.scope.ports import PortSpecError, parse_ports


class ScopeLoadError(RuntimeError):
    """The stored scopes could not be turned into rules.

    Raised rather than skipping the offending entry: a rule that cannot be read
    is not the same as a rule that does not exist, and quietly dropping it could
    change an authorization decision in either direction.
    """


def active_rules_for_target(session: Session, target_id: int) -> list[ScopeRule]:
    """Every rule, from every active unexpired scope, attached to ``target_id``."""
    now = datetime.now(UTC)
    rows = session.execute(
        select(ScopeEntry, Scope)
        .join(Scope, ScopeEntry.scope_id == Scope.id)
        .join(TargetScope, TargetScope.scope_id == Scope.id)
        .where(
            TargetScope.target_id == target_id,
            Scope.active.is_(True),
            (Scope.expires_at.is_(None)) | (Scope.expires_at > now),
        )
        .order_by(Scope.id, ScopeEntry.id)
    ).all()

    rules: list[ScopeRule] = []
    for entry, scope in rows:
        try:
            ports = parse_ports(entry.ports)
        except PortSpecError as exc:
            raise ScopeLoadError(
                f"scope {scope.name!r} entry {entry.value!r} has an unreadable port "
                f"specification ({exc}); refusing to run under a scope that cannot "
                "be evaluated"
            ) from exc
        rules.append(
            ScopeRule(
                scope_id=scope.id,
                scope_name=scope.name,
                kind=entry.kind.value,
                value=entry.value,
                ports=ports,
                protocol=entry.protocol,
                has_authorization=bool(scope.authorization_ref),
                is_lab=bool(scope.is_lab),
            )
        )
    return rules


def attached_scopes(session: Session, target_id: int) -> list[Scope]:
    """The scopes attached to a target, active or not - for display, not for a decision."""
    return list(
        session.execute(
            select(Scope)
            .join(TargetScope, TargetScope.scope_id == Scope.id)
            .where(TargetScope.target_id == target_id)
            .order_by(Scope.name)
        ).scalars()
    )
