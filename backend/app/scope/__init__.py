"""Target scope validation and exec-time authorization."""

from app.scope.authorize import (
    Decision,
    ResolutionError,
    ScopeRule,
    authorize,
    resolve_host,
)
from app.scope.ports import PortSpecError, parse_ports, port_allowed
from app.scope.policy import (
    NormalizedEntry,
    ScopePolicy,
    ScopePolicyError,
    validate_entry,
)
from app.scope.ranges import (
    AddressClass,
    AddressError,
    address_class,
    denial_reason,
    embedded_ipv4,
    inspect,
    network_denial_reason,
)

__all__ = [
    "AddressClass",
    "AddressError",
    "Decision",
    "NormalizedEntry",
    "PortSpecError",
    "ResolutionError",
    "ScopePolicy",
    "ScopePolicyError",
    "ScopeRule",
    "address_class",
    "authorize",
    "denial_reason",
    "embedded_ipv4",
    "inspect",
    "network_denial_reason",
    "parse_ports",
    "port_allowed",
    "resolve_host",
    "validate_entry",
]
