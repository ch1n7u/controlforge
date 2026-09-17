"""Scope entry policy: what an operator is allowed to authorize.

Enforced when a scope entry is created or changed, so an over-broad or
never-permitted authorization is refused at the point a human can be told why -
not discovered later when a run silently does nothing.

The rules, in the order they fire:

* Ports must parse and must be non-empty. An entry with no ports authorizes
  nothing; that is almost always a mistake, so it is rejected rather than
  quietly ignored.
* A CIDR that overlaps a hard-denied range is refused outright, which makes
  ``0.0.0.0/0`` unauthorizable by construction. This is deliberately stronger
  than "allow it with a flag": no configuration should be able to point the
  platform at the whole internet.
* Broad ranges (more than :data:`MAX_AUTHORISED_HOSTS` addresses) need
  ``allow_broad``.
* Anything touching globally routable space needs a written
  ``authorization_ref`` - the citation that says who approved testing it.
* Loopback needs ``is_lab``: the platform's own services listen there.
* Wildcards are refused; a scope is a list of specific names.
"""

from __future__ import annotations

import re

from dataclasses import dataclass

from app.scope.ports import PortSpecError, format_ports, parse_ports
from app.scope.ranges import (
    AddressClass,
    AddressError,
    IPAddress,
    IPNetwork,
    denial_reason,
    inspect,
    is_loopback,
    network_contains_loopback,
    network_denial_reason,
    network_is_broad,
    network_touches_public,
    parse_address,
    parse_network,
)

#: Larger than this and a "validation" is really a network sweep.
MAX_AUTHORISED_HOSTS = 65536

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))*$"
)

_PROTOCOLS = frozenset({"tcp", "udp"})

#: Hostnames that always resolve to the platform's own neighbourhood.
_LOCAL_HOSTNAMES = frozenset({"localhost", "localhost.localdomain", "ip6-localhost"})


class ScopePolicyError(ValueError):
    """A scope entry violates the authorization policy."""


@dataclass(frozen=True)
class ScopePolicy:
    """The flags carried by the scope an entry belongs to."""

    allow_broad: bool = False
    is_lab: bool = False
    authorization_ref: str | None = None

    @property
    def has_authorization(self) -> bool:
        return bool(self.authorization_ref and self.authorization_ref.strip())

    @property
    def label(self) -> str:
        return "scope"


@dataclass(frozen=True)
class NormalizedEntry:
    """A scope entry that has passed policy, in canonical form."""

    kind: str
    value: str
    ports: str
    protocol: str
    address: IPAddress | None = None
    network: IPNetwork | None = None
    hostname: str | None = None


def _require_broad(policy: ScopePolicy, what: str) -> None:
    if not policy.allow_broad:
        raise ScopePolicyError(
            f"{what} is too broad to authorize without allow_broad on the scope"
        )


def _require_authorization(policy: ScopePolicy, what: str) -> None:
    if not policy.has_authorization:
        raise ScopePolicyError(
            f"{what} touches publicly routable space, so the scope needs a "
            "written authorization_ref"
        )


def _require_lab(policy: ScopePolicy, what: str) -> None:
    if not policy.is_lab:
        raise ScopePolicyError(
            f"{what} is loopback, which the platform's own services use; "
            "only a lab scope (is_lab) may authorize it"
        )


def validate_protocol(protocol: str | None) -> str:
    value = (protocol or "tcp").strip().lower()
    if value not in _PROTOCOLS:
        raise ScopePolicyError(
            f"protocol must be one of {', '.join(sorted(_PROTOCOLS))}, got {protocol!r}"
        )
    return value


def validate_ports(spec: str | None) -> str:
    if spec is None or not spec.strip():
        raise ScopePolicyError("ports must be given explicitly; an empty port list authorizes nothing")
    try:
        ranges = parse_ports(spec)
    except PortSpecError as exc:
        raise ScopePolicyError(str(exc)) from exc
    if not ranges:
        raise ScopePolicyError("ports must be given explicitly; an empty port list authorizes nothing")
    return format_ports(ranges)


def validate_hostname(value: str, policy: ScopePolicy) -> str:
    name = value.strip().lower().rstrip(".")
    if "*" in name:
        raise ScopePolicyError(
            "wildcard scope entries are not permitted; list each host explicitly"
        )
    if not _HOSTNAME_RE.match(name):
        raise ScopePolicyError(f"not a valid hostname: {value!r}")
    if name in _LOCAL_HOSTNAMES:
        _require_lab(policy, f"hostname {name!r}")
    return name


def validate_entry(
    kind: str,
    value: str,
    ports: str | None,
    protocol: str | None,
    policy: ScopePolicy,
) -> NormalizedEntry:
    """Validate one scope entry against the policy, or raise ScopePolicyError."""
    if kind not in ("cidr", "host"):
        raise ScopePolicyError(f"kind must be 'cidr' or 'host', got {kind!r}")

    normalized_ports = validate_ports(ports)
    normalized_protocol = validate_protocol(protocol)
    text = (value or "").strip()
    if not text:
        raise ScopePolicyError("value must not be empty")

    if kind == "cidr":
        try:
            network = parse_network(text)
        except AddressError as exc:
            raise ScopePolicyError(str(exc)) from exc

        denial = network_denial_reason(network)
        if denial is not None:
            raise ScopePolicyError(f"{network} refused: {denial}")
        if network_is_broad(network):
            _require_broad(policy, f"range {network}")
        if network_touches_public(network):
            _require_authorization(policy, f"range {network}")
        if network_contains_loopback(network):
            _require_lab(policy, f"range {network}")

        return NormalizedEntry(
            kind="cidr",
            value=str(network),
            ports=normalized_ports,
            protocol=normalized_protocol,
            network=network,
        )

    # kind == "host": either a literal address or a name.
    try:
        address = parse_address(text)
    except AddressError:
        address = None

    if address is not None:
        denial = denial_reason(address)
        if denial is not None:
            raise ScopePolicyError(f"{address} refused: {denial}")
        if inspect(text).classification is AddressClass.PUBLIC:
            _require_authorization(policy, f"address {address}")
        if is_loopback(address):
            _require_lab(policy, f"address {address}")

        return NormalizedEntry(
            kind="host",
            value=str(address),
            ports=normalized_ports,
            protocol=normalized_protocol,
            address=address,
        )

    hostname = validate_hostname(text, policy)
    return NormalizedEntry(
        kind="host",
        value=hostname,
        ports=normalized_ports,
        protocol=normalized_protocol,
        hostname=hostname,
    )
