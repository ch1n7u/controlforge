"""Exec-time authorization: the last gate before an engine is allowed to connect.

The order of operations here is the whole point, so it is worth stating:

1. Resolve the target hostname **once**, now. The resolved addresses are what
   gets handed to the engine; the engine never sees the hostname, so it cannot
   resolve it a second time to somewhere else. This is the DNS-rebinding and
   TOCTOU defence.
2. Apply hard denials to **every** resolved address. These cannot be waived by
   any rule, which is what stops a scope from being turned into an SSRF pivot
   against the metadata service.
3. Require that **every** resolved address is matched by at least one rule. An
   address that matches nothing fails the whole run - a name that now resolves
   to one authorized and one unauthorized address is a rebinding attempt, not
   a partial success.
4. Reject loopback reached *through a name*. A name rule authorizes names, and
   names can be re-pointed; loopback must therefore always be authorized by an
   explicit address rule. Without this, an attacker-controlled name that
   resolves to 127.0.0.1 would inherit the name rule's authority.
5. Require a written authorization for any publicly routable address.

The function is deliberately pure - rules in, decision out - so the policy can
be tested exhaustively without a database or a network.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv6Address

from app.scope.ports import port_allowed
from app.scope.ranges import (
    AddressClass,
    AddressError,
    IPAddress,
    address_class,
    denial_reason,
    embedded_ipv4,
    parse_address,
)

logger = logging.getLogger("valtros.scope")

ResolvedAddress = IPv4Address | IPv6Address

# A target names the application protocol it speaks ("http", "ssh"), while a
# scope entry authorizes a transport protocol, because that is the level at
# which an address and a port are actually reachable. Without this mapping the
# two vocabularies never meet: a webapp target would look for a scope entry
# that says "http", which the scope validator never lets anyone write.
_TRANSPORT_OF: dict[str, str] = {
    "http": "tcp",
    "https": "tcp",
    "tls": "tcp",
    "ssl": "tcp",
    "ssh": "tcp",
    "smtp": "tcp",
    "ftp": "tcp",
    "smb": "tcp",
    "rdp": "tcp",
    "ldap": "tcp",
    "ldaps": "tcp",
    "mysql": "tcp",
    "postgres": "tcp",
    "postgresql": "tcp",
    "mssql": "tcp",
    "ws": "tcp",
    "wss": "tcp",
    "dns": "udp",
    "snmp": "udp",
    "ntp": "udp",
}


def transport_of(protocol: str | None) -> str:
    """The transport protocol a target's protocol name is carried over."""
    value = (protocol or "tcp").strip().lower()
    return _TRANSPORT_OF.get(value, value)


class ResolutionError(RuntimeError):
    """The target hostname could not be resolved."""


@dataclass(frozen=True)
class ScopeRule:
    """One scope entry, flattened for evaluation.

    Built by the caller from scope entries that are active and unexpired. The
    authorization flags live on the scope, and travel with each rule because
    the decision needs them per match.
    """

    scope_id: int
    scope_name: str
    kind: str
    value: str
    ports: list[tuple[int, int]]
    protocol: str
    has_authorization: bool = False
    is_lab: bool = False

    @property
    def description(self) -> str:
        return f"{self.scope_name}:{self.kind}:{self.value}"

    @property
    def is_name_rule(self) -> bool:
        return self.kind == "host" and _looks_like_name(self.value)

    def covers_address(self, addr: IPAddress) -> bool:
        if self.kind == "cidr":
            try:
                return addr in ipaddress.ip_network(self.value, strict=False)
            except ValueError:
                return False
        if self.is_name_rule:
            return False  # evaluated against the hostname, not the address
        try:
            return addr == parse_address(self.value)
        except AddressError:
            return False

    def covers_hostname(self, hostname: str) -> bool:
        return self.is_name_rule and self.value.strip().lower() == hostname.strip().lower()


def _looks_like_name(value: str) -> bool:
    try:
        parse_address(value)
    except AddressError:
        return True
    return False


@dataclass
class Decision:
    allowed: bool
    reason: str
    addresses: list[str] = field(default_factory=list)
    matched_rules: list[str] = field(default_factory=list)

    @property
    def scope_snapshot(self) -> dict:
        return {
            "addresses": self.addresses,
            "matched_rules": self.matched_rules,
            "reason": self.reason,
        }


def resolve_host(host: str, port: int | None = None) -> list[ResolvedAddress]:
    """Resolve ``host`` to addresses, or raise ResolutionError.

    No caching, on purpose: a cached answer is exactly what a rebinding attack
    needs. Addresses are returned in a stable order so that repeated runs
    against a stable name produce identical decisions.
    """
    try:
        return [parse_address(host)]  # already an address, nothing to resolve
    except AddressError:
        pass

    try:
        infos = socket.getaddrinfo(
            host, port or 0, proto=socket.IPPROTO_TCP, type=socket.SOCK_STREAM
        )
    except socket.gaierror as exc:
        raise ResolutionError(f"could not resolve {host!r}: {exc}") from exc

    seen: dict[str, ResolvedAddress] = {}
    for info in infos:
        sockaddr = info[4]
        try:
            addr = parse_address(sockaddr[0])
        except AddressError:
            continue
        seen[str(addr)] = addr

    if not seen:
        raise ResolutionError(f"{host!r} resolved to no usable addresses")

    ordered = sorted(seen.values(), key=lambda a: (a.version, int(a)))
    return ordered


def authorize(
    host: str,
    port: int,
    protocol: str,
    rules: list[ScopeRule],
    *,
    addresses: list[ResolvedAddress] | None = None,
) -> Decision:
    """Decide whether one (host, port, protocol) may be tested."""
    protocol = transport_of(protocol)

    if addresses is None:
        try:
            addresses = resolve_host(host, port)
        except ResolutionError as exc:
            return Decision(allowed=False, reason=str(exc))

    if not addresses:
        return Decision(allowed=False, reason=f"{host!r} resolved to no addresses")

    hostname = host.strip().lower()
    address_texts = [str(a) for a in addresses]

    # Step 2: hard denials first, so the specific reason wins over "no rule".
    for addr in addresses:
        reason = denial_reason(addr)
        if reason is not None:
            return Decision(
                allowed=False,
                reason=f"{addr} is never authorized: {reason}",
                addresses=address_texts,
            )

    if not rules:
        return Decision(
            allowed=False,
            reason=f"no active scope authorizes {host}",
            addresses=address_texts,
        )

    matched: list[str] = []
    for addr in addresses:
        rule, reason = _match_address(addr, hostname, port, protocol, rules)
        if rule is None:
            return Decision(
                allowed=False, reason=reason, addresses=address_texts, matched_rules=matched
            )
        matched.append(rule.description)

    return Decision(
        allowed=True,
        reason=f"authorized by {', '.join(dict.fromkeys(matched))}",
        addresses=address_texts,
        matched_rules=list(dict.fromkeys(matched)),
    )


def _match_address(
    addr: IPAddress,
    hostname: str,
    port: int,
    protocol: str,
    rules: list[ScopeRule],
) -> tuple[ScopeRule | None, str]:
    """Find a rule that authorizes this address, or explain why none does.

    ``addr`` may be an IPv6 form carrying an embedded IPv4 address; the
    embedded form is offered to the rules too, so ``::ffff:127.0.0.1`` cannot
    slip past a rule written for ``127.0.0.1``.
    """
    candidates: list[IPAddress] = [addr, *embedded_ipv4(addr)]
    loopback = any(address_class(c) is AddressClass.LOOPBACK for c in candidates)

    applicable = [
        rule
        for rule in rules
        if rule.protocol in (protocol, "any") and port_allowed(port, rule.ports)
    ]
    if not applicable:
        return None, f"no scope entry authorizes port {port}/{protocol}"

    # Address rules are the stronger authorization, so they get first refusal.
    for candidate in candidates:
        for rule in applicable:
            if not rule.covers_address(candidate):
                continue
            if _public_needs_authorization(candidate) and not rule.has_authorization:
                return None, (
                    f"{candidate} is publicly routable but scope "
                    f"{rule.scope_name!r} has no authorization_ref"
                )
            return rule, ""

    if loopback:
        # A name can be re-pointed at any time, so a name rule must never be
        # able to authorize loopback - that would turn any scoped hostname
        # into a route back to this machine's own services.
        if any(rule.covers_hostname(hostname) for rule in applicable):
            return None, (
                f"{hostname} resolves to loopback {addr}; a name rule cannot "
                "authorize loopback, an explicit address rule is required"
            )
        return None, f"{addr} (port {port}/{protocol}) is not covered by any active scope entry"

    for rule in applicable:
        if not rule.covers_hostname(hostname):
            continue
        if _public_needs_authorization(addr) and not rule.has_authorization:
            return None, (
                f"{hostname} resolves to publicly routable {addr} but scope "
                f"{rule.scope_name!r} has no authorization_ref"
            )
        return rule, ""

    return None, f"{addr} (port {port}/{protocol}) is not covered by any active scope entry"


def _public_needs_authorization(addr: IPAddress) -> bool:
    return address_class(addr) is AddressClass.PUBLIC
