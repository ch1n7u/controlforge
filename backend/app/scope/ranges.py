"""Address classification for the scope engine.

Two jobs:

1. **Hard denial.** A small set of destinations can never be authorized by any
   scope, whatever its flags say - cloud instance-metadata endpoints above all,
   since reaching them from a validation engine is exactly how a "security
   tool" becomes an SSRF pivot.

2. **Classification.** Deciding whether an address is loopback, private or
   globally routable, so the policy layer can require the right flags.

The subtle part is that several IPv6 forms *embed* an IPv4 address. Checking
``::ffff:169.254.169.254`` as an IPv6 address alone would sail past a rule
written for ``169.254.0.0/16``, so every embedded form is unwrapped and checked
as IPv4 as well.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import StrEnum

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


class AddressClass(StrEnum):
    LOOPBACK = "loopback"
    LINK_LOCAL = "link_local"
    MULTICAST = "multicast"
    RESERVED = "reserved"
    UNSPECIFIED = "unspecified"
    PRIVATE = "private"
    PUBLIC = "public"


class AddressError(ValueError):
    """The address could not be parsed."""


def parse_address(value: str) -> IPAddress:
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise AddressError(f"not a valid IP address: {value!r}") from exc


def parse_network(value: str) -> IPNetwork:
    """Parse a network, accepting a bare address as a host network.

    ``strict=False`` so ``192.168.1.5/24`` is read as the containing network
    instead of being rejected - operators type this constantly, and silently
    interpreting it as "the /24 that contains this host" is the least
    surprising reading.
    """
    text = value.strip()
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError as exc:
        raise AddressError(f"not a valid CIDR network: {value!r}") from exc


# --------------------------------------------------------------- hard denials

#: IPv4 ranges that no scope may ever authorize, directly or by overlap.
HARD_DENIED_V4: tuple[IPNetwork, ...] = (
    ipaddress.ip_network("0.0.0.0/8"),        # "this network"
    ipaddress.ip_network("169.254.0.0/16"),   # link-local, includes 169.254.169.254 metadata
    ipaddress.ip_network("100.64.0.0/10"),    # CGNAT, includes 100.100.100.200 metadata
    ipaddress.ip_network("192.0.0.0/24"),     # IETF protocol assignments
    ipaddress.ip_network("192.0.2.0/24"),     # TEST-NET-1
    ipaddress.ip_network("198.18.0.0/15"),    # benchmarking
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),   # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),      # multicast
    ipaddress.ip_network("240.0.0.0/4"),      # reserved, includes 255.255.255.255
)

#: IPv6 ranges that no scope may ever authorize.
HARD_DENIED_V6: tuple[IPNetwork, ...] = (
    ipaddress.ip_network("::/128"),           # unspecified
    ipaddress.ip_network("100::/64"),         # discard-only
    ipaddress.ip_network("2001:2::/48"),      # benchmarking
    ipaddress.ip_network("2001:db8::/32"),    # documentation
    ipaddress.ip_network("fe80::/10"),        # link-local
    ipaddress.ip_network("ff00::/8"),         # multicast
    ipaddress.ip_network("fd00:ec2::254/128"),  # AWS IPv6 instance metadata
)

#: Addresses that are singled out by name because they are worth a clear error.
NAMED_DENIALS: dict[str, str] = {
    "169.254.169.254": "cloud instance metadata (AWS/GCP/Azure/OpenStack)",
    "169.254.170.2": "ECS task metadata",
    "100.100.100.200": "Alibaba Cloud instance metadata",
    "fd00:ec2::254": "AWS IPv6 instance metadata",
    "192.0.0.192": "Oracle Cloud instance metadata",
    "metadata.google.internal": "GCP metadata hostname",
}

#: Resolved form of the IP-valued entries above, checked before range rules so
#: the operator gets the specific reason rather than a generic one.
_NAMED_DENIAL_ADDRESSES: dict[IPAddress, str] = {}
for _name, _what in NAMED_DENIALS.items():
    try:
        _NAMED_DENIAL_ADDRESSES[ipaddress.ip_address(_name)] = _what
    except ValueError:
        continue  # hostname entries are matched by the policy layer
del _name, _what

_LOOPBACK_V4 = ipaddress.ip_network("127.0.0.0/8")
_LOOPBACK_V6 = ipaddress.ip_network("::1/128")
_PRIVATE_V4 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
_PRIVATE_V6 = (ipaddress.ip_network("fc00::/7"),)


# -------------------------------------------------- IPv4-in-IPv6 unwrapping

_IPV4_MAPPED = ipaddress.ip_network("::ffff:0:0/96")
_NAT64_WELL_KNOWN = ipaddress.ip_network("64:ff9b::/96")
_SIX_TO_FOUR = ipaddress.ip_network("2002::/16")
_TEREDO = ipaddress.ip_network("2001::/32")


def embedded_ipv4(addr: IPAddress) -> list[ipaddress.IPv4Address]:
    """Return IPv4 addresses smuggled inside an IPv6 address, if any.

    Covers IPv4-mapped, NAT64 (well-known prefix), 6to4 and Teredo - the four
    forms an attacker would reach for to slip a blocked IPv4 destination past
    a v4-only denylist.
    """
    if addr.version != 6:
        return []

    found: list[ipaddress.IPv4Address] = []
    if addr in _IPV4_MAPPED:
        found.append(ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF))
    if addr in _NAT64_WELL_KNOWN:
        found.append(ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF))
    if addr in _SIX_TO_FOUR:
        found.append(ipaddress.IPv4Address((int(addr) >> 80) & 0xFFFFFFFF))
    if addr in _TEREDO:
        # The client IPv4 is the last 32 bits, XOR-obfuscated with 0xffffffff.
        raw = int(addr) & 0xFFFFFFFF
        found.append(ipaddress.IPv4Address(raw ^ 0xFFFFFFFF))

    # A bare IPv4-compatible address (::a.b.c.d, deprecated but still parsed).
    if int(addr) >> 32 == 0 and addr not in _LOOPBACK_V6:
        found.append(ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF))

    return [a for a in found if a != ipaddress.IPv4Address(0)]


def contains_embedded_version(addr: IPAddress) -> bool:
    """True when a v6 address carries a v4 address that could escape v4 rules."""
    return bool(embedded_ipv4(addr))


# ---------------------------------------------------------------- hard denial


def denial_reason(addr: IPAddress) -> str | None:
    """Return why ``addr`` can never be authorized, or None if it may be.

    The address *and* any IPv4 address embedded in it are checked.
    """
    candidates: list[IPAddress] = [addr, *embedded_ipv4(addr)]
    for candidate in candidates:
        if is_loopback(candidate):
            continue  # loopback is gated by the policy layer, not hard-denied
        if candidate in _NAMED_DENIAL_ADDRESSES:
            return _NAMED_DENIAL_ADDRESSES[candidate]
        blocked = HARD_DENIED_V4 if candidate.version == 4 else HARD_DENIED_V6
        for network in blocked:
            if candidate in network:
                return f"{network} is never authorized"
    return None


def network_denial_reason(network: IPNetwork) -> str | None:
    """Return why a whole network can never be authorized, or None.

    Rejects on *overlap*: a scope that authorizes ``10.0.0.0/8`` is fine, but
    one that authorizes a range containing a denied address is not - the engine
    is handed IPs and would happily scan straight into it. Because
    ``0.0.0.0/0`` overlaps everything, it is refused by construction.

    Loopback is deliberately absent from the denied lists: it is *gated* by the
    policy layer (``is_lab``), not denied, so a lab scope can authorize it.
    """
    blocked = HARD_DENIED_V4 if network.version == 4 else HARD_DENIED_V6
    for denied in blocked:
        if network.overlaps(denied):
            return f"range overlaps {denied}, which is never authorized"

    if network.version == 6 and network.overlaps(_IPV4_MAPPED):
        return "range covers IPv4-mapped addresses, which bypass IPv4 policy"
    return None


# -------------------------------------------------------------- classification


def address_class(addr: IPAddress) -> AddressClass:
    if addr.version == 4:
        if addr in _LOOPBACK_V4:
            return AddressClass.LOOPBACK
        if addr.is_unspecified:
            return AddressClass.UNSPECIFIED
        if addr.is_link_local:
            return AddressClass.LINK_LOCAL
        if addr.is_multicast:
            return AddressClass.MULTICAST
        if addr.is_reserved:
            return AddressClass.RESERVED
        if any(addr in net for net in _PRIVATE_V4):
            return AddressClass.PRIVATE
        return AddressClass.PUBLIC

    if addr in _LOOPBACK_V6:
        return AddressClass.LOOPBACK
    if addr.is_unspecified:
        return AddressClass.UNSPECIFIED
    if addr.is_link_local:
        return AddressClass.LINK_LOCAL
    if addr.is_multicast:
        return AddressClass.MULTICAST
    if any(addr in net for net in _PRIVATE_V6):
        return AddressClass.PRIVATE
    if addr.is_reserved:
        return AddressClass.RESERVED
    return AddressClass.PUBLIC


def is_loopback(addr: IPAddress) -> bool:
    return address_class(addr) is AddressClass.LOOPBACK


def is_private(addr: IPAddress) -> bool:
    return address_class(addr) in (AddressClass.PRIVATE, AddressClass.LOOPBACK)


def network_contains_loopback(network: IPNetwork) -> bool:
    loopback = _LOOPBACK_V4 if network.version == 4 else _LOOPBACK_V6
    return network.overlaps(loopback)


def network_touches_public(network: IPNetwork) -> bool:
    """True when the network is not entirely inside private/non-routable space.

    ``ipaddress``'s ``is_private`` answers exactly this question for a network:
    it is true only when the *whole* range sits in non-routable space, so a
    range that straddles private and public space (``10.0.0.0/7``) reports
    False and is treated as touching the public internet.
    """
    return not network.is_private


def network_is_broad(network: IPNetwork, max_hosts: int = 65536) -> bool:
    """A network large enough that scanning it is a sweep, not a check."""
    return network.num_addresses > max_hosts


@dataclass(frozen=True)
class AddressFacts:
    """Everything the policy layer needs to judge one address."""

    address: IPAddress
    classification: AddressClass
    denial: str | None
    embedded: tuple[str, ...]

    @property
    def authorised_candidate(self) -> bool:
        return self.denial is None


def inspect(value: str) -> AddressFacts:
    addr = parse_address(value)
    return AddressFacts(
        address=addr,
        classification=address_class(addr),
        denial=denial_reason(addr),
        embedded=tuple(str(a) for a in embedded_ipv4(addr)),
    )
