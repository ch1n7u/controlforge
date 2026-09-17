"""Port specification parsing and matching.

A scope entry's port authorization is a list of inclusive ranges. An empty
spec means *no* ports are authorized - never "all ports". Failing closed here
matters: a parsing bug that turns "" into "any" would silently widen every
scope that forgot to set ports.
"""

from __future__ import annotations

import re

_SPEC_RE = re.compile(r"^\d{1,5}(?:-\d{1,5})?$")

MAX_PORT = 65535

# An explicit word for "every port", because the column default has always been
# "any" and a default that fails to parse would make every entry typed without
# a port list unusable. It is still a deliberate authorization, not a fallback:
# an *empty* spec continues to mean no ports at all.
ANY_SPECS = frozenset({"any", "*"})

ALL_PORTS = f"1-{MAX_PORT}"


class PortSpecError(ValueError):
    """The port specification could not be parsed."""


def parse_ports(spec: str | None) -> list[tuple[int, int]]:
    """Parse ``"80,443,8000-8100"`` into sorted, merged inclusive ranges.

    ``"any"`` and ``"*"`` mean every port, and are spelled out rather than
    implied. Anything unparseable raises rather than being ignored.
    """
    if spec is None or not spec.strip():
        return []
    if spec.strip().lower() in ANY_SPECS:
        return [(1, MAX_PORT)]

    ranges: list[tuple[int, int]] = []
    for raw in spec.split(","):
        part = raw.strip()
        if not _SPEC_RE.match(part):
            raise PortSpecError(f"invalid port component: {part!r}")
        low, _, high = part.partition("-")
        start = int(low)
        end = int(high) if high else start
        if not (1 <= start <= MAX_PORT and 1 <= end <= MAX_PORT):
            raise PortSpecError(f"port out of range 1-{MAX_PORT}: {part!r}")
        if start > end:
            raise PortSpecError(f"inverted port range: {part!r}")
        ranges.append((start, end))

    ranges.sort()
    return _merge(ranges)


def _merge(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged = [ranges[0]]
    for start, end in ranges[1:]:
        last_start, last_end = merged[-1]
        if start <= last_end + 1:
            merged[-1] = (last_start, max(last_end, end))
        else:
            merged.append((start, end))
    return merged


def port_allowed(port: int, ranges: list[tuple[int, int]]) -> bool:
    return any(start <= port <= end for start, end in ranges)


def format_ports(ranges: list[tuple[int, int]]) -> str:
    parts = []
    for start, end in ranges:
        parts.append(str(start) if start == end else f"{start}-{end}")
    return ",".join(parts)


def describe_ports(spec: str | None) -> str:
    return format_ports(parse_ports(spec)) or "none"
