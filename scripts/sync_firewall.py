#!/usr/bin/env python3
"""Refresh the CONTROLFORGE worker egress allow-list.

Run as root: by the oneshot unit ``controlforge-fw-sync.service``, by the
service account through the sudoers drop-in, or by hand.

What it does, in order:

1. Reads the base ruleset ``deploy/nftables/controlforge.nft`` (static rules +
   four empty interval sets).
2. Queries PostgreSQL **read-only** for every entry of every scope that is
   ``active`` and not expired. Preferred connection: the dedicated
   ``CONTROLFORGE_FW_DB_URL`` role from ``/etc/controlforge/fw.env``, which can
   only SELECT the ``v_scope_firewall_rules`` view. If that role or view has
   not been provisioned yet, it falls back to the application
   ``CONTROLFORGE_DB_URL`` from ``/etc/controlforge/controlforge.env`` and the
   base tables. Either way the URL (and therefore the password) is parsed
   in-process, handed to libpq via the environment, never logged, printed or
   written anywhere, and the transaction is opened with ``BEGIN READ ONLY``.
3. Expands each entry into ``<address range> . <port range>`` elements. Entries
   whose value is a hostname are resolved once, now, by this (root) process -
   the worker itself never uses DNS, it is handed pinned IPs. Entries with an
   unusable or empty port list are skipped with a warning: they authorize
   nothing (fail closed), matching the application-level policy.
4. Appends ``add element`` statements to the base and feeds everything to a
   single ``nft -f`` - one atomic transaction, so the worker is never left
   between rule sets.

Modes:
  (default)  generate and load the ruleset
  --check    generate and validate with ``nft --check`` (loads nothing)
  --flush    delete the table entirely (fail-open; deliberate teardown only)
  --print    additionally dump the generated ruleset to stdout
"""

from __future__ import annotations

import argparse
import ipaddress
import logging
import os
import re
import socket
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote, urlparse

LOG = logging.getLogger("controlforge.fw-sync")

REPO_ROOT = Path(__file__).resolve().parent.parent
BASE_RULESET = REPO_ROOT / "deploy" / "nftables" / "controlforge.nft"
# The install directory is not always /etc/controlforge, so the unit passes it in.
ENV_DIR = Path(os.environ.get("CONTROLFORGE_CONF_DIR", "/etc/controlforge"))
ENV_FILE = ENV_DIR / "controlforge.env"
FW_ENV_FILE = ENV_DIR / "fw.env"

NFT = "/usr/sbin/nft"
PSQL = "/usr/bin/psql"

TABLE_FAMILY = "inet"
TABLE_NAME = "controlforge"

#: (address family, protocol) -> set name in the base ruleset.
SETS: dict[tuple[str, str], str] = {
    ("v4", "tcp"): "allowed_v4_tcp",
    ("v4", "udp"): "allowed_v4_udp",
    ("v6", "tcp"): "allowed_v6_tcp",
    ("v6", "udp"): "allowed_v6_udp",
}

#: Every entry of every scope that is active and not expired. Read-only.
SCOPES_SQL = """BEGIN READ ONLY;
SET statement_timeout = 20000;
SELECT se.kind, se.value, se.ports, se.protocol
  FROM scope_entries AS se
  JOIN scopes AS s ON s.id = se.scope_id
 WHERE s.active = true
   AND (s.expires_at IS NULL OR s.expires_at > now())
 ORDER BY se.kind, se.value;
COMMIT;"""

#: Same data through the view the read-only firewall role is granted.
VIEW_SQL = """BEGIN READ ONLY;
SET statement_timeout = 20000;
SELECT entry_kind, entry_value, port_spec, protocol
  FROM v_scope_firewall_rules
 ORDER BY entry_kind, entry_value;
COMMIT;"""

#: psql stderr fragments that mean "not provisioned yet" (fall back), as
#: opposed to a real failure such as a refused connection (propagate).
_PROVISIONING_ERRORS = ("permission denied", "does not exist", "42501", "42P01")

_PORT_COMPONENT = re.compile(r"^\d{1,5}(?:-\d{1,5})?$")
_DIALECT_SUFFIX = re.compile(r"^postgresql\+[a-z0-9_]+://", re.IGNORECASE)


class SyncError(RuntimeError):
    """The ruleset could not be generated or loaded."""


# --------------------------------------------------------------------------- db


def read_env_value(path: Path, key: str) -> str | None:
    """One KEY=VALUE from an env file, or None (file or key missing)."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, _, value = line.partition("=")
        if name.strip() == key:
            return value.strip().strip('"').strip("'")
    return None


def libpq_environment(raw_url: str) -> dict[str, str]:
    """libpq environment built from a database URL.

    Values are never logged, printed or persisted; they only travel from the
    file through this process environment into the psql child process.
    """
    # SQLAlchemy dialect suffixes (postgresql+psycopg://...) are not libpq URLs.
    parsed = urlparse(_DIALECT_SUFFIX.sub("postgresql://", raw_url))
    if parsed.scheme not in ("postgresql", "postgres"):
        raise SyncError(f"unsupported database URL scheme {parsed.scheme!r} in DB_URL")

    env = dict(os.environ)
    env.update(
        {
            "PGHOST": parsed.hostname or "127.0.0.1",
            "PGPORT": str(parsed.port or 5432),
            "PGDATABASE": (parsed.path or "/controlforge").lstrip("/") or "controlforge",
            "PGUSER": unquote(parsed.username or "controlforge"),
            "PGCONNECT_TIMEOUT": "5",
            "PGAPPNAME": "controlforge-fw-sync",
        }
    )
    if parsed.password:
        env["PGPASSWORD"] = unquote(parsed.password)
    else:
        env.pop("PGPASSWORD", None)
    env.pop("PGSERVICE", None)  # an ambient service file must not redirect us
    return env


def psql_rows(env: dict[str, str], sql: str) -> list[tuple[str, str, str, str]]:
    """Run one read-only query, returning (kind, value, ports, protocol) rows."""
    try:
        proc = subprocess.run(
            [
                PSQL, "-w", "-q", "-X", "-A", "-t", "-F", "|",
                "-v", "ON_ERROR_STOP=1", "-c", sql,
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SyncError(f"could not run {PSQL}: {exc}") from exc
    if proc.returncode != 0:
        raise SyncError(f"psql exited {proc.returncode}: {proc.stderr.strip()[:400]}")

    rows: list[tuple[str, str, str, str]] = []
    for line in proc.stdout.splitlines():
        parts = line.split("|")
        if len(parts) != 4:
            continue  # BEGIN / SET / COMMIT command tags, if any
        kind, value, ports, protocol = (part.strip() for part in parts)
        if kind not in ("cidr", "host"):
            continue
        rows.append((kind, value, ports, protocol))
    return rows


def query_scope_entries() -> list[tuple[str, str, str, str]]:
    """(kind, value, ports, protocol) for active, unexpired scopes.

    Prefers the read-only firewall role + view; falls back to the application
    role + base tables only while the fw role is not provisioned yet.
    """
    fw_url = read_env_value(FW_ENV_FILE, "CONTROLFORGE_FW_DB_URL")
    if fw_url:
        try:
            return psql_rows(libpq_environment(fw_url), VIEW_SQL)
        except SyncError as exc:
            if not any(marker in str(exc) for marker in _PROVISIONING_ERRORS):
                raise
            LOG.warning(
                "read-only firewall role/view not usable yet; falling back to the "
                "application role for this run (%s)",
                exc,
            )
    app_url = read_env_value(ENV_FILE, "CONTROLFORGE_DB_URL")
    if not app_url:
        raise SyncError(f"CONTROLFORGE_DB_URL not found in {ENV_FILE}")
    return psql_rows(libpq_environment(app_url), SCOPES_SQL)


# ------------------------------------------------------------------ expansion


def parse_port_spec(spec: str) -> list[tuple[int, int]]:
    """Inclusive port ranges, or [] when the spec authorizes nothing.

    Fails closed: an empty spec - or the legacy literal "any" - yields no
    ports. The application refuses both at write time; a row that predates
    that rule must not silently widen the allow-list.
    """
    text = (spec or "").strip().lower()
    if not text or text == "any":
        return []
    ranges: list[tuple[int, int]] = []
    for component in text.split(","):
        component = component.strip()
        if not _PORT_COMPONENT.match(component):
            return []
        low, _, high = component.partition("-")
        start, end = int(low), int(high or low)
        if not 1 <= start <= end <= 65535:
            return []
        ranges.append((start, end))
    return merge_ranges(ranges)


def merge_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[list[int]] = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return [(start, end) for start, end in merged]


def resolve_name(name: str) -> list[tuple[str, int, int]]:
    """Resolve a name-rule hostname once, now, from the root process.

    Addresses the application would refuse to scan (loopback reached through a
    name, link-local, multicast, ...) are not allowed through the firewall
    either - fail closed on both layers.
    """
    try:
        infos = socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        LOG.warning("entry host %r could not be resolved (%s); skipping", name, exc)
        return []

    seen: dict[int, ipaddress.IPv4Address | ipaddress.IPv6Address] = {}
    for info in infos:
        try:
            addr = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if (
            addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_unspecified
            or addr.is_reserved
        ):
            LOG.warning("entry host %r resolves to %s; not allowed, skipping", name, addr)
            continue
        seen[int(addr)] = addr
    if not seen:
        LOG.warning("entry host %r resolved to no usable address; skipping", name)
    return [
        ("v4" if addr.version == 4 else "v6", int(addr), int(addr))
        for addr in sorted(seen.values(), key=int)
    ]


def address_blocks(kind: str, value: str) -> list[tuple[str, int, int]]:
    """[(family, first_address, last_address)] for one scope entry value."""
    text = value.strip()
    if kind == "cidr":
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError:
            LOG.warning("entry cidr %r is not a valid network; skipping", text)
            return []
        family = "v4" if network.version == 4 else "v6"
        return [(family, int(network.network_address), int(network.broadcast_address))]

    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return resolve_name(text)
    return [("v4" if addr.version == 4 else "v6", int(addr), int(addr))]


def disjoint_address_segments(
    rectangles: list[tuple[int, int, list[tuple[int, int]]]],
) -> list[tuple[int, int, list[tuple[int, int]]]]:
    """Split (address range, port ranges) rectangles into disjoint segments.

    nftables interval sets refuse overlapping elements with EEXIST, and
    overlapping rectangles are exactly what two scopes can produce - e.g. a
    CIDR entry and a host entry inside it authorizing the same port. Segments
    are cut at every range boundary and carry the union of the ports covering
    them, so the emitted elements are pairwise disjoint. Adjacent segments with
    identical port sets are merged back to keep the output compact.
    """
    if not rectangles:
        return []
    boundaries: set[int] = set()
    for first, last, _ in rectangles:
        boundaries.add(first)
        boundaries.add(last + 1)
    cuts = sorted(boundaries)

    segments: list[tuple[int, int, list[tuple[int, int]]]] = []
    for seg_first, end_exclusive in zip(cuts, cuts[1:]):
        seg_last = end_exclusive - 1
        ports: list[tuple[int, int]] = []
        for first, last, port_ranges in rectangles:
            if first <= seg_first and seg_last <= last:
                ports.extend(port_ranges)
        if not ports:
            continue
        merged_ports = merge_ranges(ports)
        if (
            segments
            and segments[-1][1] + 1 == seg_first
            and segments[-1][2] == merged_ports
        ):
            segments[-1] = (segments[-1][0], seg_last, merged_ports)
        else:
            segments.append((seg_first, seg_last, merged_ports))
    return segments


def build_element_lines(rows: list[tuple[str, str, str, str]]) -> tuple[list[str], dict[str, int]]:
    """`add element` statements for every usable scope entry."""
    # set name -> [(first address, last address, port ranges)]
    buckets: dict[str, list[tuple[int, int, list[tuple[int, int]]]]] = {
        name: [] for name in SETS.values()
    }

    for kind, value, ports, protocol in rows:
        port_ranges = parse_port_spec(ports)
        if not port_ranges:
            LOG.warning(
                "entry %s:%s authorizes no usable ports (%r); skipping - fail closed",
                kind, value, ports,
            )
            continue
        protocol_text = (protocol or "tcp").strip().lower()
        if protocol_text in ("any", ""):
            protocols_list = ["tcp", "udp"]
        elif protocol_text in ("tcp", "udp"):
            protocols_list = [protocol_text]
        else:
            LOG.warning("entry %s:%s has unknown protocol %r; skipping", kind, value, protocol)
            continue

        for family, first, last in address_blocks(kind, value):
            for proto in protocols_list:
                buckets[SETS[(family, proto)]].append((first, last, port_ranges))

    lines: list[str] = []
    counts: dict[str, int] = {}
    for (family, proto), set_name in sorted(SETS.items()):
        elements: list[str] = []
        for first, last, port_ranges in disjoint_address_segments(buckets[set_name]):
            first_addr = ipaddress.ip_address(first)
            address_text = (
                str(first_addr) if first == last else f"{first_addr}-{ipaddress.ip_address(last)}"
            )
            for start, end in port_ranges:
                port_text = str(start) if start == end else f"{start}-{end}"
                elements.append(f"{address_text} . {port_text}")
        if elements:
            lines.append(
                f"add element {TABLE_FAMILY} {TABLE_NAME} {set_name} {{ "
                + ", ".join(elements)
                + " }"
            )
            counts[f"{family}_{proto}"] = len(elements)
    return lines, counts


def generate_ruleset() -> tuple[str, dict[str, int]]:
    try:
        base = BASE_RULESET.read_text(encoding="utf-8")
    except OSError as exc:
        raise SyncError(f"cannot read base ruleset {BASE_RULESET}: {exc}") from exc

    rows = query_scope_entries()
    LOG.info(
        "database returned %d scope entr%s from active, unexpired scopes",
        len(rows), "y" if len(rows) == 1 else "ies",
    )
    element_lines, counts = build_element_lines(rows)
    merged = base.rstrip() + "\n"
    if element_lines:
        merged += "\n# --- active scope destinations (generated) ---\n"
        merged += "\n".join(element_lines) + "\n"
    return merged, counts


# --------------------------------------------------------------------- nft


def run_nft(ruleset: str, *, check_only: bool) -> None:
    argv = [NFT] + (["--check"] if check_only else []) + ["-f", "-"]
    try:
        proc = subprocess.run(argv, input=ruleset, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SyncError(f"could not run {NFT}: {exc}") from exc
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip()[:600]
        raise SyncError(f"nft rejected the ruleset: {detail}")


def flush() -> None:
    listing = subprocess.run(
        [NFT, "list", "table", TABLE_FAMILY, TABLE_NAME],
        capture_output=True, text=True,
    )
    if listing.returncode != 0:
        LOG.info("table %s %s is not loaded; nothing to flush", TABLE_FAMILY, TABLE_NAME)
        return
    proc = subprocess.run(
        [NFT, "delete", "table", TABLE_FAMILY, TABLE_NAME],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise SyncError(f"could not delete the table: {proc.stderr.strip()[:400]}")
    LOG.warning(
        "table %s %s deleted - the controlforge uid now has UNFILTERED egress",
        TABLE_FAMILY, TABLE_NAME,
    )


# -------------------------------------------------------------------- main


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sync_firewall.py",
        description="Regenerate the CONTROLFORGE worker egress allow-list from active scopes.",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--check", action="store_true",
        help="generate and validate with `nft --check`; load nothing",
    )
    mode.add_argument(
        "--flush", action="store_true",
        help="delete the table (deliberate teardown; returns the uid to unfiltered egress)",
    )
    parser.add_argument(
        "--print", dest="print_ruleset", action="store_true",
        help="print the generated ruleset to stdout",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="fw-sync: %(levelname)s %(message)s")

    if os.geteuid() != 0:
        LOG.error("must run as root (nft and %s both require it)", ENV_FILE)
        return 1

    try:
        if args.flush:
            flush()
            return 0

        ruleset, counts = generate_ruleset()
        if args.print_ruleset:
            sys.stdout.write(ruleset)
        total = sum(counts.values())
        summary = ", ".join(f"{name}: {count}" for name, count in sorted(counts.items()))
        LOG.info(
            "generated %d allow element(s)%s",
            total, f" ({summary})" if summary else " - empty allow-list, fail closed",
        )
        run_nft(ruleset, check_only=args.check)
        LOG.info(
            "ruleset %s",
            "validated (nft --check; nothing was loaded)"
            if args.check
            else "loaded atomically (single nft transaction)",
        )
        return 0
    except SyncError as exc:
        LOG.error("%s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
