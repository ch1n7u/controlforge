"""The worker's kernel egress policy.

This is the layer that holds when the application layer is wrong: if a bug let a
run aim somewhere the scopes do not authorize, the uid still cannot reach it. So
the ruleset is worth guarding directly, and the parts of the generator that
decide what gets allowed are worth testing on their own.

The ruleset cannot be exercised here - loading it needs root - but its shape can
be read. What is asserted below are the properties whose loss would otherwise be
invisible until something had already escaped, or until a scan mysteriously ran
out of time.
"""

from __future__ import annotations

import importlib.util
import ipaddress
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
RULESET = REPO_ROOT / "deploy" / "nftables" / "valtros.nft"
SYNC_SCRIPT = REPO_ROOT / "scripts" / "sync_firewall.py"


@pytest.fixture(scope="module")
def sync():
    spec = importlib.util.spec_from_file_location("sync_firewall", SYNC_SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def rules(ruleset_text) -> list[str]:
    """The rules of the output chain, in order, without comments."""
    body = ruleset_text.split("chain output {", 1)[1]
    return [
        line.strip()
        for line in body.splitlines()
        if line.strip() and not line.strip().startswith(("#", "}"))
    ]


@pytest.fixture(scope="module")
def ruleset_text() -> str:
    return RULESET.read_text(encoding="utf-8")


def _addr(text: str) -> int:
    return int(ipaddress.ip_address(text))


# ------------------------------------------------------------------ the ruleset


def test_the_uid_is_denied_by_default(rules):
    """Every rule before the drop is an exception; the drop is the policy."""
    assert rules[-1] == "meta skuid valtros counter drop"


def test_only_the_worker_uid_is_filtered(ruleset_text):
    """`policy accept` is what keeps root, nginx and the API unfiltered."""
    assert "type filter hook output priority filter; policy accept;" in ruleset_text
    for line in ruleset_text.splitlines():
        if "skuid" in line:
            assert "valtros" in line, line


def test_unpermitted_loopback_is_refused_not_blackholed(ruleset_text, rules):
    """A silent drop on loopback makes tools hang instead of failing.

    testssl.sh probes ``openssl s_client -tls1`` with no -connect at startup,
    which lands on localhost:4433. Blackholed, that probe consumes the entire
    run budget and the run is reported as a timeout; refused, it returns in
    milliseconds and the scan proceeds. Nothing leaves the host either way, so
    the refusal discloses nothing.
    """
    assert any(
        "ip daddr 127.0.0.1 meta l4proto tcp counter reject with tcp reset" in line for line in rules
    ), "TCP loopback needs a reset, which is what makes connect() fail immediately"
    assert any(line.endswith("ip daddr 127.0.0.1 counter reject") for line in rules)
    assert any(line.endswith("ip6 daddr ::1 counter reject") for line in rules)

    # Ordering carries the meaning: a refusal above the allow rules would
    # refuse the scoped targets themselves.
    allow = next(i for i, line in enumerate(rules) if "@allowed_v4_tcp" in line)
    reject = next(i for i, line in enumerate(rules) if line.endswith("ip daddr 127.0.0.1 counter reject"))
    drop = next(i for i, line in enumerate(rules) if line.endswith("counter drop"))
    assert allow < reject < drop


def test_there_is_no_dns_rule(ruleset_text):
    """Engines are handed pinned addresses, so the uid must not need a resolver."""
    assert "dport 53" not in ruleset_text


# --------------------------------------------------------------- the generator


def test_a_port_spec_that_authorizes_nothing_fails_closed(sync):
    for spec in ("", "   ", "any", "ANY", "http", "0", "70000", "80-", "-80", "80,,443", "80;443"):
        assert sync.parse_port_spec(spec) == [], spec


def test_port_specs_are_parsed_and_merged(sync):
    assert sync.parse_port_spec("443") == [(443, 443)]
    assert sync.parse_port_spec("80,443") == [(80, 80), (443, 443)]
    assert sync.parse_port_spec("8000-8010") == [(8000, 8010)]
    # Overlapping and adjacent components collapse into one range.
    assert sync.parse_port_spec("80,80,81-83,90") == [(80, 83), (90, 90)]
    assert sync.parse_port_spec("1-2,3-4") == [(1, 4)]


def test_a_hostname_that_resolves_to_loopback_is_not_usable(sync, monkeypatch):
    """The application refuses loopback reached through a name; so does this."""
    monkeypatch.setattr(
        sync.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("127.0.0.1", 0))]
    )
    assert sync.resolve_name("localhost") == []


def test_a_hostname_that_will_not_resolve_is_skipped(sync, monkeypatch):
    def boom(*args, **kwargs):
        raise sync.socket.gaierror("no such host")

    monkeypatch.setattr(sync.socket, "getaddrinfo", boom)
    assert sync.resolve_name("nope.invalid") == []


def test_overlapping_authorizations_become_disjoint_elements(sync):
    """nftables interval sets refuse overlapping elements, and two scopes
    covering the same address with different ports is an ordinary thing to
    write down: the address must be split so each port set is carried by an
    address range that does not overlap its neighbours."""
    rectangles = [
        (_addr("10.0.0.0"), _addr("10.0.0.255"), [(443, 443)]),
        (_addr("10.0.0.5"), _addr("10.0.0.5"), [(8443, 8443)]),
    ]
    segments = sync.disjoint_address_segments(rectangles)

    spans = [(first, last) for first, last, _ in segments]
    assert spans == sorted(spans)
    for (_, last, _), (next_first, _, _) in zip(segments, segments[1:]):
        assert last < next_first, "segments must not overlap"
    assert all(ports for _, _, ports in segments)

    # The single address that both scopes cover now carries both ports; the
    # addresses only the first scope covers carry only 443.
    shared = _addr("10.0.0.5")
    for first, _, ports in segments:
        assert ports == ([(443, 443), (8443, 8443)] if first == shared else [(443, 443)])
