"""The scope policy is the platform's core safety claim, so it gets attacked.

Every test in this file is either a bypass attempt that *must* be refused or a
legitimate authorization that must still work. The refusals matter more: a
scope engine that is merely inconvenient to bypass is worthless, so the
interesting cases are metadata access, DNS rebinding, IPv4-mapped IPv6,
over-broad ranges and port smuggling.
"""

from __future__ import annotations

import ipaddress

import pytest

from app.scope import (
    PortSpecError,
    ScopePolicy,
    ScopePolicyError,
    ScopeRule,
    authorize,
    denial_reason,
    embedded_ipv4,
    inspect,
    parse_ports,
    port_allowed,
    validate_entry,
)

ip = ipaddress.ip_address

LAB = ScopePolicy(is_lab=True)
PUBLIC = ScopePolicy(authorization_ref="engagement-2026-014")
BROAD = ScopePolicy(allow_broad=True)


def rule(value, *, kind="host", ports="443", protocol="tcp", policy=None, scope_id=1):
    entry = validate_entry(kind, value, ports, protocol, policy or LAB)
    return ScopeRule(
        scope_id=scope_id,
        scope_name=f"scope{scope_id}",
        kind=entry.kind,
        value=entry.value,
        ports=parse_ports(entry.ports),
        protocol=entry.protocol,
        has_authorization=(policy or LAB).has_authorization,
        is_lab=(policy or LAB).is_lab,
    )


# ----------------------------------------------------------------- ports ----


def test_port_spec_parses_and_merges():
    assert parse_ports("80,443,8000-8002,8001") == [(80, 80), (443, 443), (8000, 8002)]


@pytest.mark.parametrize("spec", ["", None, "   "])
def test_empty_port_spec_authorizes_nothing(spec):
    """Failing closed: "" must never mean "all ports"."""
    assert parse_ports(spec) == []


@pytest.mark.parametrize("spec", ["0", "65536", "80-", "-80", "abc", "80,,443", "1-2-3"])
def test_malformed_port_specs_are_rejected(spec):
    with pytest.raises(PortSpecError):
        parse_ports(spec)


def test_inverted_port_range_is_rejected():
    with pytest.raises(PortSpecError):
        parse_ports("9000-8000")


def test_port_matching_is_inclusive():
    ranges = parse_ports("8000-8010")
    assert port_allowed(8000, ranges) and port_allowed(8010, ranges)
    assert not port_allowed(7999, ranges) and not port_allowed(8011, ranges)


# --------------------------------------------------- never-authorizable IPs --


@pytest.mark.parametrize(
    "address",
    [
        "169.254.169.254",   # AWS/GCP/Azure/OpenStack metadata
        "169.254.170.2",     # ECS task metadata
        "100.100.100.200",   # Alibaba metadata
        "fd00:ec2::254",     # AWS IPv6 metadata
        "192.0.0.192",       # Oracle metadata
        "224.0.0.1",         # multicast
        "255.255.255.255",   # broadcast
        "0.0.0.0",           # unspecified
        "fe80::1",           # IPv6 link-local
        "ff02::1",           # IPv6 multicast
    ],
)
def test_metadata_and_reserved_addresses_are_hard_denied(address):
    assert denial_reason(ip(address)) is not None


def test_metadata_address_cannot_be_authorized_even_in_a_permissive_scope():
    """No combination of flags authorizes the metadata service."""
    for policy in (LAB, PUBLIC, BROAD, ScopePolicy(allow_broad=True, is_lab=True, authorization_ref="x")):
        with pytest.raises(ScopePolicyError) as excinfo:
            validate_entry("host", "169.254.169.254", "80", "tcp", policy)
        assert "refused" in str(excinfo.value)


def test_metadata_cannot_be_smuggled_through_a_cidr():
    """A range containing metadata is refused outright, so 0.0.0.0/0 is impossible."""
    for cidr in ("169.254.0.0/16", "0.0.0.0/0", "169.254.169.0/24", "100.64.0.0/10"):
        with pytest.raises(ScopePolicyError) as excinfo:
            validate_entry("cidr", cidr, "80", "tcp", ScopePolicy(allow_broad=True, is_lab=True, authorization_ref="x"))
        assert "refused" in str(excinfo.value)


# ------------------------------------------------- IPv4-inside-IPv6 bypasses --


@pytest.mark.parametrize(
    "address,expected_embedded",
    [
        ("::ffff:169.254.169.254", "169.254.169.254"),  # IPv4-mapped
        ("::ffff:127.0.0.1", "127.0.0.1"),              # mapped loopback
        ("64:ff9b::a9fe:a9fe", "169.254.169.254"),      # NAT64 of metadata
        ("2002:a9fe:a9fe::", "169.254.169.254"),        # 6to4 of metadata
    ],
)
def test_ipv4_addresses_embedded_in_ipv6_are_detected(address, expected_embedded):
    found = [str(a) for a in embedded_ipv4(ipaddress.ip_address(address))]
    assert expected_embedded in found


def test_ipv4_mapped_metadata_is_denied():
    """Checking the v6 address alone would sail straight past a v4 denylist."""
    assert denial_reason(ipaddress.ip_address("::ffff:169.254.169.254")) is not None


def test_ipv4_mapped_loopback_is_classified_as_loopback():
    facts = inspect("::ffff:127.0.0.1")
    assert facts.embedded == ("127.0.0.1",)
    assert facts.classification is not None


def test_mapped_metadata_fails_an_end_to_end_authorization():
    decision = authorize(
        "::ffff:169.254.169.254",
        80,
        "tcp",
        [rule("127.0.0.1/32", kind="cidr", ports="80")],
    )
    assert decision.allowed is False
    assert "never authorized" in decision.reason


# ------------------------------------------------------------ broad ranges --


def test_broad_range_requires_allow_broad():
    with pytest.raises(ScopePolicyError) as excinfo:
        validate_entry("cidr", "10.0.0.0/8", "443", "tcp", ScopePolicy(is_lab=True))
    assert "allow_broad" in str(excinfo.value)


def test_narrow_range_needs_no_allow_broad():
    entry = validate_entry("cidr", "10.20.30.0/24", "443", "tcp", ScopePolicy(is_lab=True))
    assert entry.value == "10.20.30.0/24"


def test_broad_range_is_accepted_with_the_flag():
    entry = validate_entry("cidr", "10.0.0.0/8", "443", "tcp", ScopePolicy(allow_broad=True))
    assert entry.value == "10.0.0.0/8"


def test_public_range_requires_authorization_reference():
    with pytest.raises(ScopePolicyError) as excinfo:
        validate_entry("cidr", "203.0.112.0/24", "443", "tcp", ScopePolicy(allow_broad=True))
    assert "authorization_ref" in str(excinfo.value)


def test_public_range_is_accepted_with_authorization():
    entry = validate_entry("cidr", "8.8.8.0/24", "443", "tcp", PUBLIC)
    assert entry.value == "8.8.8.0/24"


# ------------------------------------------------------------ loopback gate --


def test_loopback_requires_a_lab_scope():
    with pytest.raises(ScopePolicyError) as excinfo:
        validate_entry("host", "127.0.0.1", "8081", "tcp", ScopePolicy())
    assert "lab scope" in str(excinfo.value)


def test_localhost_hostname_requires_a_lab_scope():
    with pytest.raises(ScopePolicyError):
        validate_entry("host", "localhost", "8081", "tcp", ScopePolicy())


def test_loopback_is_accepted_for_a_lab_scope():
    entry = validate_entry("host", "127.0.0.1", "8081", "tcp", LAB)
    assert entry.value == "127.0.0.1"


# ------------------------------------------------------------ hostname rules --


def test_wildcards_are_refused():
    for value in ("*.example.com", "example.*", "*"):
        with pytest.raises(ScopePolicyError) as excinfo:
            validate_entry("host", value, "443", "tcp", LAB)
        assert "wildcard" in str(excinfo.value)


def test_hostnames_are_normalised_to_lowercase():
    entry = validate_entry("host", "App.Example.COM.", "443", "tcp", LAB)
    assert entry.value == "app.example.com"


@pytest.mark.parametrize("value", ["not a hostname", "-bad.example.com", "a..b", "x" * 300])
def test_invalid_hostnames_are_refused(value):
    with pytest.raises(ScopePolicyError):
        validate_entry("host", value, "443", "tcp", LAB)


def test_empty_value_is_refused():
    with pytest.raises(ScopePolicyError):
        validate_entry("host", "   ", "443", "tcp", LAB)


def test_ports_must_be_explicit_on_a_scope_entry():
    with pytest.raises(ScopePolicyError) as excinfo:
        validate_entry("cidr", "10.0.0.0/24", "", "tcp", LAB)
    assert "explicitly" in str(excinfo.value)


def test_protocol_is_validated():
    with pytest.raises(ScopePolicyError):
        validate_entry("host", "10.0.0.5", "443", "sctp", LAB)


# ------------------------------------------------- end-to-end authorization --


def test_authorized_target_passes():
    rules = [rule("127.0.0.1", ports="8081")]
    decision = authorize("127.0.0.1", 8081, "tcp", rules)
    assert decision.allowed is True
    assert decision.addresses == ["127.0.0.1"]


def test_unscoped_target_is_refused():
    decision = authorize("127.0.0.2", 8081, "tcp", [rule("127.0.0.1", ports="8081")])
    assert decision.allowed is False
    assert "not covered" in decision.reason


def test_unscoped_port_on_a_scoped_host_is_refused():
    decision = authorize("127.0.0.1", 9999, "tcp", [rule("127.0.0.1", ports="8081")])
    assert decision.allowed is False
    # the message distinguishes "this port is not authorized at all" from
    # "this host is not authorized", which is what an operator needs to know
    assert "no scope entry authorizes port 9999/tcp" in decision.reason


def test_unscoped_port_on_a_scoped_hostname_is_refused():
    decision = authorize(
        "app.internal",
        9999,
        "tcp",
        [rule("app.internal", ports="443")],
        addresses=[ip("10.0.0.5")],
    )
    assert decision.allowed is False
    assert "no scope entry authorizes port 9999/tcp" in decision.reason


def test_no_rules_means_no_authorization():
    decision = authorize("127.0.0.1", 8081, "tcp", [])
    assert decision.allowed is False
    assert "no active scope" in decision.reason


def test_authorization_is_port_specific():
    rules = [rule("10.0.0.0/24", kind="cidr", ports="443")]
    assert authorize("10.0.0.5", 443, "tcp", rules).allowed is True
    assert authorize("10.0.0.5", 8443, "tcp", rules).allowed is False


def test_authorization_is_protocol_specific():
    rules = [rule("10.0.0.5", ports="53", protocol="udp")]
    assert authorize("10.0.0.5", 53, "udp", rules).allowed is True
    assert authorize("10.0.0.5", 53, "tcp", rules).allowed is False


def test_public_address_without_authorization_reference_is_refused_at_run_time():
    """The scope may exist, but a public address still needs a citation."""
    unapproved = ScopeRule(
        scope_id=2,
        scope_name="unapproved",
        kind="host",
        value="8.8.8.8",
        ports=parse_ports("443"),
        protocol="tcp",
        has_authorization=False,
    )
    decision = authorize("8.8.8.8", 443, "tcp", [unapproved])
    assert decision.allowed is False
    assert "authorization_ref" in decision.reason


def test_public_address_with_authorization_reference_passes():
    approved = ScopeRule(
        scope_id=3,
        scope_name="approved",
        kind="host",
        value="8.8.8.8",
        ports=parse_ports("443"),
        protocol="tcp",
        has_authorization=True,
    )
    assert authorize("8.8.8.8", 443, "tcp", [approved]).allowed is True


# --------------------------------------------------------- rebinding attacks --


def test_name_rule_cannot_authorize_loopback():
    """A scoped name that has been re-pointed at 127.0.0.1 must not be usable.

    This is the core rebinding defence: a name rule authorizes a *name*, and a
    name can be re-pointed at any moment, so it must never grant access to
    loopback where the platform's own services live.
    """
    name_rule = rule("app.internal", ports="443")
    decision = authorize("app.internal", 443, "tcp", [name_rule], addresses=[ip("127.0.0.1")])
    assert decision.allowed is False
    assert "cannot authorize loopback" in decision.reason


def test_name_rule_authorizes_normal_addresses():
    name_rule = rule("app.internal", ports="443")
    decision = authorize(
        "app.internal", 443, "tcp", [name_rule], addresses=[ipaddress.ip_address("10.1.2.3")]
    )
    assert decision.allowed is True


def test_an_address_rule_does_authorize_loopback_when_the_scope_is_a_lab():
    rules = [rule("127.0.0.1", ports="8081")]
    decision = authorize(
        "127.0.0.1", 8081, "tcp", rules, addresses=[ip("127.0.0.1")]
    )
    assert decision.allowed is True


def test_split_resolution_fails_the_whole_run():
    """One authorized and one unauthorized address is an attack, not a pass."""
    rules = [rule("10.0.0.5", ports="443")]
    decision = authorize(
        "app.internal",
        443,
        "tcp",
        rules,
        addresses=[ipaddress.ip_address("10.0.0.5"), ipaddress.ip_address("10.0.0.99")],
    )
    assert decision.allowed is False
    assert "10.0.0.99" in decision.reason


def test_split_resolution_where_one_address_is_denied_fails_the_run():
    """Even a rule that *names* a denied address cannot rescue it.

    The rule is built by hand because ``validate_entry`` refuses to create one
    for a denied address at all. That refusal is the first layer; this covers
    the second, which is what holds if a rule is ever loaded from somewhere
    that skipped validation.
    """
    forged_rule = ScopeRule(
        scope_id=9,
        scope_name="forged",
        kind="host",
        value="169.254.169.254",
        ports=parse_ports("443"),
        protocol="tcp",
        has_authorization=True,
        is_lab=True,
    )
    decision = authorize(
        "app.internal",
        443,
        "tcp",
        [rule("10.0.0.5", ports="443"), forged_rule],
        addresses=[ip("10.0.0.5"), ip("169.254.169.254")],
    )
    assert decision.allowed is False
    assert "never authorized" in decision.reason


def test_resolution_failure_is_refused_not_ignored():
    decision = authorize("no-such-host.invalid", 443, "tcp", [rule("no-such-host.invalid")])
    assert decision.allowed is False
