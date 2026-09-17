"""The local_baseline engine: sysctls, file modes and sshd settings.

Everything here is exercised through stubs over the module's own observation
helpers (``_observe`` and ``Path``), because a unit test must not be reading
the machine it happens to run on - the live behaviour is covered separately in
test_engine_live.py. The load-bearing property: an observation that could not
be made is a fact with ``confidence = 0.0`` and a null verdict, never a
compliant one.
"""

from __future__ import annotations

import os
import stat as stat_module
from pathlib import Path

import pytest

from app.engines import local_baseline
from app.engines.catalogue import ALLOWED_LOCAL_PATHS, LocalBaselineParams
from app.engines.context import EngineContext, EngineError, TargetView
from app.models.enums import TargetType


def _target(**overrides) -> TargetView:
    values = dict(
        ip="127.0.0.1",
        port=0,
        protocol="",
        hostname="localhost",
        path="/",
        target_type=TargetType.LOCAL,
    )
    values.update(overrides)
    return TargetView(**values)


def _ctx(tmp_path: Path):
    logs: list[tuple[str, str]] = []
    ctx = EngineContext(
        run_id=1,
        timeout_seconds=60,
        max_output_bytes=1_000_000,
        safe_mode=False,
        workdir=tmp_path,
        log=lambda level, message: logs.append((level, message)),
    )
    return ctx, logs


def _stat(mode: int, uid: int = 0, gid: int = 0, *, directory: bool = False):
    kind = stat_module.S_IFDIR if directory else stat_module.S_IFREG
    return os.stat_result((kind | mode, 1, 1, 1, uid, gid, 0, 0, 0, 0))


def _patch_stat(monkeypatch, table):
    """Route ``Path(raw).stat()`` through ``table``; an exception value is
    raised, a missing entry is an OSError (as an unreadable path would be)."""

    class FakePath:
        def __init__(self, raw):
            self.raw = str(raw)

        def __str__(self):
            return self.raw

        def __fspath__(self):
            return self.raw

        def stat(self):
            outcome = table.get(self.raw, OSError(f"stat: {self.raw}: no such file"))
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome

    monkeypatch.setattr(local_baseline, "Path", FakePath)


def _patch_observe(monkeypatch, table):
    def fake_observe(path):
        return table.get(str(path))

    monkeypatch.setattr(local_baseline, "_observe", fake_observe)


def _files_by_key(facts):
    return {f.key: f for f in facts if f.fact_type == "file_mode"}


def _sysctls_by_key(facts):
    return {f.key: f for f in facts if f.fact_type == "sysctl"}


def _stat_table(**overrides):
    """A plausible, compliant machine; overrides replace per-path values."""
    table = {
        "/etc/passwd": _stat(0o644, 0),
        "/etc/shadow": _stat(0o640, 0),
        "/etc/ssh/sshd_config": _stat(0o644, 0),
        "/etc/valtros/valtros.env": _stat(0o640, 0),
        "/var/lib/valtros": _stat(0o750, 1000, directory=True),
        "/var/lib/valtros/evidence": _stat(0o770, 1000, directory=True),
    }
    table.update(overrides)
    return table


# ------------------------------------------------------------------ file modes --


def test_a_mode_inside_the_rule_mask_is_compliant(monkeypatch, tmp_path):
    _patch_stat(monkeypatch, {"/etc/shadow": _stat(0o640, 0)})
    ctx, _ = _ctx(tmp_path)
    facts = local_baseline._file_facts(["/etc/shadow"], ctx)

    fact = _files_by_key(facts)["/etc/shadow"]
    assert fact.value["exists"] is True
    assert fact.value["mode"] == "0640"
    assert fact.value["max_mode"] == "0640"
    assert fact.value["uid"] == 0
    assert fact.value["mask_ok"] is True
    assert fact.value["uid_ok"] is True
    assert fact.value["compliant"] is True
    assert fact.value["observable"] is True
    assert fact.confidence == 1.0


def test_a_stricter_mode_than_the_rule_is_compliant(monkeypatch, tmp_path):
    """A mask is the most permissive mode accepted. 0400 passes a 0640 rule -
    stricter is not a finding."""
    _patch_stat(
        monkeypatch,
        {
            "/etc/shadow": _stat(0o600, 0),  # rule allows up to 0640
            "/etc/passwd": _stat(0o400, 0),  # rule allows up to 0644
        },
    )
    ctx, _ = _ctx(tmp_path)
    facts = _files_by_key(local_baseline._file_facts(["/etc/shadow", "/etc/passwd"], ctx))

    assert facts["/etc/shadow"].value["mask_ok"] is True
    assert facts["/etc/shadow"].value["compliant"] is True
    assert facts["/etc/passwd"].value["mask_ok"] is True
    assert facts["/etc/passwd"].value["compliant"] is True


def test_any_bit_outside_the_rule_mask_is_not_compliant(monkeypatch, tmp_path):
    _patch_stat(
        monkeypatch,
        {
            "/etc/shadow": _stat(0o644, 0),  # world-readable: bit outside 0640
            "/etc/valtros/valtros.env": _stat(0o660, 0),
        },
    )
    ctx, _ = _ctx(tmp_path)
    facts = _files_by_key(
        local_baseline._file_facts(
            ["/etc/shadow", "/etc/valtros/valtros.env"], ctx
        )
    )

    assert facts["/etc/shadow"].value["mask_ok"] is False
    assert facts["/etc/shadow"].value["compliant"] is False
    assert facts["/etc/valtros/valtros.env"].value["mask_ok"] is False


def test_a_wrong_owner_is_not_compliant(monkeypatch, tmp_path):
    _patch_stat(monkeypatch, {"/etc/passwd": _stat(0o644, 1000)})
    ctx, _ = _ctx(tmp_path)
    fact = _files_by_key(local_baseline._file_facts(["/etc/passwd"], ctx))["/etc/passwd"]

    assert fact.value["mode"] == "0644"
    assert fact.value["mask_ok"] is True
    assert fact.value["uid_ok"] is False
    assert fact.value["compliant"] is False, "mode alone must not make it pass"


def test_ownership_not_in_the_rule_is_null_not_false(monkeypatch, tmp_path):
    """The service directories are owned by the worker account; ownership is
    not part of their rule, and None says 'not judged', not 'failed'."""
    _patch_stat(monkeypatch, {"/var/lib/valtros": _stat(0o750, 1000, directory=True)})
    ctx, _ = _ctx(tmp_path)
    fact = _files_by_key(local_baseline._file_facts(["/var/lib/valtros"], ctx))[
        "/var/lib/valtros"
    ]

    assert fact.value["uid_ok"] is None
    assert fact.value["expected_uid"] is None
    assert fact.value["compliant"] is True


def test_setgid_and_sticky_are_outside_the_mask_comparison(monkeypatch, tmp_path):
    """setgid on a shared directory is a mechanism, not a relaxation of who
    may read or write."""
    _patch_stat(
        monkeypatch,
        {
            "/var/lib/valtros": _stat(0o2750, 1000, directory=True),
            "/var/lib/valtros/evidence": _stat(0o1770, 1000, directory=True),
        },
    )
    ctx, _ = _ctx(tmp_path)
    facts = _files_by_key(
        local_baseline._file_facts(
            ["/var/lib/valtros", "/var/lib/valtros/evidence"], ctx
        )
    )

    assert facts["/var/lib/valtros"].value["setgid"] is True
    assert facts["/var/lib/valtros"].value["mask_ok"] is True
    assert facts["/var/lib/valtros"].value["compliant"] is True
    assert facts["/var/lib/valtros/evidence"].value["sticky"] is True
    assert facts["/var/lib/valtros/evidence"].value["compliant"] is True


def test_an_unreadable_path_is_unobserved_not_compliant(monkeypatch, tmp_path):
    _patch_stat(monkeypatch, {"/etc/shadow": PermissionError("permission denied")})
    ctx, _ = _ctx(tmp_path)
    fact = _files_by_key(local_baseline._file_facts(["/etc/shadow"], ctx))["/etc/shadow"]

    assert fact.confidence == 0.0
    assert fact.value["exists"] is None
    assert fact.value["mode"] is None
    assert fact.value["mask_ok"] is None
    assert fact.value["uid_ok"] is None
    assert fact.value["compliant"] is None
    assert fact.value["observable"] is False
    assert "could not be inspected" in fact.detail


def test_a_nonexistent_path_is_unobserved_not_missing(monkeypatch, tmp_path):
    _patch_stat(monkeypatch, {})  # every path raises
    ctx, _ = _ctx(tmp_path)
    fact = _files_by_key(local_baseline._file_facts(["/etc/shadow"], ctx))["/etc/shadow"]
    assert fact.confidence == 0.0
    assert fact.value["exists"] is None
    assert fact.value["compliant"] is None


# -------------------------------------------------------------------- sysctls --


def test_a_matching_sysctl_is_compliant(monkeypatch, tmp_path):
    _patch_observe(
        monkeypatch,
        {"/proc/sys/kernel/randomize_va_space": "2", "/proc/sys/net/ipv4/tcp_syncookies": "1"},
    )
    ctx, _ = _ctx(tmp_path)
    facts = _sysctls_by_key(
        local_baseline._sysctl_facts(
            ["kernel.randomize_va_space", "net.ipv4.tcp_syncookies"], ctx
        )
    )

    aslr = facts["kernel.randomize_va_space"]
    assert aslr.value["value"] == "2"
    assert aslr.value["expected"] == "2"
    assert aslr.value["compliant"] is True
    assert aslr.value["observable"] is True
    assert aslr.confidence == 1.0


def test_a_mismatched_sysctl_is_not_compliant(monkeypatch, tmp_path):
    _patch_observe(monkeypatch, {"/proc/sys/net/ipv4/tcp_syncookies": "0"})
    ctx, _ = _ctx(tmp_path)
    fact = _sysctls_by_key(local_baseline._sysctl_facts(["net.ipv4.tcp_syncookies"], ctx))[
        "net.ipv4.tcp_syncookies"
    ]
    assert fact.value["value"] == "0"
    assert fact.value["compliant"] is False


def test_an_unreadable_sysctl_is_unobserved_not_compliant(monkeypatch, tmp_path):
    _patch_observe(monkeypatch, {})
    ctx, _ = _ctx(tmp_path)
    fact = _sysctls_by_key(local_baseline._sysctl_facts(["kernel.yama.ptrace_scope"], ctx))[
        "kernel.yama.ptrace_scope"
    ]

    assert fact.confidence == 0.0
    assert fact.value["value"] is None
    assert fact.value["compliant"] is None
    assert fact.value["observable"] is False
    assert "not readable" in fact.detail


def test_a_sysctl_outside_the_baseline_is_skipped_with_a_warning(monkeypatch, tmp_path):
    ctx, logs = _ctx(tmp_path)
    facts = local_baseline._sysctl_facts(["kernel.not.in.the.baseline"], ctx)
    assert facts == []
    assert any("not in the baseline" in message for _, message in logs)


# ---------------------------------------------------------------- sshd_config --


def _sshd_facts(monkeypatch, tmp_path, content: str):
    _patch_observe(monkeypatch, {"/etc/ssh/sshd_config": content})
    ctx, _ = _ctx(tmp_path)
    facts = [f for f in local_baseline._sshd_facts(ctx) if f.fact_type == "sshd_setting"]
    return {f.key: f for f in facts}


def test_sshd_first_occurrence_wins_and_comments_are_ignored(monkeypatch, tmp_path):
    """sshd uses the first occurrence of a keyword; taking the last would
    describe a configuration sshd ignores."""
    facts = _sshd_facts(
        monkeypatch,
        tmp_path,
        "# OpenSSH lab config\n"
        "PermitRootLogin yes\n"
        "PermitRootLogin no\n"
        "PasswordAuthentication YES\n"
        "MaxAuthTries 2 # two attempts\n"
        "PubkeyAuthentication yes\n",
    )

    assert facts["permitrootlogin"].value["value"] == "yes"
    assert facts["permitrootlogin"].value["compliant"] is False
    # The raw casing is preserved, the comparison is case-insensitive: the
    # baseline wants "no" for PasswordAuthentication, so YES is a finding.
    assert facts["passwordauthentication"].value["value"] == "YES"
    assert facts["passwordauthentication"].value["compliant"] is False
    assert facts["maxauthtries"].value["value"] == "2"
    assert facts["maxauthtries"].value["comparison"] == "lte"
    assert facts["maxauthtries"].value["compliant"] is True
    assert facts["pubkeyauthentication"].value["compliant"] is True


def test_an_unset_sshd_keyword_is_null_not_false(monkeypatch, tmp_path):
    facts = _sshd_facts(monkeypatch, tmp_path, "PermitRootLogin no\n")

    unset = facts["x11forwarding"]
    assert unset.value["value"] is None
    assert unset.value["compliant"] is None
    assert unset.value["reason"] == "not set in sshd_config; the sshd default applies"
    assert unset.confidence == 1.0


def test_sshd_keywords_may_contain_digits(monkeypatch, tmp_path):
    """Regression: a keyword pattern of letters only skipped X11Forwarding,
    reporting a directive that is right there in the file as unset."""
    facts = _sshd_facts(monkeypatch, tmp_path, "X11Forwarding yes\n")

    assert facts["x11forwarding"].value["value"] == "yes"
    assert facts["x11forwarding"].value["compliant"] is False


def test_included_files_are_read_in_the_order_they_appear(tmp_path):
    (tmp_path / "dropins").mkdir()
    (tmp_path / "dropins" / "10-hardening.conf").write_text("PermitRootLogin no\n")
    (tmp_path / "sshd_config").write_text(
        "Include dropins/*.conf\nPermitRootLogin yes\n"
    )

    found: dict[str, tuple[str, str]] = {}
    local_baseline._sshd_keywords(
        tmp_path / "sshd_config", found, set(), base=tmp_path
    )

    # sshd keeps the first occurrence, and the drop-in is included first.
    assert found["permitrootlogin"][0] == "no"
    assert found["permitrootlogin"][1].endswith("10-hardening.conf")


def test_an_include_cycle_terminates(tmp_path):
    (tmp_path / "sshd_config").write_text("Include sshd_config\n")

    found: dict[str, tuple[str, str]] = {}
    local_baseline._sshd_keywords(
        tmp_path / "sshd_config", found, set(), base=tmp_path
    )

    assert found == {}


def test_max_auth_tries_boundary_and_unreadable_value(monkeypatch, tmp_path):
    facts = _sshd_facts(monkeypatch, tmp_path, "MaxAuthTries 4\n")
    assert facts["maxauthtries"].value["compliant"] is True

    facts = _sshd_facts(monkeypatch, tmp_path, "MaxAuthTries 5\n")
    assert facts["maxauthtries"].value["compliant"] is False

    # A value that cannot be read as a number is null, not a pass.
    facts = _sshd_facts(monkeypatch, tmp_path, "MaxAuthTries lots\n")
    assert facts["maxauthtries"].value["value"] == "lots"
    assert facts["maxauthtries"].value["compliant"] is None


def test_an_unreadable_sshd_config_produces_no_facts(monkeypatch, tmp_path):
    _patch_observe(monkeypatch, {})
    ctx, logs = _ctx(tmp_path)
    assert local_baseline._sshd_facts(ctx) == []
    assert any("not readable" in message for _, message in logs)


# ------------------------------------------------------------------------ run --


def test_run_reports_the_kernel_version_and_every_requested_check(monkeypatch, tmp_path):
    _patch_stat(monkeypatch, _stat_table())
    _patch_observe(
        monkeypatch,
        {
            "/proc/sys/kernel/randomize_va_space": "2",
            "/proc/sys/net/ipv4/tcp_syncookies": "1",
            "/proc/sys/kernel/osrelease": "6.1.0-kali-amd64",
            "/etc/ssh/sshd_config": "PermitRootLogin no\n",
        },
    )
    ctx, _ = _ctx(tmp_path)
    result = local_baseline.run(_target(), LocalBaselineParams(), ctx)

    fact_types = {f.fact_type for f in result.facts}
    assert fact_types == {"sysctl", "file_mode", "sshd_setting"}
    assert result.tool_versions["kernel"] == "6.1.0-kali-amd64"
    assert all(f.subject == "localhost" for f in result.facts)


def test_run_with_nothing_observable_is_an_error_not_a_pass(monkeypatch, tmp_path):
    """An engine that could not observe anything must mark the run error;
    'no facts' must never look like a control that held."""
    _patch_observe(monkeypatch, {})
    ctx, _ = _ctx(tmp_path)
    with pytest.raises(EngineError, match="no local baseline facts were produced"):
        local_baseline.run(_target(), LocalBaselineParams(checks=["sshd_config"]), ctx)


def test_run_with_an_unreadable_sysctl_still_returns_an_unobserved_fact(monkeypatch, tmp_path):
    _patch_observe(monkeypatch, {})
    ctx, _ = _ctx(tmp_path)
    result = local_baseline.run(
        _target(), LocalBaselineParams(checks=["sysctls"], sysctl_keys=["kernel.dmesg_restrict"]), ctx
    )

    assert len(result.facts) == 1
    fact = result.facts[0]
    assert fact.confidence == 0.0
    assert fact.value["compliant"] is None
    assert fact.value["observable"] is False


def test_run_only_performs_the_requested_checks(monkeypatch, tmp_path):
    _patch_stat(monkeypatch, _stat_table())
    _patch_observe(monkeypatch, {"/proc/sys/kernel/randomize_va_space": "2"})
    ctx, _ = _ctx(tmp_path)
    result = local_baseline.run(
        _target(),
        LocalBaselineParams(checks=["sysctls"], sysctl_keys=["kernel.randomize_va_space"]),
        ctx,
    )
    assert {f.fact_type for f in result.facts} == {"sysctl"}
