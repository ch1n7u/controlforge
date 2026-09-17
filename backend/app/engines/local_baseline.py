"""Read-only inspection of the machine Valtros runs on.

Touches no network at all. This engine exists because the platform's own host is
a target like any other: if the box that does the validating is not hardened,
every result it produces is less trustworthy.

Everything read here comes from a fixed allowlist of keys and paths compiled
into the engine, so the parameters choose *from* that list and can never name a
new file to read.

An unreadable path is reported as a fact with ``confidence = 0.0`` and a reason,
rather than being silently skipped or reported as compliant. That is what makes
the assertion over it come back INCONCLUSIVE instead of a false pass.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from app.engines.catalogue import ALLOWED_LOCAL_PATHS, ALLOWED_SYSCTLS, LOCAL_BASELINE_CHECKS
from app.engines.context import (
    EngineContext,
    EngineError,
    EngineResult,
    FactDraft,
    TargetView,
)

# An observation that could not be made. The evaluator maps a selection made
# only of these to INCONCLUSIVE rather than letting a placeholder value decide.
UNOBSERVED = 0.0

PROC_SYS = Path("/proc/sys")

# What each sysctl should be, and why - the "why" ends up in the finding.
SYSCTL_BASELINE: dict[str, tuple[str, str]] = {
    "kernel.randomize_va_space": ("2", "full address space randomisation"),
    "net.ipv4.conf.all.rp_filter": ("1", "reverse path filtering on"),
    "net.ipv4.conf.all.accept_redirects": ("0", "ICMP redirects refused"),
    "net.ipv4.conf.all.accept_source_route": ("0", "source routing refused"),
    "net.ipv4.conf.all.send_redirects": ("0", "does not send ICMP redirects"),
    "net.ipv4.conf.all.log_martians": ("1", "martian packets logged"),
    "net.ipv4.tcp_syncookies": ("1", "SYN cookies enabled"),
    "net.ipv4.icmp_echo_ignore_broadcasts": ("1", "smurf amplification refused"),
    "net.ipv6.conf.all.accept_redirects": ("0", "IPv6 redirects refused"),
    "net.ipv6.conf.all.accept_ra": ("0", "IPv6 router advertisements refused"),
    "fs.protected_hardlinks": ("1", "hardlinks to files you do not own are blocked"),
    "fs.protected_symlinks": ("1", "symlinks followed only in sticky world-writable dirs"),
    "fs.suid_dumpable": ("0", "setuid processes do not dump core"),
    "kernel.dmesg_restrict": ("1", "kernel log not readable by unprivileged users"),
    "kernel.kptr_restrict": ("1", "kernel pointers hidden from unprivileged users"),
    "kernel.yama.ptrace_scope": ("1", "ptrace restricted to descendants"),
}

# ``mask`` is the most permissive set of permission bits accepted; any bit
# outside it is a finding. Comparing masks rather than exact modes means 0400
# passes a 0440 rule, which is the right answer - stricter is not a finding.
# The setgid and sticky bits are deliberately outside this comparison: setgid on
# a shared directory is a mechanism (new files inherit the group), not a
# relaxation of who may read or write.
@dataclass(frozen=True, slots=True)
class FileRule:
    mask: int
    uid: int | None
    why: str


FILE_BASELINE: dict[str, FileRule] = {
    "/etc/passwd": FileRule(0o644, 0, "world-readable account list"),
    "/etc/shadow": FileRule(0o640, 0, "password hashes readable only by root and shadow"),
    "/etc/ssh/sshd_config": FileRule(0o644, 0, "sshd configuration not world-writable"),
    "/etc/valtros/valtros.env": FileRule(
        0o640, 0, "Valtros secrets readable only by root and the service group"
    ),
    # The state directories are owned by the service account rather than root
    # because the worker writes there; ownership is not the control, being
    # inaccessible to every other local user is.
    "/var/lib/valtros": FileRule(
        0o750, None, "service state directory not readable by other local users"
    ),
    "/var/lib/valtros/evidence": FileRule(
        0o770,
        None,
        "evidence store writable by the worker but not world-accessible",
    ),
}

SSHD_BASELINE: dict[str, tuple[str, str, str]] = {
    "permitrootlogin": ("no", "eq", "root cannot log in over SSH"),
    "passwordauthentication": ("no", "eq", "key-based authentication only"),
    "permitemptypasswords": ("no", "eq", "no account with an empty password"),
    "x11forwarding": ("no", "eq", "X11 forwarding disabled"),
    "maxauthtries": ("4", "lte", "limited authentication attempts"),
    "pubkeyauthentication": ("yes", "eq", "public key authentication available"),
}

_SSHD_LINE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9]*)\s+(.+?)\s*$")

_SSHD_BASE = Path("/etc/ssh")


def _sshd_keywords(
    path: Path,
    found: dict[str, tuple[str, str]],
    seen: set[str],
    *,
    base: Path = _SSHD_BASE,
) -> None:
    """Collect keyword -> (value, source file) in sshd's own precedence order.

    sshd takes the first occurrence of a keyword, so the first match wins here
    too - taking the last would describe a configuration sshd ignores. An
    ``Include`` is expanded where it appears, for the same reason: a drop-in
    listed before a keyword overrides it, and Debian-family hosts keep most of
    the effective settings in ``/etc/ssh/sshd_config.d``.
    """
    name = str(path)
    if name in seen:
        return
    seen.add(name)
    content = _observe(path)
    if content is None:
        return
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _SSHD_LINE.match(stripped)
        if not match:
            continue
        keyword = match.group(1).lower()
        value = match.group(2).split("#")[0].strip()
        if keyword == "include":
            # sshd resolves relative Include paths against /etc/ssh, not
            # against the including file's directory.
            pattern = value if value.startswith("/") else str(base / value)
            for included in sorted(Path("/").glob(pattern.lstrip("/"))):
                if included.is_file():
                    _sshd_keywords(included, found, seen, base=base)
            continue
        found.setdefault(keyword, (value, name))


def _observe(path: Path) -> str | None:
    """Read a small file, or None if it is not visible to this process."""
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None


def _sysctl_facts(keys: list[str], ctx: EngineContext) -> list[FactDraft]:
    facts: list[FactDraft] = []
    for key in keys:
        if key not in SYSCTL_BASELINE:
            ctx.emit("warning", f"sysctl {key!r} is not in the baseline; skipped")
            continue
        expected, why = SYSCTL_BASELINE[key]
        observed = _observe(PROC_SYS / key.replace(".", "/"))
        if observed is None:
            facts.append(
                FactDraft(
                    fact_type="sysctl",
                    subject="localhost",
                    key=key,
                    confidence=UNOBSERVED,
                    detail=f"{key} is not readable from this process",
                    value={
                        "name": key,
                        "value": None,
                        "expected": expected,
                        "why": why,
                        "compliant": None,
                        "observable": False,
                    },
                )
            )
            continue
        facts.append(
            FactDraft(
                fact_type="sysctl",
                subject="localhost",
                key=key,
                value={
                    "name": key,
                    "value": observed,
                    "expected": expected,
                    "why": why,
                    "compliant": observed == expected,
                    "observable": True,
                },
            )
        )
    return facts


def _file_facts(paths: list[str], ctx: EngineContext) -> list[FactDraft]:
    facts: list[FactDraft] = []
    for raw in paths:
        if raw not in ALLOWED_LOCAL_PATHS:
            ctx.emit("warning", f"{raw!r} is not in the allowlist; skipped")
            continue
        rule = FILE_BASELINE.get(raw)
        if rule is None:
            continue
        path = Path(raw)
        try:
            stat = path.stat()
        except (OSError, PermissionError) as exc:
            facts.append(
                FactDraft(
                    fact_type="file_mode",
                    subject="localhost",
                    key=raw,
                    confidence=UNOBSERVED,
                    detail=f"{raw} could not be inspected: {exc}",
                    value={
                        "path": raw,
                        "exists": None,
                        "mode": None,
                        "uid": None,
                        "gid": None,
                        "mask_ok": None,
                        "uid_ok": None,
                        "compliant": None,
                        "observable": False,
                    },
                )
            )
            continue

        mode = stat.st_mode & 0o7777
        permissions = mode & 0o777
        mask_ok = (permissions & ~rule.mask) == 0
        # None means ownership is not part of the rule, not that it failed to
        # match: the two are different answers and an assertion may want to tell
        # them apart.
        uid_ok = None if rule.uid is None else stat.st_uid == rule.uid
        facts.append(
            FactDraft(
                fact_type="file_mode",
                subject="localhost",
                key=raw,
                value={
                    "path": raw,
                    "exists": True,
                    "mode": f"{mode:04o}",
                    "mode_bits": mode,
                    "permissions": f"{permissions:04o}",
                    "max_mode": f"{rule.mask:04o}",
                    "setgid": bool(mode & 0o2000),
                    "sticky": bool(mode & 0o1000),
                    "uid": stat.st_uid,
                    "gid": stat.st_gid,
                    "expected_uid": rule.uid,
                    "mask_ok": mask_ok,
                    "uid_ok": uid_ok,
                    "compliant": bool(mask_ok and uid_ok is not False),
                    "why": rule.why,
                    "observable": True,
                },
            )
        )
    return facts


def _sshd_facts(ctx: EngineContext) -> list[FactDraft]:
    path = Path("/etc/ssh/sshd_config")
    if _observe(path) is None:
        ctx.emit("info", "sshd_config is not readable; no sshd facts emitted")
        return []

    effective: dict[str, tuple[str, str]] = {}
    _sshd_keywords(path, effective, set())

    facts: list[FactDraft] = []
    for keyword, (expected, comparison, why) in SSHD_BASELINE.items():
        observed = effective.get(keyword)
        value, source = observed if observed else (None, str(path))
        if value is None:
            compliant: bool | None = None
            reason = "not set in sshd_config; the sshd default applies"
        else:
            lowered = value.lower()
            if comparison == "eq":
                compliant = lowered == expected
            else:  # "lte"
                try:
                    compliant = int(lowered) <= int(expected)
                except ValueError:
                    compliant = None
            reason = why
        facts.append(
            FactDraft(
                fact_type="sshd_setting",
                subject="localhost",
                key=keyword,
                value={
                    "name": keyword,
                    "value": value,
                    "expected": expected,
                    "comparison": comparison,
                    "why": why,
                    "compliant": compliant,
                    "reason": reason,
                    "source": source,
                },
            )
        )
    return facts


def run(target: TargetView, params, ctx: EngineContext) -> EngineResult:
    result = EngineResult()
    checks = list(params.checks)

    if "sysctls" in checks:
        keys = [k for k in params.sysctl_keys if k in ALLOWED_SYSCTLS]
        result.facts.extend(_sysctl_facts(keys, ctx))
    if "file_modes" in checks:
        result.facts.extend(_file_facts(list(params.paths), ctx))
    if "sshd_config" in checks:
        result.facts.extend(_sshd_facts(ctx))

    # The version of the kernel is part of the baseline: a sysctl's meaning and
    # a default can both change between releases.
    release = _observe(Path("/proc/sys/kernel/osrelease"))
    if release:
        result.tool_versions["kernel"] = release

    if not result.facts:
        raise EngineError(
            "no local baseline facts were produced; none of the requested keys or "
            "paths were observable from this process"
        )
    return result
