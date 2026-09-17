"""What each engine can do, declared rather than discovered.

The catalogue is the contract between three consumers that must agree:

* the API, which refuses a validation test whose assertion references a fact
  type its engine can never emit (such a test could only ever come back
  INCONCLUSIVE, so it is a mistake worth catching while a human is typing);
* the runner, which uses ``params`` to validate requested parameters and build
  an argv list - never a shell string;
* the UI, which renders the available engines and their options.

Engines are declared here; their execution lives in the sibling modules and is
wired up in :mod:`app.engines.runtime`. Keeping the declaration separate means
the API layer never imports a module that shells out to a security tool.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.enums import TargetType

# --------------------------------------------------------------------- params --


class StrictParams(BaseModel):
    """Engine parameters are rejected, never coerced.

    A typo in a parameter name would otherwise be silently dropped, and the
    engine would run with defaults the operator never chose - on a security
    test that difference is the whole result.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)


class NmapParams(StrictParams):
    """TCP connect scan over a port set that must sit inside the scope."""

    ports: str = Field(
        min_length=1,
        max_length=512,
        description="Port specification, e.g. '443' or '80,443,8000-8010'.",
    )
    service_detection: bool = True
    max_rate: int | None = Field(
        default=None, ge=1, le=1000, description="Packets per second cap."
    )

    @field_validator("ports")
    @classmethod
    def _parseable(cls, value: str) -> str:
        from app.scope.ports import PortSpecError, parse_ports

        try:
            parse_ports(value)
        except PortSpecError as exc:
            raise ValueError(str(exc)) from exc
        return value


class TlsConfigParams(StrictParams):
    """What testssl is asked for.

    There is deliberately no severity filter here. testssl's ``--severity`` flag
    drops lower-graded entries from its JSON, so a run configured with a floor
    would leave an assertion like "no LOW finding exists" with nothing to look
    at, and it would pass. Narrowing by severity belongs in the assertion, which
    still sees every entry the tool produced.
    """

    check_vulnerabilities: bool = Field(
        default=False,
        description=(
            "Include the slower vulnerability sweep. The well-known checks "
            "(Heartbleed, CCS injection, ROBOT, FREAK, LOGJAM and others) run "
            "either way."
        ),
    )
    starttls: str | None = Field(
        default=None,
        max_length=32,
        pattern=r"^(ftp|lmtp|smtp|pop3|imap|xmpp|xmpp-server|telnet|ldap|postgres|mysql)$",
        description="Test a STARTTLS-wrapped protocol instead of a direct TLS port.",
    )
    max_wait_seconds: int = Field(
        default=240,
        ge=30,
        le=900,
        description="Ceiling on the sweep, below the run's own timeout.",
    )


class HttpHeadersParams(StrictParams):
    path: str = Field(default="/", max_length=255)
    method: str = Field(default="GET", pattern=r"^(GET|HEAD)$")
    follow_redirects: bool = Field(
        default=False,
        description="Follow one redirect, and only when it stays on the same host and port.",
    )


class HttpExposureParams(StrictParams):
    profile: str = Field(
        default="minimal",
        pattern=r"^(minimal|web|api|spring|vcs|dirlist)$",
        description="Which curated path list to probe.",
    )
    extra_paths: list[str] = Field(default_factory=list, max_length=32)
    method: str = Field(default="GET", pattern=r"^(GET|HEAD)$")

    @field_validator("extra_paths")
    @classmethod
    def _safe_paths(cls, value: list[str]) -> list[str]:
        return [_clean_path(path) for path in value]


class NucleiParams(StrictParams):
    template_tags: list[str] = Field(
        default_factory=lambda: ["headers", "misconfiguration", "exposure"],
        max_length=16,
    )
    severities: list[str] = Field(
        default_factory=lambda: ["low", "medium", "high", "critical"], max_length=5
    )
    rate_limit: int = Field(default=25, ge=1, le=150)

    @field_validator("template_tags")
    @classmethod
    def _allowed_tags(cls, value: list[str]) -> list[str]:
        unknown = [tag for tag in value if tag not in NUCLEI_TEMPLATE_TAGS]
        if unknown:
            raise ValueError(
                "unsupported template tags: " + ", ".join(sorted(unknown))
            )
        return value

    @field_validator("severities")
    @classmethod
    def _allowed_severities(cls, value: list[str]) -> list[str]:
        unknown = [s for s in value if s not in NUCLEI_SEVERITIES]
        if unknown:
            raise ValueError("unsupported severities: " + ", ".join(sorted(unknown)))
        return value


class LocalBaselineParams(StrictParams):
    """Read-only inspection of the machine Valtros itself runs on."""

    checks: list[str] = Field(
        default_factory=lambda: ["sysctls", "file_modes", "sshd_config"],
        min_length=1,
        max_length=8,
    )
    sysctl_keys: list[str] = Field(
        default_factory=lambda: list(ALLOWED_SYSCTLS), max_length=64
    )
    paths: list[str] = Field(
        default_factory=lambda: list(ALLOWED_LOCAL_PATHS), max_length=64
    )

    @field_validator("checks")
    @classmethod
    def _allowed_checks(cls, value: list[str]) -> list[str]:
        unknown = [c for c in value if c not in LOCAL_BASELINE_CHECKS]
        if unknown:
            raise ValueError("unsupported checks: " + ", ".join(sorted(unknown)))
        return value

    @field_validator("sysctl_keys")
    @classmethod
    def _allowed_sysctls(cls, value: list[str]) -> list[str]:
        unknown = [k for k in value if k not in ALLOWED_SYSCTLS]
        if unknown:
            raise ValueError("unsupported sysctl keys: " + ", ".join(sorted(unknown)))
        return value

    @field_validator("paths")
    @classmethod
    def _allowed_paths(cls, value: list[str]) -> list[str]:
        unknown = [p for p in value if p not in ALLOWED_LOCAL_PATHS]
        if unknown:
            raise ValueError("unsupported paths: " + ", ".join(sorted(unknown)))
        return value


_PATH_RE = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,120}$")


def _clean_path(path: str) -> str:
    """Keep extra exposure paths boring: absolute, no query, no traversal.

    The engine only ever requests a path on an already-authorized host, so this
    is not the primary control - it is there to stop a path like ``/../../``
    from being normalised by a client into something nobody asked for.
    """
    path = path.strip()
    if not _PATH_RE.match(path) or ".." in path or "//" in path:
        raise ValueError(f"{path!r} is not an acceptable URL path")
    return path


# ------------------------------------------------------- engine-specific data --

NUCLEI_TEMPLATE_TAGS = (
    "headers",
    "misconfiguration",
    "exposure",
    "ssl",
    "tech",
    "http",
    "cors",
    "info",
)

NUCLEI_SEVERITIES = ("info", "low", "medium", "high", "critical")

LOCAL_BASELINE_CHECKS = ("sysctls", "file_modes", "sshd_config")

ALLOWED_SYSCTLS = (
    "kernel.randomize_va_space",
    "net.ipv4.conf.all.rp_filter",
    "net.ipv4.conf.all.accept_redirects",
    "net.ipv4.conf.all.accept_source_route",
    "net.ipv4.conf.all.send_redirects",
    "net.ipv4.conf.all.log_martians",
    "net.ipv4.tcp_syncookies",
    "net.ipv4.icmp_echo_ignore_broadcasts",
    "net.ipv6.conf.all.accept_redirects",
    "net.ipv6.conf.all.accept_ra",
    "fs.protected_hardlinks",
    "fs.protected_symlinks",
    "fs.suid_dumpable",
    "kernel.dmesg_restrict",
    "kernel.kptr_restrict",
    "kernel.yama.ptrace_scope",
)

ALLOWED_LOCAL_PATHS = (
    "/etc/passwd",
    "/etc/shadow",
    "/etc/ssh/sshd_config",
    "/etc/valtros/valtros.env",
    "/var/lib/valtros",
    "/var/lib/valtros/evidence",
)

# Curated exposure paths. Each is a well-known location that either leaks
# credentials, leaks source, or exposes an administrative surface. Probing is a
# plain GET on an authorized host; nothing here is destructive.
EXPOSURE_PATHS: dict[str, tuple[str, ...]] = {
    "minimal": (
        "/.env",
        "/.git/HEAD",
        "/server-status",
        "/robots.txt",
    ),
    "web": (
        "/.env",
        "/.git/HEAD",
        "/.git/config",
        "/.svn/entries",
        "/.DS_Store",
        "/server-status",
        "/phpinfo.php",
        "/backup.zip",
        "/wp-config.php.bak",
        "/robots.txt",
        "/sitemap.xml",
    ),
    "api": (
        "/.env",
        "/swagger.json",
        "/openapi.json",
        "/api/swagger.json",
        "/actuator",
        "/actuator/env",
        "/actuator/health",
        "/metrics",
        "/debug",
        "/api/v1/users",
    ),
    "spring": (
        "/actuator",
        "/actuator/env",
        "/actuator/beans",
        "/actuator/heapdump",
        "/actuator/mappings",
        "/jolokia/list",
        "/env",
    ),
    "vcs": (
        "/.git/HEAD",
        "/.git/config",
        "/.git/logs/HEAD",
        "/.svn/entries",
        "/.hg/store",
        "/.bzr/README",
    ),
    "dirlist": (
        "/files/",
        "/backup/",
        "/backups/",
        "/uploads/",
        "/data/",
        "/logs/",
        "/static/",
        "/assets/",
        "/images/",
        "/admin/",
        "/.git/",
    ),
}

# A directory path counts as exposed when the server hands back a listing
# rather than refusing or redirecting. Matched case-insensitively.
DIRECTORY_LISTING_MARKERS = (
    "<title>index of",
    "to parent directory",
    "directory listing for",
    "<h1>index of",
)

# A path only counts as exposed if the response actually looks like the thing
# it is named after. Without this, a 200 from a catch-all handler would be
# reported as a leak, and the whole findings list would lose credibility.
EXPOSURE_MARKERS: dict[str, tuple[str, ...]] = {
    "/.git/HEAD": ("ref: refs/",),
    "/.git/config": ("[core]", "repositoryformatversion"),
    "/.git/logs/HEAD": ("commit ",),
    "/.svn/entries": ("dir", "svn"),
    "/.hg/store": ("",),
    "/.bzr/README": ("bazaar", "bzr"),
    "/.env": ("=",),
    "/.DS_Store": ("Bud1",),
    "/server-status": ("Apache Server Status", "Server Status"),
    "/phpinfo.php": ("phpinfo()", "PHP Version"),
    "/actuator": ('"_links"', "actuator"),
    "/actuator/env": ('"propertySources"',),
    "/actuator/beans": ('"beans"',),
    "/actuator/heapdump": ("JAVA PROFILE",),
    "/actuator/mappings": ('"contexts"', '"mappings"'),
    "/jolokia/list": ('"value"',),
    "/swagger.json": ('"swagger"', '"openapi"'),
    "/openapi.json": ('"openapi"', '"swagger"'),
    "/api/swagger.json": ('"swagger"', '"openapi"'),
    "/wp-config.php.bak": ("DB_NAME", "DB_PASSWORD"),
    "/backup.zip": ("PK\x03\x04",),
}


# ---------------------------------------------------------------- the catalog --


@dataclass(frozen=True, slots=True)
class EngineSpec:
    """Everything the rest of the platform needs to know about an engine."""

    id: str
    title: str
    description: str
    params: type[StrictParams]
    fact_types: tuple[str, ...]
    target_types: tuple[TargetType, ...]
    default_timeout: int
    mutating: bool = False
    internal: bool = False
    notes: str = ""

    def describe(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "fact_types": list(self.fact_types),
            "target_types": [t.value for t in self.target_types],
            "default_timeout": self.default_timeout,
            "mutating": self.mutating,
            "internal": self.internal,
            "notes": self.notes,
            "params_schema": self.params.model_json_schema(),
        }


ENGINE_SPECS: tuple[EngineSpec, ...] = (
    EngineSpec(
        id="nmap",
        title="Port and service inventory",
        description=(
            "TCP connect scan over an authorized port set, with optional service "
            "and version detection. Emits one port_state fact per probed port."
        ),
        params=NmapParams,
        fact_types=("port_state", "host_state"),
        target_types=(
            TargetType.HOST,
            TargetType.WEBAPP,
            TargetType.API,
            TargetType.TLS,
            TargetType.SSH,
        ),
        default_timeout=300,
        notes=(
            "Runs unprivileged, so this is a connect scan (-sT) - no SYN scan, "
            "no raw sockets, no masscan. Host discovery is skipped because the "
            "target is already pinned to an address."
        ),
    ),
    EngineSpec(
        id="tls_config",
        title="TLS configuration",
        description=(
            "Protocol versions, cipher suites, certificate posture and optional "
            "protocol-level vulnerability checks."
        ),
        params=TlsConfigParams,
        fact_types=(
            "tls_protocol",
            "tls_cipher",
            "tls_certificate",
            "tls_vulnerability",
        ),
        target_types=(TargetType.TLS, TargetType.WEBAPP, TargetType.API, TargetType.HOST),
        default_timeout=420,
        notes=(
            "testssl.sh with JSON output, parsed into facts. The connection is "
            "made to the pinned address with --ip and DNS is switched off "
            "entirely, so the tool cannot resolve its way out of scope; the "
            "hostname is still supplied so SNI and certificate checks are "
            "correct. The raw JSON is kept as evidence."
        ),
    ),
    EngineSpec(
        id="http_headers",
        title="HTTP response and security headers",
        description=(
            "One request to the target, emitting the response line, every "
            "response header and every cookie flag."
        ),
        params=HttpHeadersParams,
        fact_types=("http_response", "http_header", "http_cookie"),
        target_types=(TargetType.WEBAPP, TargetType.API, TargetType.HOST),
        default_timeout=60,
        notes=(
            "Pure Python. The request is sent to a pinned IP with the hostname "
            "supplied explicitly as Host and SNI. Redirects are never followed "
            "to a different host or port."
        ),
    ),
    EngineSpec(
        id="http_exposure",
        title="Sensitive path exposure",
        description=(
            "Probes a curated list of well-known sensitive paths and reports the "
            "ones that return content matching that path's signature."
        ),
        params=HttpExposureParams,
        fact_types=("path_exposed",),
        target_types=(TargetType.WEBAPP, TargetType.API),
        default_timeout=180,
        notes=(
            "Read-only GET/HEAD requests. A path is only reported as exposed "
            "when the response body matches the expected marker for that path, "
            "so a catch-all handler does not produce false findings."
        ),
    ),
    EngineSpec(
        id="nuclei",
        title="Template-based checks",
        description=(
            "Runs Nuclei restricted to non-intrusive template classes and "
            "converts each match into a nuclei_finding fact."
        ),
        params=NucleiParams,
        fact_types=("nuclei_finding",),
        target_types=(TargetType.WEBAPP, TargetType.API, TargetType.HOST),
        default_timeout=600,
        notes=(
            "Restricted to HTTP templates (-pt http), which excludes the file, "
            "code and javascript template protocols along with dns and the rest. "
            "Fuzzing, brute-force, intrusive and denial-of-service template "
            "classes are never enabled. Interactsh is off (-ni) and template "
            "auto-update is disabled (-duc), so nothing reaches out beyond the "
            "authorized target. Findings stream to stdout as JSONL, so a "
            "cancelled run keeps what it had already found."
        ),
    ),
    EngineSpec(
        id="local_baseline",
        title="Local host baseline",
        description=(
            "Read-only inspection of this machine: kernel sysctls, file "
            "permissions and sshd configuration."
        ),
        params=LocalBaselineParams,
        fact_types=("sysctl", "file_mode", "sshd_setting"),
        target_types=(TargetType.LOCAL,),
        default_timeout=60,
        notes=(
            "Touches no network at all. Only the keys, paths and checks listed "
            "in the catalogue are readable - the parameter values are a choice "
            "from that list, never a free-form path."
        ),
    ),
)

ENGINES: dict[str, EngineSpec] = {spec.id: spec for spec in ENGINE_SPECS}


def get_engine(engine_id: str) -> EngineSpec | None:
    return ENGINES.get(engine_id)


def fact_types_for(engine_id: str) -> frozenset[str]:
    spec = ENGINES.get(engine_id)
    return frozenset(spec.fact_types) if spec else frozenset()


def all_fact_types() -> frozenset[str]:
    return frozenset(
        fact_type for spec in ENGINE_SPECS for fact_type in spec.fact_types
    )
