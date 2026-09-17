"""The engine catalogue is the contract between the API, the runner and the UI.

These tests pin the properties the other layers rely on: parameter models that
refuse what they do not understand (an extra key is an error, never silently
dropped), the declared fact types, and the validators that keep a parameter
value a choice *from* a curated list rather than a free-form path.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.engines import catalogue
from app.engines.catalogue import (
    ALLOWED_LOCAL_PATHS,
    ALLOWED_SYSCTLS,
    DIRECTORY_LISTING_MARKERS,
    ENGINES,
    ENGINE_SPECS,
    EXPOSURE_MARKERS,
    EXPOSURE_PATHS,
    LOCAL_BASELINE_CHECKS,
    NUCLEI_SEVERITIES,
    NUCLEI_TEMPLATE_TAGS,
    HttpExposureParams,
    HttpHeadersParams,
    LocalBaselineParams,
    NmapParams,
    NucleiParams,
    TlsConfigParams,
    all_fact_types,
    fact_types_for,
    get_engine,
)
from app.models.enums import TargetType

ENGINE_IDS = [spec.id for spec in ENGINE_SPECS]


def _minimal(spec) -> object:
    """A minimally valid instance of an engine's params model."""
    if spec.params is NmapParams:
        return spec.params(ports="8081")
    return spec.params()


# --------------------------------------------------------------- strict params --


@pytest.mark.parametrize("spec", ENGINE_SPECS, ids=ENGINE_IDS)
def test_an_unknown_parameter_is_refused_never_dropped(spec):
    """A typo must be an error, not a silent fall back to a default the
    operator never chose - on a security test that difference is the result."""
    raw = _minimal(spec).model_dump()
    raw["surprise_option"] = True
    with pytest.raises(ValidationError) as excinfo:
        spec.params.model_validate(raw)
    assert "surprise_option" in str(excinfo.value)


@pytest.mark.parametrize("spec", ENGINE_SPECS, ids=ENGINE_IDS)
def test_parameters_are_frozen(spec):
    instance = _minimal(spec)
    field = next(iter(spec.params.model_fields))
    with pytest.raises(ValidationError):
        setattr(instance, field, getattr(instance, field))


def test_nmap_ports_must_be_parseable():
    assert NmapParams(ports="80,443,8000-8010").ports == "80,443,8000-8010"
    for bad in ("", "http", "0", "70000", "80-", "-80", "443,notaport", "8000-7000"):
        with pytest.raises(ValidationError):
            NmapParams(ports=bad)


def test_nmap_defaults():
    params = NmapParams(ports="443")
    assert params.service_detection is True
    assert params.max_rate is None
    assert NmapParams(ports="443", max_rate=1000).max_rate == 1000
    for bad in (0, 1001):
        with pytest.raises(ValidationError):
            NmapParams(ports="443", max_rate=bad)


def test_tls_params_deliberately_have_no_severity_floor():
    """testssl's --severity drops lower-graded entries from its JSON output, so
    a floor here would leave an assertion like 'no LOW finding exists' with
    nothing to look at - and it would pass."""
    assert set(TlsConfigParams.model_fields) == {
        "check_vulnerabilities",
        "starttls",
        "max_wait_seconds",
    }
    assert TlsConfigParams().check_vulnerabilities is False
    assert TlsConfigParams().starttls is None
    assert TlsConfigParams().max_wait_seconds == 240


def test_tls_starttls_only_accepts_known_protocols():
    for good in ("ftp", "smtp", "imap", "pop3", "ldap", "postgres", "mysql"):
        assert TlsConfigParams(starttls=good).starttls == good
    for bad in ("raw", "https", "smtp ", "a" * 33):
        with pytest.raises(ValidationError):
            TlsConfigParams(starttls=bad)


def test_tls_wait_bounds():
    assert TlsConfigParams(max_wait_seconds=30).max_wait_seconds == 30
    assert TlsConfigParams(max_wait_seconds=900).max_wait_seconds == 900
    for bad in (29, 901):
        with pytest.raises(ValidationError):
            TlsConfigParams(max_wait_seconds=bad)


def test_http_headers_params():
    assert HttpHeadersParams().path == "/"
    assert HttpHeadersParams().method == "GET"
    assert HttpHeadersParams().follow_redirects is False
    assert HttpHeadersParams(method="HEAD").method == "HEAD"
    with pytest.raises(ValidationError):
        HttpHeadersParams(method="POST")
    # 255 characters fit, 256 do not.
    assert HttpHeadersParams(path="/" + "a" * 254).path
    with pytest.raises(ValidationError):
        HttpHeadersParams(path="/" + "a" * 255)


def test_http_exposure_profile_is_curated():
    assert HttpExposureParams().profile == "minimal"
    assert set(EXPOSURE_PATHS) == {
        "minimal",
        "web",
        "api",
        "spring",
        "vcs",
        "dirlist",
    }
    with pytest.raises(ValidationError):
        HttpExposureParams(profile="everything")


def test_http_exposure_extra_paths_must_be_boring():
    good = HttpExposureParams(extra_paths=["/notes.txt", "/admin", "/a-b_c~d"])
    assert good.extra_paths == ["/notes.txt", "/admin", "/a-b_c~d"]
    for bad in (
        "relative/path",
        "/../etc/passwd",
        "/a/../b",
        "/a//b",
        "/a?b=c",
        "/a#fragment",
        "http://evil.example/",
        "   ",
    ):
        with pytest.raises(ValidationError):
            HttpExposureParams(extra_paths=[bad])


def test_http_exposure_extra_paths_are_capped():
    HttpExposureParams(extra_paths=[f"/p{i}" for i in range(32)])
    with pytest.raises(ValidationError):
        HttpExposureParams(extra_paths=[f"/p{i}" for i in range(33)])


def test_nuclei_tags_and_severities_are_curated():
    defaults = NucleiParams()
    assert defaults.template_tags == ["headers", "misconfiguration", "exposure"]
    assert defaults.severities == ["low", "medium", "high", "critical"]
    assert defaults.rate_limit == 25

    with pytest.raises(ValidationError) as excinfo:
        NucleiParams(template_tags=["fuzz"])
    assert "unsupported template tags" in str(excinfo.value)
    with pytest.raises(ValidationError):
        NucleiParams(severities=["catastrophic"])
    assert NucleiParams(severities=["high", "critical"]).severities == ["high", "critical"]

    for bad in (0, 151):
        with pytest.raises(ValidationError):
            NucleiParams(rate_limit=bad)
    # The intrusive template classes are not in the curated tag list at all.
    for intrusive in ("fuzz", "dos", "intrusive", "brute-force", "code", "file"):
        assert intrusive not in NUCLEI_TEMPLATE_TAGS
    assert set(NUCLEI_SEVERITIES) == {"info", "low", "medium", "high", "critical"}


def test_local_baseline_params_choose_from_the_allowlist():
    defaults = LocalBaselineParams()
    assert defaults.checks == ["sysctls", "file_modes", "sshd_config"]
    assert set(defaults.sysctl_keys) == set(ALLOWED_SYSCTLS)
    assert set(defaults.paths) == set(ALLOWED_LOCAL_PATHS)

    with pytest.raises(ValidationError):
        LocalBaselineParams(checks=["network"])
    with pytest.raises(ValidationError):
        LocalBaselineParams(checks=[])
    with pytest.raises(ValidationError):
        LocalBaselineParams(sysctl_keys=["kernel.dmesg_restrict", "kernel.unknown_key"])
    with pytest.raises(ValidationError):
        LocalBaselineParams(paths=["/root/.ssh/id_rsa"])
    # The allowlists are exactly what the engine knows how to judge.
    assert set(LOCAL_BASELINE_CHECKS) == {"sysctls", "file_modes", "sshd_config"}


# ------------------------------------------------------------ the catalog data --


def test_engine_ids_are_unique_and_well_formed():
    assert len(ENGINE_IDS) == len(set(ENGINE_IDS))
    for spec in ENGINE_SPECS:
        assert spec.id and spec.title and spec.description
        assert spec.fact_types, f"{spec.id} declares no fact types"
        assert spec.target_types, f"{spec.id} declares no target types"
        assert all(isinstance(t, TargetType) for t in spec.target_types)
        assert spec.default_timeout > 0
        assert spec.mutating is False, f"{spec.id} must be read-only"
        assert spec.internal is False


def test_only_local_baseline_targets_the_local_machine():
    local = {spec.id for spec in ENGINE_SPECS if TargetType.LOCAL in spec.target_types}
    assert local == {"local_baseline"}


def test_describe_is_json_friendly():
    described = ENGINES["nmap"].describe()
    assert described["id"] == "nmap"
    assert described["fact_types"] == ["port_state", "host_state"]
    assert described["target_types"] == ["host", "webapp", "api", "tls", "ssh"]
    assert described["mutating"] is False
    assert "properties" in described["params_schema"]


def test_get_engine_and_fact_type_helpers():
    assert get_engine("nmap").id == "nmap"
    assert get_engine("does-not-exist") is None
    assert fact_types_for("nmap") == frozenset({"port_state", "host_state"})
    assert fact_types_for("does-not-exist") == frozenset()
    assert all_fact_types() == frozenset(
        fact_type for spec in ENGINE_SPECS for fact_type in spec.fact_types
    )
    assert {
        "port_state",
        "tls_protocol",
        "tls_cipher",
        "tls_certificate",
        "tls_vulnerability",
        "http_response",
        "http_header",
        "http_cookie",
        "path_exposed",
        "nuclei_finding",
        "sysctl",
        "file_mode",
        "sshd_setting",
    } <= all_fact_types()


def test_every_curated_exposure_path_is_absolute_and_boring():
    for profile, paths in EXPOSURE_PATHS.items():
        assert paths, f"profile {profile!r} is empty"
        for path in paths:
            assert path.startswith("/"), path
            assert ".." not in path and "?" not in path and "//" not in path, path
    for path in EXPOSURE_MARKERS:
        assert path.startswith("/"), path
    assert DIRECTORY_LISTING_MARKERS


def test_the_catalogue_module_is_importable_without_tool_side_effects():
    """The declaration exists so the API layer never imports a module that
    shells out; importing it must not require nmap/testssl/nuclei."""
    assert catalogue.ENGINES is ENGINES
