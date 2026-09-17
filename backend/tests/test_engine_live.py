"""Live tests against the local lab.

These are the only tests here that touch the real machine or the real lab
containers. Each network test is skipped when its port is not accepting
connections, so the suite stays green (and useful) when Docker is not running.
The lab ports are bound to 127.0.0.1 only.

    docker compose -f lab/docker-compose.yml up -d --wait
"""

from __future__ import annotations

import socket

import pytest

from app.engines import http_exposure, http_headers, local_baseline, tls_config
from app.engines.catalogue import (
    HttpExposureParams,
    HttpHeadersParams,
    LocalBaselineParams,
    NucleiParams,
    TlsConfigParams,
)
from app.engines.context import EngineContext, TargetView
from app.engines.runtime import run_engine
from app.models.enums import TargetType

LAB_HEADERS = 8081
LAB_WEBAPP = 8082
LAB_WEAKTLS = 8443


def _port_open(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        return sock.connect_ex(("127.0.0.1", port)) == 0


requires_headers = pytest.mark.skipif(
    not _port_open(LAB_HEADERS), reason=f"lab-headers (127.0.0.1:{LAB_HEADERS}) is not running"
)
requires_webapp = pytest.mark.skipif(
    not _port_open(LAB_WEBAPP), reason=f"lab-webapp (127.0.0.1:{LAB_WEBAPP}) is not running"
)
requires_weaktls = pytest.mark.skipif(
    not _port_open(LAB_WEAKTLS), reason=f"lab-weaktls (127.0.0.1:{LAB_WEAKTLS}) is not running"
)


def _target(port: int, hostname: str, target_type: TargetType) -> TargetView:
    return TargetView(
        ip="127.0.0.1",
        port=port,
        protocol="tcp",
        hostname=hostname,
        path="/",
        target_type=target_type,
    )


def _ctx(tmp_path, timeout_seconds: int) -> EngineContext:
    logs: list[tuple[str, str]] = []
    return EngineContext(
        run_id=1,
        timeout_seconds=timeout_seconds,
        max_output_bytes=4 * 1024 * 1024,
        safe_mode=False,
        workdir=tmp_path,
        log=lambda level, message: logs.append((level, message)),
    )


@requires_headers
def test_live_nmap_through_dispatch_reports_open_and_closed(tmp_path):
    """The whole path: runtime validates the stored parameters, the real nmap
    binary runs a connect scan, the XML is parsed into facts."""
    target = _target(LAB_HEADERS, "lab-headers.local", TargetType.WEBAPP)
    result = run_engine("nmap", target, {"ports": "8081,9999"}, _ctx(tmp_path, 90))

    ports = {f.key: f for f in result.facts if f.fact_type == "port_state"}
    assert ports["tcp/8081"].value["open"] is True
    assert ports["tcp/8081"].confidence == 1.0
    # Nothing listens on 9999; a refused connect is a real observation.
    assert ports["tcp/9999"].value["open"] is False
    assert ports["tcp/9999"].value["state"] == "closed"
    assert ports["tcp/9999"].confidence == 1.0
    assert result.tool_versions.get("nmap")
    # Discovery was skipped (-Pn), so the host_state says so rather than
    # presenting an assumption as a finding.
    host = next(f for f in result.facts if f.fact_type == "host_state")
    assert host.value["reason"] == "user-set"


@requires_headers
def test_live_nuclei_finds_the_missing_headers(tmp_path):
    """The real binary against the real target, with the provisioned template
    tree. Tags and severities are narrowed so only the one known template runs;
    it is severity ``info``, which the engine's default severity floor
    (low..critical) deliberately excludes, so the params say so explicitly."""
    target = _target(LAB_HEADERS, "lab-headers.local", TargetType.WEBAPP)
    params = NucleiParams(template_tags=["headers"], severities=["info"])
    result = run_engine("nuclei", target, params.model_dump(), _ctx(tmp_path, 120))

    keys = {f.key for f in result.facts}
    assert "http-missing-security-headers:strict-transport-security" in keys
    assert all(f.fact_type == "nuclei_finding" for f in result.facts)
    assert all(f.confidence == 1.0 for f in result.facts)


@requires_headers
def test_live_http_headers_sees_the_labs_missing_headers(tmp_path):
    target = _target(LAB_HEADERS, "lab-headers.local", TargetType.WEBAPP)
    result = http_headers.run(target, HttpHeadersParams(), _ctx(tmp_path, 30))

    response = next(f for f in result.facts if f.fact_type == "http_response")
    assert response.value["status_code"] == 200
    assert response.value["body_bytes"] > 0

    headers = {f.key for f in result.facts if f.fact_type == "http_header"}
    assert "server" in headers
    server = next(
        f for f in result.facts if f.fact_type == "http_header" and f.key == "server"
    )
    assert server.value["value"].startswith("nginx")
    # The lab vhost deliberately sets no security headers.
    assert "strict-transport-security" not in headers
    assert "content-security-policy" not in headers


@requires_webapp
def test_live_exposure_finds_the_webapps_leaks(tmp_path):
    """The webapp target serves a real /.env and /.git/HEAD and a real 404 for
    everything else - both a positive and a negative from live responses."""
    target = _target(LAB_WEBAPP, "lab-webapp.local", TargetType.WEBAPP)
    result = http_exposure.run(target, HttpExposureParams(), _ctx(tmp_path, 60))

    facts = {f.key: f for f in result.facts if f.fact_type == "path_exposed"}
    assert facts["/.env"].value["exposed"] is True
    assert facts["/.env"].value["matched_marker"] == "="
    assert facts["/.git/HEAD"].value["exposed"] is True
    assert facts["/robots.txt"].value["exposed"] is False
    assert result.artifacts, "an exposed path must leave evidence behind"


@requires_headers
def test_live_exposure_does_not_find_leaks_where_there_are_none(tmp_path):
    target = _target(LAB_HEADERS, "lab-headers.local", TargetType.WEBAPP)
    result = http_exposure.run(target, HttpExposureParams(), _ctx(tmp_path, 60))

    facts = {f.key: f for f in result.facts if f.fact_type == "path_exposed"}
    assert set(facts) == {"/.env", "/.git/HEAD", "/server-status", "/robots.txt"}
    assert all(f.value["exposed"] is False for f in facts.values())
    assert not result.artifacts


@requires_weaktls
def test_live_tls_config_sees_the_weak_service(tmp_path):
    """testssl against the lab's deliberately weak listener: deprecated
    protocols offered, NULL ciphers offered, a 1024-bit certificate, and the
    well-known vulnerability checks answered. This is the slow live test
    (~a minute) because testssl runs its full default sweep."""
    target = _target(LAB_WEAKTLS, "lab-weaktls.local", TargetType.TLS)
    result = tls_config.run(target, TlsConfigParams(), _ctx(tmp_path, 300))

    facts = {f.key: f for f in result.facts}
    assert facts["TLS1"].value["offered"] is True
    assert facts["TLS1_1"].value["offered"] is True
    assert facts["SSLv2"].value["offered"] is False
    assert facts["cipherlist_NULL"].value["offered"] is True
    assert facts["cert_keySize"].value["bits"] < 2048
    assert facts["cert_keySize"].value["weak"] is True
    assert facts["heartbleed"].value["vulnerable"] is False
    assert facts["heartbleed"].confidence == 1.0
    # The raw JSON is evidence, even live.
    assert result.artifacts and result.artifacts[0].data


def test_live_local_baseline_observes_this_machine(tmp_path):
    """No port to skip on: the local baseline always has a subject. Strictly
    observational - asserting specific compliance here would be asserting the
    test machine's hardening, not the engine."""
    target = _target(0, "localhost", TargetType.LOCAL)
    result = local_baseline.run(target, LocalBaselineParams(), _ctx(tmp_path, 60))

    assert result.facts
    assert {f.fact_type for f in result.facts} <= {
        "sysctl",
        "file_mode",
        "sshd_setting",
    }
    # On an ordinary Linux host at least the sysctls are observable; if this
    # machine cannot read any of them, every sysctl fact says so explicitly.
    sysctls = [f for f in result.facts if f.fact_type == "sysctl"]
    assert sysctls
    for fact in sysctls:
        assert isinstance(fact.value["observable"], bool)
        assert (fact.value["compliant"] is None) == (not fact.value["observable"])
    assert result.tool_versions.get("kernel")
