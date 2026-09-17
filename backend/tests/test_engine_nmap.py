"""The nmap engine, driven by a real captured scan of the lab.

The fixture (``fixtures/nmap_connect_scan.xml``) is the actual XML nmap
produced for ``-sT -Pn -n -p 8081,8082,9999 127.0.0.1``: 8081/8082 open, 9999
closed, the host reported up with reason ``user-set`` because discovery was
skipped, and every service name taken from nmap's own ports table rather than
observed. ``fixtures/nmap_probed_service.xml`` is derived from it with ``-sV``
on, so port 8081 carries ``method="probed"`` and a product/version.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.engines import nmap
from app.engines.catalogue import NmapParams
from app.engines.context import EngineContext, EngineError, TargetView
from app.models.enums import TargetType
from app.runner.exec import CommandResult

FIXTURES = Path(__file__).resolve().parent / "fixtures"
CAPTURED_SCAN = FIXTURES / "nmap_connect_scan.xml"
PROBED_SCAN = FIXTURES / "nmap_probed_service.xml"


def _target(**overrides) -> TargetView:
    values = dict(
        ip="127.0.0.1",
        port=8081,
        protocol="tcp",
        hostname="lab.local",
        path="/",
        target_type=TargetType.WEBAPP,
    )
    values.update(overrides)
    return TargetView(**values)


def _ctx(tmp_path: Path, *, safe_mode: bool = False, timeout_seconds: int = 120):
    logs: list[tuple[str, str]] = []
    ctx = EngineContext(
        run_id=1,
        timeout_seconds=timeout_seconds,
        max_output_bytes=1_000_000,
        safe_mode=safe_mode,
        workdir=tmp_path,
        log=lambda level, message: logs.append((level, message)),
    )
    return ctx, logs


def _stub(monkeypatch, stdout, *, exit_code=0, stderr="", truncated=False):
    """Stub the name the engine module actually looks up.

    ``nmap.py`` did ``from app.runner.exec import run_command``, so its binding
    lives in ``app.engines.nmap``. Patching ``app.runner.exec.run_command``
    would not reach it.
    """
    calls: list[list[str]] = []

    def fake_run_command(
        argv, *, timeout_seconds, max_output_bytes, should_cancel=None, on_output=None, **kwargs
    ):
        calls.append(list(argv))
        return CommandResult(
            argv=list(argv),
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_ms=5,
            truncated=truncated,
        )

    monkeypatch.setattr("app.engines.nmap.run_command", fake_run_command)
    return calls


def _facts(result, fact_type):
    return [f for f in result.facts if f.fact_type == fact_type]


def _by_key(result, fact_type):
    return {f.key: f for f in result.facts if f.fact_type == fact_type}


def test_stubbing_runner_exec_alone_would_not_reach_the_engine(monkeypatch):
    """The import-into-namespace gotcha, pinned so a future test author does
    not silently stub nothing: the engine holds its own reference."""
    import app.runner.exec as exec_module

    monkeypatch.setattr(exec_module, "run_command", lambda *a, **k: None)
    assert nmap.run_command is not exec_module.run_command


def test_the_captured_scan_parses_every_port(monkeypatch, tmp_path):
    calls = _stub(monkeypatch, CAPTURED_SCAN.read_text())
    ctx, logs = _ctx(tmp_path)
    result = nmap.run(_target(), NmapParams(ports="8081,8082,9999"), ctx)

    assert calls, "the engine must have invoked run_command"
    ports = _by_key(result, "port_state")
    assert set(ports) == {"tcp/8081", "tcp/8082", "tcp/9999"}

    open_port = ports["tcp/8081"]
    assert open_port.value["open"] is True
    assert open_port.value["state"] == "open"
    assert open_port.value["reason"] == "syn-ack"
    assert open_port.confidence == 1.0

    closed = ports["tcp/9999"]
    assert closed.value["open"] is False
    assert closed.value["state"] == "closed"
    assert closed.value["reason"] == "conn-refused"
    assert closed.confidence == 1.0

    host = _facts(result, "host_state")[0]
    assert host.value["up"] is True
    assert host.key == "127.0.0.1"
    assert result.tool_versions["nmap"] == "7.99"
    assert result.exit_code == 0


def test_a_user_set_host_reason_is_kept_and_warned_about(monkeypatch, tmp_path):
    """-Pn makes nmap report the host up without having tested it. The fact
    keeps the reason and the run says so in a warning."""
    _stub(monkeypatch, CAPTURED_SCAN.read_text())
    ctx, logs = _ctx(tmp_path)
    result = nmap.run(_target(), NmapParams(ports="8081,8082,9999"), ctx)

    host = _facts(result, "host_state")[0]
    assert host.value["reason"] == "user-set"
    assert any(
        level == "warning" and "not because it answered" in message
        for level, message in logs
    )


def test_a_table_service_name_is_not_a_confirmation(monkeypatch, tmp_path):
    """A name from nmap's /etc/services table is a guess about a port number.
    The fact must say so, so an assertion over a service name can insist on
    ``probed`` instead of accepting a lookup."""
    _stub(monkeypatch, CAPTURED_SCAN.read_text())
    ctx, _ = _ctx(tmp_path)
    result = nmap.run(_target(), NmapParams(ports="8081,8082,9999"), ctx)

    port = _by_key(result, "port_state")["tcp/8081"]
    assert port.value["service"] == "blackice-icecap"
    assert port.value["service_method"] == "table"
    assert port.value["service_confirmed"] is False
    assert port.value["product"] is None
    assert port.value["version"] is None
    assert any("services table" in note for note in result.notes)


def test_a_probed_service_is_confirmed(monkeypatch, tmp_path):
    _stub(monkeypatch, PROBED_SCAN.read_text())
    ctx, _ = _ctx(tmp_path)
    result = nmap.run(_target(), NmapParams(ports="8081,8082,9999"), ctx)

    ports = _by_key(result, "port_state")
    probed = ports["tcp/8081"]
    assert probed.value["service"] == "http"
    assert probed.value["service_method"] == "probed"
    assert probed.value["service_confirmed"] is True
    assert probed.value["product"] == "nginx"
    assert probed.value["version"] == "1.31.6"

    # 8082 keeps its table lookup in the same document: not confirmed.
    table = ports["tcp/8082"]
    assert table.value["service"] == "blackice-alerts"
    assert table.value["service_confirmed"] is False


def test_a_port_without_a_state_element_is_unobserved(monkeypatch, tmp_path):
    """nmap listing a port without saying anything about it is not an
    observation, and must not read as "closed"."""
    xml = (
        '<?xml version="1.0"?>\n'
        '<nmaprun scanner="nmap" version="7.99">\n'
        '<host><status state="up" reason="syn-ack"/><address addr="127.0.0.1" addrtype="ipv4"/>\n'
        "<ports><port protocol=\"tcp\" portid=\"8081\">"
        '<service name="http" method="table"/></port></ports>\n'
        "</host></nmaprun>\n"
    )
    _stub(monkeypatch, xml)
    ctx, _ = _ctx(tmp_path)
    result = nmap.run(_target(), NmapParams(ports="8081"), ctx)

    port = _by_key(result, "port_state")["tcp/8081"]
    assert port.confidence == 0.0
    assert port.value["state"] == "unknown"
    assert port.value["open"] is None
    assert "without reporting a state" in port.detail
    # The service fields nmap did include are still reported, unconfirmed.
    assert port.value["service"] == "http"
    assert port.value["service_confirmed"] is False


def test_a_port_without_a_service_element_reports_absences(monkeypatch, tmp_path):
    xml = (
        '<?xml version="1.0"?>\n'
        '<nmaprun scanner="nmap" version="7.99">\n'
        '<host><status state="up" reason="syn-ack"/><address addr="127.0.0.1" addrtype="ipv4"/>\n'
        '<ports><port protocol="tcp" portid="8081">'
        '<state state="open" reason="syn-ack"/></port></ports>\n'
        "</host></nmaprun>\n"
    )
    _stub(monkeypatch, xml)
    ctx, _ = _ctx(tmp_path)
    result = nmap.run(_target(), NmapParams(ports="8081"), ctx)

    port = _by_key(result, "port_state")["tcp/8081"]
    assert port.value["service"] is None
    assert port.value["service_method"] is None
    assert port.value["service_confirmed"] is False


def test_truncated_output_is_an_error_not_a_partial_result(monkeypatch, tmp_path):
    _stub(monkeypatch, CAPTURED_SCAN.read_text(), truncated=True)
    ctx, _ = _ctx(tmp_path)
    with pytest.raises(EngineError, match="exceeded the capture limit"):
        nmap.run(_target(), NmapParams(ports="8081"), ctx)


def test_a_failed_command_is_an_error(monkeypatch, tmp_path):
    _stub(monkeypatch, "", exit_code=1, stderr="nmap: QUITTING!")
    ctx, _ = _ctx(tmp_path)
    with pytest.raises(EngineError, match="exited 1"):
        nmap.run(_target(), NmapParams(ports="8081"), ctx)


def test_a_missing_binary_is_reported_as_an_error(monkeypatch, tmp_path):
    _stub(monkeypatch, "", exit_code=None, stderr="nmap is not installed")
    ctx, _ = _ctx(tmp_path)
    with pytest.raises(EngineError):
        nmap.run(_target(), NmapParams(ports="8081"), ctx)


def test_unparseable_output_is_an_error(monkeypatch, tmp_path):
    _stub(monkeypatch, "this is not xml")
    ctx, _ = _ctx(tmp_path)
    with pytest.raises(EngineError, match="could not be parsed"):
        nmap.run(_target(), NmapParams(ports="8081"), ctx)


def test_a_wrong_document_type_is_an_error(monkeypatch, tmp_path):
    _stub(monkeypatch, "<foo/>")
    ctx, _ = _ctx(tmp_path)
    with pytest.raises(EngineError, match="expected an nmaprun document"):
        nmap.run(_target(), NmapParams(ports="8081"), ctx)


def test_a_document_without_hosts_is_an_error(monkeypatch, tmp_path):
    _stub(monkeypatch, '<?xml version="1.0"?><nmaprun scanner="nmap" version="7.99"/>')
    ctx, _ = _ctx(tmp_path)
    with pytest.raises(EngineError, match="reported no host"):
        nmap.run(_target(), NmapParams(ports="8081"), ctx)


def test_argv_is_a_pinned_connect_scan(tmp_path):
    ctx, _ = _ctx(tmp_path, timeout_seconds=120)
    argv = nmap.build_argv(_target(), NmapParams(ports="8081,8082,9999"), ctx)

    assert argv[0] == "nmap"
    assert {"-sT", "-Pn", "-n"} <= set(argv)
    assert "-sV" in argv  # service detection is on by default
    assert "--version-light" not in argv
    assert argv[argv.index("-p") + 1] == "8081,8082,9999"
    assert argv[-1] == "127.0.0.1", "the pinned address is the only target"
    # nmap's own budget is the runner's minus a margin, floored at 30s.
    assert argv[argv.index("--host-timeout") + 1] == "100s"


def test_argv_safe_mode_narrows_version_detection(tmp_path):
    ctx, _ = _ctx(tmp_path, safe_mode=True)
    argv = nmap.build_argv(_target(), NmapParams(ports="443"), ctx)
    assert "--version-light" in argv

    ctx, _ = _ctx(tmp_path)
    argv = nmap.build_argv(_target(), NmapParams(ports="443"), ctx)
    assert "-sV" in argv and "--version-light" not in argv

    argv = nmap.build_argv(_target(), NmapParams(ports="443", service_detection=False), ctx)
    assert "-sV" not in argv and "--version-light" not in argv


def test_argv_rate_limit_and_timeout_floor(tmp_path):
    ctx, _ = _ctx(tmp_path, timeout_seconds=40)
    argv = nmap.build_argv(_target(), NmapParams(ports="443", max_rate=500), ctx)
    assert argv[argv.index("--max-rate") + 1] == "500"
    assert argv[argv.index("--host-timeout") + 1] == "30s"

    argv = nmap.build_argv(_target(), NmapParams(ports="443"), ctx)
    assert "--max-rate" not in argv


def test_safe_mode_note_is_added_only_when_version_light_ran(monkeypatch, tmp_path):
    _stub(monkeypatch, CAPTURED_SCAN.read_text())
    ctx, _ = _ctx(tmp_path, safe_mode=True)
    result = nmap.run(_target(), NmapParams(ports="8081,8082,9999"), ctx)
    assert any("--version-light" in note for note in result.notes)
