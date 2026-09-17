"""Dispatch, and the two runtime invariants that make the catalogue load-bearing:

* stored parameters (a JSONB column, not a request body) are re-validated
  before an engine runs;
* an engine that emits a fact type it did not declare is an error, because
  assertions are written against the declaration and an undeclared fact would
  make a test look like it passed.
"""

from __future__ import annotations

import importlib
from pathlib import Path
from types import ModuleType

import pytest

from app.engines import runtime
from app.engines.catalogue import ENGINES, ENGINE_SPECS, EngineSpec
from app.engines.context import (
    EngineContext,
    EngineError,
    EngineResult,
    FactDraft,
    TargetView,
)
from app.models.enums import TargetType

FIXTURES = Path(__file__).resolve().parent / "fixtures"
NMAP_XML = FIXTURES / "nmap_connect_scan.xml"


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


def _ctx(tmp_path: Path, **overrides) -> EngineContext:
    values = dict(
        run_id=1,
        timeout_seconds=60,
        max_output_bytes=1_000_000,
        safe_mode=False,
        workdir=tmp_path,
    )
    values.update(overrides)
    return EngineContext(**values)


def test_an_unknown_engine_id_is_refused_with_the_known_list():
    with pytest.raises(EngineError) as excinfo:
        runtime.load_engine("definitely-not-an-engine")
    message = str(excinfo.value)
    assert "unknown engine" in message
    assert "nmap" in message and "local_baseline" in message


def test_a_declared_engine_without_an_implementation_is_refused(monkeypatch):
    ghost = EngineSpec(
        id="ghost_engine",
        title="Declared but not implemented",
        description="exists only for this test",
        params=ENGINES["tls_config"].params,
        fact_types=("ghost_fact",),
        target_types=(TargetType.LOCAL,),
        default_timeout=5,
    )
    monkeypatch.setitem(runtime.ENGINES, "ghost_engine", ghost)
    with pytest.raises(EngineError, match="declared but not implemented"):
        runtime.load_engine("ghost_engine")


def test_an_engine_module_without_run_is_refused(monkeypatch):
    ghost = EngineSpec(
        id="ghost_engine",
        title="Declared but without run()",
        description="exists only for this test",
        params=ENGINES["tls_config"].params,
        fact_types=("ghost_fact",),
        target_types=(TargetType.LOCAL,),
        default_timeout=5,
    )
    monkeypatch.setitem(runtime.ENGINES, "ghost_engine", ghost)

    def fake_import(name: str) -> ModuleType:
        return ModuleType(name)

    monkeypatch.setattr(importlib, "import_module", fake_import)
    with pytest.raises(EngineError, match="has no run\\(\\) entry point"):
        runtime.load_engine("ghost_engine")


@pytest.mark.parametrize("spec", ENGINE_SPECS, ids=[s.id for s in ENGINE_SPECS])
def test_every_declared_engine_loads_and_has_a_run_entry_point(spec):
    loaded_spec, module = runtime.load_engine(spec.id)
    assert loaded_spec is spec
    assert callable(module.run)


def test_a_target_type_the_engine_does_not_declare_is_refused(monkeypatch):
    """The engine must not even be reached: a local-only engine asked to run
    against a web application is a wiring mistake, not a scan."""
    calls = []
    monkeypatch.setattr(
        "app.engines.local_baseline.run", lambda *a, **k: calls.append(a)
    )
    with pytest.raises(EngineError, match="does not run against a webapp target"):
        runtime.run_engine(
            "local_baseline", _target(), {}, _ctx(Path("/tmp"))
        )
    assert calls == []


def test_stored_parameters_are_revalidated_before_the_engine_runs(monkeypatch):
    """Parameters arrive from a JSONB column: a row edited directly in the
    database must not be able to hand an engine parameters its own schema
    would have refused."""
    ran = []
    monkeypatch.setattr(
        "app.engines.nmap.run_command",
        lambda *a, **k: ran.append(a),
    )
    with pytest.raises(EngineError) as excinfo:
        runtime.run_engine(
            "nmap",
            _target(),
            {"ports": "8081", "surprise_option": True},
            _ctx(Path("/tmp")),
        )
    assert "nmap rejected its stored parameters" in str(excinfo.value)
    assert ran == [], "the engine must not have been started"


def test_stored_parameters_with_an_invalid_value_are_refused(monkeypatch):
    ran = []
    monkeypatch.setattr("app.engines.nmap.run_command", lambda *a, **k: ran.append(a))
    with pytest.raises(EngineError, match="rejected its stored parameters"):
        runtime.run_engine("nmap", _target(), {"ports": "70000"}, _ctx(Path("/tmp")))
    assert ran == []


def test_missing_parameters_fall_back_to_defaults_only_where_a_default_exists():
    tls = runtime.build_params(ENGINES["tls_config"], None)
    assert tls.check_vulnerabilities is False
    # nmap's ports field is required, so None must be an error, not an empty scan.
    with pytest.raises(EngineError, match="rejected its stored parameters"):
        runtime.build_params(ENGINES["nmap"], None)


def test_an_engine_emitting_an_undeclared_fact_type_is_an_error(monkeypatch):
    """Assertions are written against the declaration. An undeclared fact type
    could never be selected by them, so the mismatch would look like a control
    that passed."""

    def rogue_run(target, params, ctx):
        return EngineResult(
            facts=[FactDraft(fact_type="open_port", value={"port": 8081})]
        )

    monkeypatch.setattr("app.engines.nmap.run", rogue_run)
    with pytest.raises(EngineError) as excinfo:
        runtime.run_engine("nmap", _target(), {"ports": "8081"}, _ctx(Path("/tmp")))
    message = str(excinfo.value)
    assert "engine 'nmap' emitted undeclared fact type(s): open_port" in message


def test_declared_fact_types_pass_the_runtime_check(monkeypatch):
    declared = EngineResult(facts=[FactDraft(fact_type="port_state", value={"port": 8081})])
    monkeypatch.setattr("app.engines.nmap.run", lambda *a, **k: declared)
    result = runtime.run_engine("nmap", _target(), {"ports": "8081"}, _ctx(Path("/tmp")))
    assert result is declared


def test_the_real_nmap_parser_and_dispatch_work_together(monkeypatch, tmp_path):
    """One integration path through run_engine: validated parameters in, the
    fixture's XML out, every fact type checked against the catalogue."""
    from app.runner.exec import CommandResult

    stdout = NMAP_XML.read_text()

    def fake_run_command(
        argv, *, timeout_seconds, max_output_bytes, should_cancel=None, on_output=None, **kwargs
    ):
        return CommandResult(
            argv=list(argv),
            exit_code=0,
            stdout=stdout,
            stderr="",
            duration_ms=5,
        )

    monkeypatch.setattr("app.engines.nmap.run_command", fake_run_command)
    spec = ENGINES["nmap"]
    raw_params = {"ports": "8081,8082,9999"}
    result = runtime.run_engine("nmap", _target(), raw_params, _ctx(tmp_path))
    assert result.facts
    assert {f.fact_type for f in result.facts} <= set(spec.fact_types)
    assert any(f.key == "tcp/8081" and f.value["open"] is True for f in result.facts)
