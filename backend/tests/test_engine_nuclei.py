"""The nuclei engine, driven by a real JSONL capture from the lab.

``fixtures/nuclei_findings.jsonl`` is the actual output of nuclei against the
lab's headers target (127.0.0.1:8081): ten findings from one template
(``http-missing-security-headers``), one per ``matcher-name``. That shape is
the point of the tests below - the finding key has to keep them apart, and a
line that is not a finding has to be counted rather than crash the parser.

``run`` resolves its template directory before anything else and refuses to
start without one; the run tests therefore patch ``templates_dir`` to a
populated temporary directory (``_templates``), and the refusal itself is
pinned by ``test_no_templates_is_unavailable_not_a_clean_run``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.engines import nuclei
from app.engines.catalogue import NucleiParams
from app.engines.context import EngineContext, EngineError, EngineUnavailable, TargetView
from app.models.enums import TargetType
from app.runner.exec import CommandResult

FIXTURES = Path(__file__).resolve().parent / "fixtures"
FINDINGS = FIXTURES / "nuclei_findings.jsonl"

MATCHERS = {
    "x-frame-options",
    "x-content-type-options",
    "x-permitted-cross-domain-policies",
    "referrer-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
    "strict-transport-security",
    "permissions-policy",
    "cross-origin-opener-policy",
    "content-security-policy",
}


def _target(**overrides) -> TargetView:
    values = dict(
        ip="127.0.0.1",
        port=8081,
        protocol="tcp",
        hostname="lab-headers.local",
        path="/",
        target_type=TargetType.WEBAPP,
    )
    values.update(overrides)
    return TargetView(**values)


def _ctx(tmp_path: Path, timeout_seconds: int = 120):
    logs: list[tuple[str, str]] = []
    ctx = EngineContext(
        run_id=1,
        timeout_seconds=timeout_seconds,
        max_output_bytes=1_000_000,
        safe_mode=False,
        workdir=tmp_path,
        log=lambda level, message: logs.append((level, message)),
    )
    return ctx, logs


@pytest.fixture(autouse=True)
def templates(monkeypatch, tmp_path) -> Path:
    """A populated temporary template directory, patched in for
    ``templates_dir``. Autouse: ``run`` refuses to start without one. Tests
    that exercise the refusal re-patch ``templates_dir`` themselves."""
    directory = tmp_path / "templates"
    (directory / "http").mkdir(parents=True)
    (directory / "http" / "dummy.yaml").write_text("id: dummy\n")
    monkeypatch.setattr(nuclei, "templates_dir", lambda: directory)
    return directory


def _stub(monkeypatch, stdout, *, exit_code=0, stderr="", truncated=False, cancelled=False, timed_out=False):
    """Stub the name in the engine module's namespace, not app.runner.exec."""
    calls: list[dict] = []

    def fake_run_command(
        argv, *, timeout_seconds, max_output_bytes, should_cancel=None, env_extra=None, **kwargs
    ):
        calls.append({"argv": list(argv), "env_extra": dict(env_extra or {})})
        return CommandResult(
            argv=list(argv),
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_ms=5,
            truncated=truncated,
            cancelled=cancelled,
            timed_out=timed_out,
        )

    monkeypatch.setattr("app.engines.nuclei.run_command", fake_run_command)
    return calls


def _by_key(result):
    return {f.key: f for f in result.facts if f.fact_type == "nuclei_finding"}


def test_the_captured_findings_are_parsed_one_fact_each(monkeypatch, tmp_path):
    stdout = FINDINGS.read_text()
    _stub(monkeypatch, stdout)
    ctx, _ = _ctx(tmp_path)
    result = nuclei.run(_target(), NucleiParams(), ctx)

    facts = result.facts
    assert len(facts) == 10
    assert all(f.fact_type == "nuclei_finding" for f in facts)
    assert {f.value["matcher_name"] for f in facts} == MATCHERS


def test_each_matcher_keeps_its_own_key(monkeypatch, tmp_path):
    """Ten findings from one template must not collapse into one key: an
    assertion selecting on the key has to be able to name one matcher."""
    _stub(monkeypatch, FINDINGS.read_text())
    ctx, _ = _ctx(tmp_path)
    result = nuclei.run(_target(), NucleiParams(), ctx)

    keys = [f.key for f in result.facts]
    assert len(set(keys)) == 10
    assert set(keys) == {f"http-missing-security-headers:{m}" for m in MATCHERS}

    fact = _by_key(result)["http-missing-security-headers:x-frame-options"]
    assert fact.value["template_id"] == "http-missing-security-headers"
    assert fact.value["template_name"] == "HTTP Missing Security Headers"
    assert fact.value["severity"] == "info"
    assert fact.value["matched_at"] == "http://127.0.0.1:8081"
    assert fact.value["ip"] == "127.0.0.1"
    assert fact.value["cwe"] == ["cwe-693"]
    assert fact.value["cve"] == []
    assert "headers" in fact.value["tags"]


def test_a_finding_without_a_matcher_name_falls_back_to_a_stable_key(monkeypatch, tmp_path):
    payload = json.dumps(
        {
            "template-id": "custom-check",
            "info": {"name": "Custom", "severity": "low"},
        }
    )
    _stub(monkeypatch, payload + "\n")
    ctx, _ = _ctx(tmp_path)
    result = nuclei.run(_target(), NucleiParams(), ctx)

    fact = result.facts[0]
    assert fact.key == "custom-check:match"
    assert fact.value["matcher_name"] is None


def test_a_line_that_is_not_a_finding_is_skipped_and_counted(monkeypatch, tmp_path):
    """nuclei interleaves progress lines, and a template can emit its own
    output. An unparseable line must be dropped but counted, never crash the
    run and never look like a finding that was assessed."""
    noise = [
        "[INF] templates loaded: 1000",
        "[",
        "{}",  # a JSON object that is not a finding (no template-id)
        "[1, 2]",  # a JSON value that is not an object
        "some template debug output",
    ]
    _stub(monkeypatch, FINDINGS.read_text() + "\n".join(noise) + "\n")
    ctx, logs = _ctx(tmp_path)
    result = nuclei.run(_target(), NucleiParams(), ctx)

    assert len(result.facts) == 10
    assert any("5 output line(s) were not parseable findings" in n for n in result.notes)
    # Each non-JSON line produced a warning naming the line.
    assert sum(1 for level, _ in logs if level == "warning") == 3


def test_blank_lines_are_not_counted_as_skipped(monkeypatch, tmp_path):
    _stub(monkeypatch, "\n\n" + FINDINGS.read_text() + "\n\n")
    ctx, _ = _ctx(tmp_path)
    result = nuclei.run(_target(), NucleiParams(), ctx)
    assert len(result.facts) == 10
    assert not any("not parseable" in n for n in result.notes)


def test_truncated_output_is_an_error_not_an_incomplete_result(monkeypatch, tmp_path):
    """Findings that were cut off are findings that will never be evaluated,
    and a control with no finding against it reads as a control that held."""
    _stub(monkeypatch, FINDINGS.read_text(), truncated=True)
    ctx, _ = _ctx(tmp_path)
    with pytest.raises(EngineError, match="exceeded the capture limit"):
        nuclei.run(_target(), NucleiParams(), ctx)


def test_a_missing_binary_is_unavailable(monkeypatch, tmp_path):
    _stub(monkeypatch, "", exit_code=None, stderr="nuclei is not installed")
    ctx, _ = _ctx(tmp_path)
    with pytest.raises(EngineUnavailable):
        nuclei.run(_target(), NucleiParams(), ctx)


def test_a_failed_run_without_findings_is_an_error(monkeypatch, tmp_path):
    _stub(monkeypatch, "", exit_code=2, stderr="something broke")
    ctx, _ = _ctx(tmp_path)
    with pytest.raises(EngineError, match="exited 2"):
        nuclei.run(_target(), NucleiParams(), ctx)


def test_a_failed_run_that_still_printed_findings_is_parsed(monkeypatch, tmp_path):
    """JSONL on stdout exists exactly so a run that dies late still leaves the
    findings it produced in the captured stream."""
    _stub(monkeypatch, FINDINGS.read_text(), exit_code=2)
    ctx, _ = _ctx(tmp_path)
    result = nuclei.run(_target(), NucleiParams(), ctx)
    assert len(result.facts) == 10


def test_cancelled_and_timed_out_runs_say_their_finding_set_may_be_partial(monkeypatch, tmp_path):
    _stub(monkeypatch, FINDINGS.read_text(), cancelled=True)
    ctx, _ = _ctx(tmp_path)
    result = nuclei.run(_target(), NucleiParams(), ctx)
    assert any("cancelled" in note for note in result.notes)

    _stub(monkeypatch, FINDINGS.read_text(), timed_out=True)
    ctx, _ = _ctx(tmp_path)
    result = nuclei.run(_target(), NucleiParams(), ctx)
    assert any("timed out" in note for note in result.notes)


def test_the_finding_count_and_severity_summary_is_reported(monkeypatch, tmp_path):
    _stub(monkeypatch, FINDINGS.read_text())
    ctx, _ = _ctx(tmp_path)
    result = nuclei.run(_target(), NucleiParams(), ctx)
    assert any(note.startswith("10 finding(s)") and "10 info" in note for note in result.notes)


def test_no_templates_is_unavailable_not_a_clean_run(monkeypatch, tmp_path):
    """An empty template set produces an empty run, and an empty run against a
    control reads exactly like a control that held - so it must refuse."""
    calls = _stub(monkeypatch, "")
    ctx, _ = _ctx(tmp_path)

    empty = tmp_path / "empty-templates"
    empty.mkdir()
    monkeypatch.setattr(nuclei, "templates_dir", lambda: empty)
    with pytest.raises(EngineUnavailable, match="no nuclei templates"):
        nuclei.run(_target(), NucleiParams(), ctx)

    # A directory that exists but holds no YAML is the same empty run.
    (empty / "readme.txt").write_text("nothing to run here")
    with pytest.raises(EngineUnavailable, match="no nuclei templates"):
        nuclei.run(_target(), NucleiParams(), ctx)

    assert calls == [], "the tool must not be started with no templates"


def test_the_run_gets_its_own_home_and_tmpdir(monkeypatch, tmp_path):
    """The executor's environment is scrubbed and HOME points at a path that
    does not exist; nuclei writes a config and a template cache on startup and
    would not run without somewhere writable - which must not be the
    operator's own nuclei profile."""
    calls = _stub(monkeypatch, "")
    ctx, _ = _ctx(tmp_path)
    nuclei.run(_target(), NucleiParams(), ctx)

    assert calls[-1]["env_extra"]["HOME"] == str(tmp_path)
    assert calls[-1]["env_extra"]["TMPDIR"] == str(tmp_path)


def test_argv_is_restricted_so_it_cannot_leave_the_target(tmp_path, templates):
    target = _target()
    argv = nuclei.build_argv(target, NucleiParams(), templates)

    assert argv[0] == "nuclei"
    assert argv[argv.index("-u") + 1] == "http://127.0.0.1:8081"
    # The hardening flags, each for a way the run could otherwise reach out.
    assert argv[argv.index("-pt") + 1] == "http"  # no file/code/javascript/dns
    assert argv[argv.index("-t") + 1] == str(templates), "an explicit local tree, never a download"
    assert "-ni" in argv  # no interactsh callbacks
    assert "-duc" in argv  # no template auto-update
    assert "-j" in argv and "-or" in argv and "-ot" in argv
    assert argv[argv.index("-severity") + 1] == "low,medium,high,critical"
    assert argv[argv.index("-tags") + 1] == "headers,misconfiguration,exposure"
    # The operator's hostname reaches the app through the Host header, while
    # the connection goes to the pinned address.
    assert argv[argv.index("-H") + 1] == "Host: lab-headers.local:8081"


def test_no_host_header_when_the_hostname_is_the_address(tmp_path, templates):
    argv = nuclei.build_argv(_target(hostname="127.0.0.1"), NucleiParams(), templates)
    assert "-H" not in argv


def test_argv_carries_the_chosen_tags_and_severities(templates):
    params = NucleiParams(template_tags=["ssl"], severities=["critical"], rate_limit=7)
    argv = nuclei.build_argv(_target(), params, templates)
    assert argv[argv.index("-tags") + 1] == "ssl"
    assert argv[argv.index("-severity") + 1] == "critical"
    assert argv[argv.index("-rl") + 1] == "7"
