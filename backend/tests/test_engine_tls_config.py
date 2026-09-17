"""The tls_config engine, driven by a real testssl capture of the lab.

``fixtures/testssl_weaktls.json`` is the actual JSON testssl.sh produced
against the lab's deliberately weak TLS service on 127.0.0.1:8443: TLS 1.0/1.1
offered, NULL cipher suites offered, a 1024-bit self-signed certificate, and
both readable ("not vulnerable" / "VULNERABLE") and unreadable verdicts.

``fixtures/testssl_edge_cases.json`` is a small synthetic document for the
branches the real capture does not hit: an unreadable protocol result and a
cipher line that cannot be split into columns.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from app.engines import tls_config
from app.engines.catalogue import TlsConfigParams
from app.engines.context import (
    EngineContext,
    EngineError,
    EngineUnavailable,
    TargetView,
)
from app.models.enums import TargetType
from app.runner.exec import CommandResult

FIXTURES = Path(__file__).resolve().parent / "fixtures"
WEAKTLS = FIXTURES / "testssl_weaktls.json"
EDGE_CASES = FIXTURES / "testssl_edge_cases.json"


def _target(**overrides) -> TargetView:
    values = dict(
        ip="127.0.0.1",
        port=8443,
        protocol="tcp",
        hostname="lab-weaktls.local",
        path="/",
        target_type=TargetType.TLS,
    )
    values.update(overrides)
    return TargetView(**values)


def _ctx(tmp_path: Path, timeout_seconds: int = 240):
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


def _stub_testssl(
    monkeypatch,
    payload: bytes | None,
    *,
    exit_code=0,
    truncated=False,
    timed_out=False,
    cancelled=False,
    version: str | None = "testssl version 9.9.9 from https://testssl.sh/",
):
    """Stub the engine module's run_command, and have it write ``payload`` to
    the --jsonfile path the engine chose - the way the real tool would.

    The version probe is stubbed as well. Draining a banner out of a process is
    the executor's business (see test_exec.py), and leaving it live here would
    make every test in this file spawn the real testssl binary.
    """
    calls: list[dict] = []

    def fake_run_command(
        argv, *, timeout_seconds, max_output_bytes, should_cancel=None, on_output=None, **kwargs
    ):
        calls.append({"argv": list(argv), "timeout_seconds": timeout_seconds})
        if payload is not None:
            json_path = Path(argv[list(argv).index("--jsonfile") + 1])
            json_path.write_bytes(payload)
        return CommandResult(
            argv=list(argv),
            exit_code=exit_code,
            stdout="",
            stderr="",
            duration_ms=10,
            timed_out=timed_out,
            cancelled=cancelled,
            truncated=truncated,
        )

    monkeypatch.setattr("app.engines.tls_config.run_command", fake_run_command)
    monkeypatch.setattr("app.engines.tls_config.tool_version", lambda argv, **kwargs: version)
    return calls


def _facts(result, fact_type):
    return [f for f in result.facts if f.fact_type == fact_type]


def _by_key(result):
    return {f.key: f for f in result.facts}


# ------------------------------------------------------------------- protocols --


def test_protocols_offered_and_not_offered_are_read_from_the_capture(monkeypatch, tmp_path):
    _stub_testssl(monkeypatch, WEAKTLS.read_bytes())
    ctx, _ = _ctx(tmp_path)
    result = tls_config.run(_target(), TlsConfigParams(), ctx)

    protocols = {f.key: f for f in _facts(result, "tls_protocol")}
    assert set(protocols) == {"SSLv2", "SSLv3", "TLS1", "TLS1_1", "TLS1_2", "TLS1_3"}

    assert protocols["SSLv2"].value["offered"] is False
    assert protocols["SSLv3"].value["offered"] is False
    # "offered (deprecated)" is still offered - the deprecation is the finding.
    assert protocols["TLS1"].value["offered"] is True
    assert protocols["TLS1_1"].value["offered"] is True
    assert protocols["TLS1_2"].value["offered"] is True
    assert protocols["TLS1_3"].value["offered"] is False

    assert protocols["TLS1"].value["label"] == "TLSv1.0"
    assert all(f.confidence == 1.0 for f in protocols.values())
    assert "protocols offered: TLSv1.0, TLSv1.1, TLSv1.2" in " ".join(result.notes)


def test_an_unreadable_protocol_result_is_zero_confidence_and_null(monkeypatch, tmp_path):
    """A check that was skipped or phrased differently must not be read as
    'not offered'."""
    _stub_testssl(monkeypatch, EDGE_CASES.read_bytes())
    ctx, _ = _ctx(tmp_path)
    result = tls_config.run(_target(), TlsConfigParams(), ctx)

    fact = _by_key(result)["TLS1_3"]
    assert fact.value["offered"] is None
    assert fact.value["offered"] is not False
    assert fact.confidence == 0.0
    assert "unreadable protocol result" in fact.detail


# ---------------------------------------------------------------------- ciphers --


def test_the_null_cipher_columns_are_absences_not_the_string_none(monkeypatch, tmp_path):
    """testssl prints an unset field as the literal string "None". A NULL
    cipher genuinely has no encryption algorithm and no bit length; left as
    strings they would read as values that merely happen not to be "AES"."""
    _stub_testssl(monkeypatch, WEAKTLS.read_bytes())
    ctx, _ = _ctx(tmp_path)
    result = tls_config.run(_target(), TlsConfigParams(), ctx)

    facts = _by_key(result)
    null_cipher = facts["cipher-tls1_x01"]
    assert null_cipher.value["kind"] == "supported"
    assert null_cipher.value["openssl_name"] == "NULL-MD5"
    assert null_cipher.value["hex_code"] == "x01"
    assert null_cipher.value["encryption"] is None
    assert null_cipher.value["bits"] is None
    assert null_cipher.value["key_exchange"] == "RSA"
    assert null_cipher.value["iana_name"] == "TLS_RSA_WITH_NULL_MD5"
    assert null_cipher.value["severity"] == "CRITICAL"
    assert null_cipher.confidence == 1.0
    # The columns that legitimately carry data still do.
    assert null_cipher.value["version"] == "TLSv1"


def test_a_normal_cipher_parses_all_of_its_columns(monkeypatch, tmp_path):
    _stub_testssl(monkeypatch, WEAKTLS.read_bytes())
    ctx, _ = _ctx(tmp_path)
    result = tls_config.run(_target(), TlsConfigParams(), ctx)

    fact = _by_key(result)["cipher-tls1_x2f"]
    assert fact.value["version"] == "TLSv1"
    assert fact.value["hex_code"] == "x2f"
    assert fact.value["openssl_name"] == "AES128-SHA"
    assert fact.value["key_exchange"] == "RSA"
    assert fact.value["encryption"] == "AES"
    assert fact.value["bits"] == 128
    assert fact.value["iana_name"] == "TLS_RSA_WITH_AES_128_CBC_SHA"
    assert fact.value["parsed"] is True
    assert fact.confidence == 1.0


def test_cipher_classes_report_offered_and_not_offered(monkeypatch, tmp_path):
    _stub_testssl(monkeypatch, WEAKTLS.read_bytes())
    ctx, _ = _ctx(tmp_path)
    result = tls_config.run(_target(), TlsConfigParams(), ctx)

    facts = _by_key(result)
    null_class = facts["cipherlist_NULL"]
    assert null_class.value["kind"] == "class"
    assert null_class.value["cipher_class"] == "NULL"
    assert null_class.value["offered"] is True
    assert null_class.value["severity"] == "CRITICAL"

    assert facts["cipherlist_STRONG_FS"].value["offered"] is False
    assert facts["cipherlist_STRONG_FS"].value["severity"] == "MEDIUM"
    assert facts["cipherlist_EXPORT"].value["offered"] is False


def test_cipher_order_records_the_servers_preference(monkeypatch, tmp_path):
    _stub_testssl(monkeypatch, WEAKTLS.read_bytes())
    ctx, _ = _ctx(tmp_path)
    result = tls_config.run(_target(), TlsConfigParams(), ctx)

    fact = _by_key(result)["cipher_order-tls1"]
    assert fact.value["kind"] == "order"
    assert fact.value["protocol"] == "tls1"
    assert fact.value["preference"] == "server"


def test_a_cipher_line_that_cannot_be_split_is_zero_confidence(monkeypatch, tmp_path):
    _stub_testssl(monkeypatch, EDGE_CASES.read_bytes())
    ctx, _ = _ctx(tmp_path)
    result = tls_config.run(_target(), TlsConfigParams(), ctx)

    fact = _by_key(result)["cipher-tls1_x01"]
    assert fact.value["parsed"] is False
    assert fact.confidence == 0.0
    assert "could not be split" in fact.detail


# ----------------------------------------------------------------- certificates --


def test_the_1024_bit_key_is_flagged_weak(monkeypatch, tmp_path):
    _stub_testssl(monkeypatch, WEAKTLS.read_bytes())
    ctx, _ = _ctx(tmp_path)
    result = tls_config.run(_target(), TlsConfigParams(), ctx)

    fact = _by_key(result)["cert_keySize"]
    assert fact.value["property"] == "keySize"
    assert fact.value["algorithm"] == "RSA"
    assert fact.value["bits"] == 1024
    assert fact.value["weak"] is True
    assert fact.value["severity"] == "MEDIUM"


def test_other_certificate_properties_are_reported(monkeypatch, tmp_path):
    _stub_testssl(monkeypatch, WEAKTLS.read_bytes())
    ctx, _ = _ctx(tmp_path)
    result = tls_config.run(_target(), TlsConfigParams(), ctx)

    facts = _by_key(result)
    assert facts["cert_expirationStatus"].value["days"] == 1
    assert facts["cert_expirationStatus"].value["expired"] is False
    assert facts["cert_trust"].value["trusted"] is False
    assert facts["cert_commonName"].value["finding"] == "lab-weaktls.local"
    # The PEM body is evidence, not a fact.
    assert "cert" not in facts


# -------------------------------------------------------------- vulnerabilities --


def test_readable_vulnerability_verdicts(monkeypatch, tmp_path):
    _stub_testssl(monkeypatch, WEAKTLS.read_bytes())
    ctx, _ = _ctx(tmp_path)
    result = tls_config.run(_target(), TlsConfigParams(), ctx)

    facts = _by_key(result)
    assert facts["heartbleed"].value["vulnerable"] is False
    assert facts["heartbleed"].confidence == 1.0
    # "VULNERABLE -- but also supports higher protocols..." is still vulnerable.
    assert facts["BEAST"].value["vulnerable"] is True
    # "potentially vulnerable" counts as vulnerable, not as a pass.
    assert facts["LUCKY13"].value["vulnerable"] is True
    assert facts["ROBOT"].value["cve"][0] == "CVE-2017-17382"
    assert len(facts["ROBOT"].value["cve"]) == 9


def test_an_unreadable_verdict_is_zero_confidence_and_null_not_false(monkeypatch, tmp_path):
    """Only an explicit statement becomes True or False. The capture contains
    vulnerability entries whose finding (a hint, or a bare cipher list) carries
    no verdict word; those must be reported as unreadable so the evaluator can
    return INCONCLUSIVE instead of an assertion passing on a placeholder."""
    _stub_testssl(monkeypatch, WEAKTLS.read_bytes())
    ctx, _ = _ctx(tmp_path)
    result = tls_config.run(_target(), TlsConfigParams(), ctx)

    facts = _by_key(result)
    for key in ("DROWN_hint", "LOGJAM-common_primes", "BEAST_CBC_TLS1"):
        fact = facts[key]
        assert fact.value["vulnerable"] is None, key
        assert fact.confidence == 0.0, key
        assert "unreadable verdict" in fact.detail
        # The raw finding is still recorded for a human.
        assert fact.value["finding"]

    # DROWN itself is readable, as a contrast in the same run.
    assert facts["DROWN"].value["vulnerable"] is False
    assert facts["DROWN"].confidence == 1.0


def test_the_vulnerable_summary_lists_only_readable_true_verdicts(monkeypatch, tmp_path):
    _stub_testssl(monkeypatch, WEAKTLS.read_bytes())
    ctx, _ = _ctx(tmp_path)
    result = tls_config.run(_target(), TlsConfigParams(), ctx)
    assert "vulnerable to: BEAST, LUCKY13" in " ".join(result.notes)


# ------------------------------------------------------------------- accounting --


def test_every_entry_is_either_modelled_or_counted(monkeypatch, tmp_path):
    """The run must never be quietly smaller than the tool's own output."""
    payload = WEAKTLS.read_bytes()
    entries = json.loads(payload)
    _stub_testssl(monkeypatch, payload)
    ctx, _ = _ctx(tmp_path)
    result = tls_config.run(_target(), TlsConfigParams(), ctx)

    assert len(entries) == 162
    assert len(result.facts) == 74
    assert any("88 testssl entry/entries were not modelled" in note for note in result.notes)

    # Every fact type emitted is one the catalogue declares.
    from app.engines.catalogue import fact_types_for

    assert {f.fact_type for f in result.facts} == fact_types_for("tls_config")


def test_the_raw_json_is_kept_as_evidence(monkeypatch, tmp_path):
    payload = WEAKTLS.read_bytes()
    _stub_testssl(monkeypatch, payload)
    ctx, _ = _ctx(tmp_path)
    result = tls_config.run(_target(), TlsConfigParams(), ctx)

    assert len(result.artifacts) == 1
    artifact = result.artifacts[0]
    assert artifact.filename == "testssl.json"
    assert artifact.content_type == "application/json"
    assert artifact.data == payload


def test_no_json_produced_while_the_tool_is_missing_is_unavailable(monkeypatch, tmp_path):
    _stub_testssl(monkeypatch, None, exit_code=None)
    ctx, _ = _ctx(tmp_path)
    with pytest.raises(EngineUnavailable):
        tls_config.run(_target(), TlsConfigParams(), ctx)


def test_no_json_produced_by_a_run_that_exited_is_an_error(monkeypatch, tmp_path):
    _stub_testssl(monkeypatch, None, exit_code=1)
    ctx, _ = _ctx(tmp_path)
    with pytest.raises(EngineError, match="produced no JSON") as raised:
        tls_config.run(_target(), TlsConfigParams(), ctx)
    # The command still ran, so what it ran as is recorded with the failure.
    assert raised.value.result is not None
    assert raised.value.result.tool_versions["testssl"]


def test_the_tool_version_is_recorded_with_the_result(monkeypatch, tmp_path):
    """Which build produced an observation is part of the observation: a year
    later the finding has to be defensible without re-running the tool."""
    _stub_testssl(monkeypatch, WEAKTLS.read_bytes(), version="testssl version 3.2.4 from https://testssl.sh/")
    ctx, _ = _ctx(tmp_path)
    result = tls_config.run(_target(), TlsConfigParams(), ctx)
    assert result.tool_versions["testssl"] == "testssl version 3.2.4 from https://testssl.sh/"


def test_a_run_stopped_at_its_budget_says_so(monkeypatch, tmp_path):
    """testssl writes a JSON stub before it starts scanning and rewrites it as
    checks land, so a run killed at the timeout leaves a file containing none
    of the entries this engine models - it reads "Scan interrupted". Reporting
    that document as unmodelled would bury both the cause and the fix."""
    stub = json.dumps([{"id": "scanTime", "finding": "Scan interrupted"}]).encode()
    _stub_testssl(monkeypatch, stub, exit_code=None, timed_out=True)
    ctx, _ = _ctx(tmp_path, timeout_seconds=120)

    with pytest.raises(EngineError, match="120s budget") as raised:
        tls_config.run(_target(), TlsConfigParams(max_wait_seconds=120), ctx)

    assert "raise the test's timeout" in str(raised.value)
    assert raised.value.result is not None


def test_a_cancelled_run_before_the_first_check_is_reported_as_cancelled(monkeypatch, tmp_path):
    stub = json.dumps([{"id": "scanTime", "finding": "Scan interrupted"}]).encode()
    _stub_testssl(monkeypatch, stub, exit_code=None, cancelled=True)
    ctx, _ = _ctx(tmp_path)

    with pytest.raises(EngineError, match="cancelled before it reported"):
        tls_config.run(_target(), TlsConfigParams(), ctx)


def test_invalid_json_is_an_error(monkeypatch, tmp_path):
    _stub_testssl(monkeypatch, b"{not json")
    ctx, _ = _ctx(tmp_path)
    with pytest.raises(EngineError, match="could not be parsed"):
        tls_config.run(_target(), TlsConfigParams(), ctx)


def test_json_that_is_not_a_list_is_an_error(monkeypatch, tmp_path):
    _stub_testssl(monkeypatch, b'{"finding": "not a list"}')
    ctx, _ = _ctx(tmp_path)
    with pytest.raises(EngineError, match="expected a list"):
        tls_config.run(_target(), TlsConfigParams(), ctx)


def test_a_document_with_nothing_modelled_is_an_error(monkeypatch, tmp_path):
    """If nothing in the JSON is understood, raising marks the run error
    rather than letting 'no facts' look like a control that held."""
    payload = json.dumps([{"id": "ALPN", "finding": "h2"}]).encode()
    _stub_testssl(monkeypatch, payload)
    ctx, _ = _ctx(tmp_path)
    with pytest.raises(EngineError, match="no entry this engine models"):
        tls_config.run(_target(), TlsConfigParams(), ctx)


def test_a_nonzero_exit_with_json_is_still_parsed_and_noted(monkeypatch, tmp_path):
    """testssl often exits nonzero for a target it still managed to scan."""
    _stub_testssl(monkeypatch, WEAKTLS.read_bytes(), exit_code=1)
    ctx, _ = _ctx(tmp_path)
    result = tls_config.run(_target(), TlsConfigParams(), ctx)
    assert result.facts
    assert any("testssl exited 1" in note for note in result.notes)


def test_truncated_tool_output_does_not_block_the_json(monkeypatch, tmp_path):
    """The JSON lives in a file, so a capped stdout is not an incomplete
    result - unlike nmap or nuclei, whose facts come from the stream."""
    _stub_testssl(monkeypatch, WEAKTLS.read_bytes(), truncated=True)
    ctx, _ = _ctx(tmp_path)
    result = tls_config.run(_target(), TlsConfigParams(), ctx)
    assert result.facts


# ------------------------------------------------------------------------- argv --


def test_argv_pins_the_address_and_disables_dns(tmp_path):
    json_path = tmp_path / "testssl.json"
    argv = tls_config.build_argv(_target(), TlsConfigParams(), json_path)

    assert argv[0] == "testssl"
    assert argv[argv.index("--ip") + 1] == "127.0.0.1"
    assert argv[argv.index("--nodns") + 1] == "none"
    assert argv[argv.index("--jsonfile") + 1] == str(json_path)
    assert argv[-1] == "lab-weaktls.local:8443"
    assert "--vulnerable" not in argv
    assert "--severity" not in argv, "a severity floor would hide entries from assertions"


def test_argv_optionally_adds_vulnerability_checks_and_starttls():
    argv = tls_config.build_argv(
        _target(),
        TlsConfigParams(check_vulnerabilities=True, starttls="smtp"),
        Path("/tmp/testssl.json"),
    )
    assert "--vulnerable" in argv
    assert argv[argv.index("-t") + 1] == "smtp"


def test_the_run_budget_is_the_smaller_of_runner_timeout_and_max_wait(monkeypatch, tmp_path):
    calls = _stub_testssl(monkeypatch, WEAKTLS.read_bytes())

    # Runner timeout is the binding constraint here.
    tls_config.run(_target(), TlsConfigParams(max_wait_seconds=240), _ctx(tmp_path, timeout_seconds=100)[0])
    assert calls[-1]["timeout_seconds"] == 100

    # ... and max_wait_seconds here.
    calls.clear()
    tls_config.run(_target(), TlsConfigParams(max_wait_seconds=240), _ctx(tmp_path, timeout_seconds=600)[0])
    assert calls[-1]["timeout_seconds"] == 240


# ------------------------------------------------- certificate fact readings --


@pytest.mark.parametrize(
    ("entry_id", "boolean"),
    [
        ("cert_keySize", "weak"),
        ("cert_trust", "trusted"),
        ("cert_expirationStatus", "expired"),
    ],
)
def test_unreadable_certificate_properties_are_inconclusive(monkeypatch, tmp_path, entry_id, boolean):
    payload = json.dumps(
        [{"id": entry_id, "finding": "--", "severity": "INFO"}]
    ).encode()
    _stub_testssl(monkeypatch, payload)
    ctx, _ = _ctx(tmp_path)
    result = tls_config.run(_target(), TlsConfigParams(), ctx)

    fact = result.facts[0]
    assert fact.value[boolean] is None
    assert fact.confidence == 0.0


def test_a_fact_value_carries_nothing_but_plain_data(monkeypatch, tmp_path):
    """Every fact value must be JSON-serialisable - it is stored in a JSONB
    column and read back by the assertion evaluator."""
    _stub_testssl(monkeypatch, WEAKTLS.read_bytes())
    ctx, _ = _ctx(tmp_path)
    result = tls_config.run(_target(), TlsConfigParams(), ctx)
    for fact in result.facts:
        json.dumps(dataclasses.asdict(fact))
