"""Template-based checks, restricted to a shape that cannot leave the target.

nuclei is easily the most powerful tool here and also the easiest to turn into
something that reaches outside the authorized scope, so the command line is
narrow on several axes at once:

* ``-pt http`` restricts the run to HTTP templates. That single flag excludes
  the ``file`` protocol (which reads files on the worker), the ``code`` and
  ``javascript`` protocols (which execute code on the worker), ``dns`` (which
  queries resolvers rather than the target) and the rest of the protocol set;
* ``-ni`` disables interactsh, so no template can ask an external server to
  confirm an out-of-band callback;
* ``-duc`` keeps template auto-update off, so a run cannot pull new templates
  from the internet;
* the target is passed as the pinned address with the operator's hostname in a
  ``Host`` header, so nuclei has no name to resolve;
* redirects are left at nuclei's default of not being followed, so a redirect
  to another host is reported rather than chased.

Findings arrive as JSONL on stdout. That matters for a cancelled or timed-out
run: the findings produced before the stop are already in the captured stream,
where an exporter that only writes at exit would leave nothing behind.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from app.engines._http import scheme_for
from app.engines.context import (
    EngineContext,
    EngineError,
    EngineResult,
    EngineUnavailable,
    FactDraft,
    TargetView,
)
from app.runner.exec import run_command, tool_version

# Where nuclei keeps its templates. The executor hands every tool a scrubbed
# environment with a HOME that does not exist, so nuclei cannot find its own
# per-user configuration or templates unless both are supplied explicitly. That
# scrubbing is deliberate: a developer's personal nuclei config can carry proxy
# settings and third-party provider keys, and a validation run must not inherit
# either.
DEFAULT_TEMPLATES_DIR = "/var/lib/valtros/nuclei-templates"
TEMPLATES_ENV_VAR = "VALTROS_NUCLEI_TEMPLATES"


def templates_dir() -> Path:
    return Path(os.environ.get(TEMPLATES_ENV_VAR, DEFAULT_TEMPLATES_DIR))


def _require_templates(directory: Path) -> Path:
    """Refuse to run with no templates rather than reporting no findings.

    An empty template set produces an empty run, and an empty run against a
    control reads exactly like a control that held.
    """
    if not directory.is_dir() or next(directory.rglob("*.yaml"), None) is None:
        raise EngineUnavailable(
            f"no nuclei templates at {directory}. Populate them once while this "
            f"host has network access - `nuclei -update-templates -t {directory}` "
            f"- after which runs work offline."
        )
    return directory


def build_argv(target: TargetView, params, templates: Path) -> list[str]:
    scheme = scheme_for(target)
    default_port = 443 if scheme == "https" else 80
    url = f"{scheme}://{target.ip}:{target.port}" if target.port else f"{scheme}://{target.ip}"

    argv = [
        "nuclei",
        "-u", url,
        "-pt", "http",  # HTTP templates only: no file, code, javascript or dns
        "-t", str(templates),  # explicit: the run's HOME holds no template tree
        "-ni",  # no out-of-band callbacks through interactsh
        "-duc",  # no template auto-update
        "-j",  # findings as JSONL on stdout
        "-or",  # omit request/response pairs, which would swamp the byte cap
        "-ot",  # omit the encoded template blob, which is of no use in a fact
        "-silent",
        "-nc",  # no ANSI colour
        "-rl", str(params.rate_limit),
        "-timeout", "10",
        "-retries", "1",
        "-severity", ",".join(params.severities),
        "-tags", ",".join(params.template_tags),
    ]
    if target.hostname and target.hostname != target.ip:
        # The connection goes to the pinned address; the name the operator
        # registered still reaches the application through the Host header.
        authority = target.authority(default_port=default_port)
        argv += ["-H", f"Host: {authority}"]
    return argv


def _fact_from_finding(finding: dict[str, Any], target: TargetView) -> FactDraft | None:
    template_id = finding.get("template-id")
    if not template_id:
        return None

    info = finding.get("info") or {}
    classification = info.get("classification") or {}
    template_id = str(template_id)
    matcher = finding.get("matcher-name")

    return FactDraft(
        fact_type="nuclei_finding",
        subject=target.hostname,
        key=f"{template_id}:{matcher or 'match'}",
        detail=info.get("name"),
        value={
            "template_id": template_id,
            "template_name": info.get("name"),
            "template_path": finding.get("template"),
            "matcher_name": matcher,
            "severity": info.get("severity"),
            "type": finding.get("type"),
            "matched_at": finding.get("matched-at"),
            "url": finding.get("url"),
            "host": finding.get("host"),
            "port": finding.get("port"),
            "scheme": finding.get("scheme"),
            "ip": finding.get("ip"),
            "timestamp": finding.get("timestamp"),
            "description": info.get("description"),
            "tags": info.get("tags") or [],
            "cve": classification.get("cve-id") or [],
            "cwe": classification.get("cwe-id") or [],
            "references": info.get("reference") or [],
            "extracted_results": finding.get("extracted-results") or [],
        },
    )


def _parse_stream(stdout: str, target: TargetView, ctx: EngineContext) -> tuple[list[FactDraft], int]:
    facts: list[FactDraft] = []
    skipped = 0

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            finding = json.loads(line)
        except json.JSONDecodeError:
            # nuclei interleaves non-JSON progress lines with -silent off, and a
            # template can emit its own output. An unparseable line is dropped
            # but counted, so it can never look like a finding that was assessed.
            skipped += 1
            ctx.emit("warning", f"ignored a non-JSON line from nuclei: {line[:160]}")
            continue
        if not isinstance(finding, dict):
            skipped += 1
            continue
        fact = _fact_from_finding(finding, target)
        if fact is None:
            skipped += 1
            continue
        facts.append(fact)

    return facts, skipped


def run(target: TargetView, params, ctx: EngineContext) -> EngineResult:
    templates = _require_templates(templates_dir())
    argv = build_argv(target, params, templates)
    ctx.emit(
        "info",
        f"nuclei with tags {','.join(params.template_tags)} against {target.ip}:{target.port}",
    )

    command = run_command(
        argv,
        timeout_seconds=ctx.timeout_seconds,
        max_output_bytes=ctx.max_output_bytes,
        should_cancel=ctx.should_cancel,
        on_output=ctx.on_output,
        # nuclei writes a config directory and a template cache on startup and
        # will not run at all if it cannot. Pointing HOME at the run's own
        # workdir gives it somewhere disposable to do that, and keeps the run
        # away from any operator's personal nuclei configuration - which can
        # name a proxy or carry provider keys, neither of which belongs on a
        # validation run.
        env_extra={"HOME": str(ctx.workdir), "TMPDIR": str(ctx.workdir)},
    )
    result = EngineResult(argv=command.argv, exit_code=command.exit_code)
    result.stdout = command.stdout
    result.stderr = command.stderr
    if version := tool_version(["nuclei", "-version"]):
        result.tool_versions["nuclei"] = version

    if command.truncated:
        # Findings that were cut off are findings that will never be evaluated,
        # and a control with no finding against it reads as a control that held.
        raise EngineError(
            "nuclei's output exceeded the capture limit and was cut off, so the "
            "finding set is incomplete; raise the run's output budget and retry",
            result=result,
        )
    if command.exit_code is None:
        raise EngineUnavailable(f"nuclei could not be run: {command.failure_reason()}")
    if command.exit_code != 0 and not command.stdout.strip():
        raise EngineError(f"nuclei {command.failure_reason()}", result=result)

    facts, skipped = _parse_stream(command.stdout, target, ctx)
    result.facts.extend(facts)

    if command.cancelled:
        result.incomplete = True
        result.incomplete_reason = (
            "nuclei was cancelled; only the findings reported before the stop are present"
        )
        result.notes.append("cancelled; only the findings reported before the stop are present")
    if command.timed_out:
        result.incomplete = True
        result.incomplete_reason = "nuclei timed out; the finding set may be incomplete"
        result.notes.append("timed out; the finding set may be incomplete")
    if skipped:
        result.notes.append(f"{skipped} output line(s) were not parseable findings")

    by_severity: dict[str, int] = {}
    for fact in facts:
        severity = str(fact.value.get("severity") or "unknown")
        by_severity[severity] = by_severity.get(severity, 0) + 1
    result.notes.append(
        f"{len(facts)} finding(s)"
        + (
            ": " + ", ".join(f"{count} {sev}" for sev, count in sorted(by_severity.items()))
            if by_severity
            else ""
        )
    )
    return result
