"""Port and service inventory, parsed from nmap's XML.

nmap is invoked as a connect scan because the worker runs unprivileged and raw
sockets are not on the table. Host discovery is skipped: the address handed to
this engine has already been authorized and pinned, so asking nmap to go looking
for hosts would only add packets nobody asked for. ``-n`` is the load-bearing
flag - if nmap were allowed to resolve a name it would reopen exactly the
rebinding window the pinning exists to close.

Two details in the parsed output matter more than they look:

* a service name that came from nmap's ``/etc/services`` table is a guess about
  a port number, not an observation of the target. The fact says which it was
  (``service_method``), so an assertion over a service name can insist on
  ``probed`` rather than accepting a lookup;
* ``-Pn`` makes nmap report the host up without having tested it, with the
  reason ``user-set``. The fact keeps that reason rather than presenting an
  assumption as a finding.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

from app.engines.context import (
    EngineContext,
    EngineError,
    EngineResult,
    FactDraft,
    TargetView,
)
from app.runner.exec import run_command

# When nmap's own budget is shorter than the runner's, a slow target still gets
# an XML document out of nmap instead of being killed mid-scan with nothing to
# show for it.
HOST_TIMEOUT_MARGIN_SECONDS = 20
MIN_HOST_TIMEOUT_SECONDS = 30


def build_argv(target: TargetView, params, ctx: EngineContext) -> list[str]:
    argv = [
        "nmap",
        "-sT",  # connect scan: unprivileged, no raw sockets, no masscan
        "-Pn",  # the target is already authorized and pinned
        "-n",  # never resolve; nmap is handed an address, not a name
        "--reason",
        "-p",
        params.ports,
    ]
    if params.service_detection:
        # ``-sV`` is what turns version detection on; ``--version-light`` only
        # narrows the probe set once it is on. Passing the narrowing flag alone
        # leaves nmap naming services out of its own ports table, which looks
        # like a result and is not one.
        argv.append("-sV")
        if ctx.safe_mode:
            argv.append("--version-light")
    if params.max_rate:
        argv += ["--max-rate", str(params.max_rate)]
    argv += [
        "--host-timeout",
        f"{max(MIN_HOST_TIMEOUT_SECONDS, ctx.timeout_seconds - HOST_TIMEOUT_MARGIN_SECONDS)}s",
        "-oX",
        "-",
        target.ip,
    ]
    return argv


def _service_fact(service: ET.Element | None) -> dict[str, object]:
    if service is None:
        return {
            "service": None,
            "service_method": None,
            "service_confirmed": False,
            "product": None,
            "version": None,
            "extrainfo": None,
            "tunnel": None,
        }
    method = service.get("method")
    return {
        "service": service.get("name"),
        "service_method": method,
        # "table" means the name was looked up from the port number. Only
        # "probed" means the target itself said what it is.
        "service_confirmed": method == "probed",
        "product": service.get("product"),
        "version": service.get("version"),
        "extrainfo": service.get("extrainfo"),
        "tunnel": service.get("tunnel"),
    }


def _parse(xml_text: str) -> ET.Element:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise EngineError(f"nmap produced XML that could not be parsed: {exc}") from exc

    if root.tag != "nmaprun":
        raise EngineError(f"expected an nmaprun document, got <{root.tag}>")
    return root


def _facts_from_root(root: ET.Element, target: TargetView) -> tuple[list[FactDraft], list[str]]:
    facts: list[FactDraft] = []
    warnings: list[str] = []

    for host in root.findall("host"):
        status = host.find("status")
        address = host.find("address")
        addr = address.get("addr", "") if address is not None else ""
        state = status.get("state", "unknown") if status is not None else "unknown"
        reason = status.get("reason", "") if status is not None else ""
        if reason == "user-set":
            warnings.append(
                "host reported up because discovery was skipped (-Pn), not because it answered"
            )

        facts.append(
            FactDraft(
                fact_type="host_state",
                subject=target.hostname,
                key=addr or target.ip,
                value={
                    "address": addr or target.ip,
                    "state": state,
                    "up": state == "up",
                    "reason": reason,
                    "reason_ttl": status.get("reason_ttl") if status is not None else None,
                },
            )
        )

        for port in host.findall("./ports/port"):
            protocol = port.get("protocol", "tcp")
            raw_port = port.get("portid", "0")
            port_state = port.find("state")
            if port_state is None:
                # nmap listed the port but said nothing about it. That is not an
                # observation, and an assertion over it must not read as "closed".
                facts.append(
                    FactDraft(
                        fact_type="port_state",
                        subject=target.hostname,
                        key=f"{protocol}/{raw_port}",
                        confidence=0.0,
                        detail="nmap listed the port without reporting a state",
                        value={
                            "port": int(raw_port),
                            "protocol": protocol,
                            "state": "unknown",
                            "open": None,
                            "reason": None,
                            **_service_fact(port.find("service")),
                        },
                    )
                )
                continue

            observed = port_state.get("state", "unknown")
            facts.append(
                FactDraft(
                    fact_type="port_state",
                    subject=target.hostname,
                    key=f"{protocol}/{raw_port}",
                    value={
                        "port": int(raw_port),
                        "protocol": protocol,
                        "state": observed,
                        "open": observed == "open",
                        "reason": port_state.get("reason"),
                        "reason_ttl": port_state.get("reason_ttl"),
                        **_service_fact(port.find("service")),
                    },
                )
            )

    return facts, warnings


def run(target: TargetView, params, ctx: EngineContext) -> EngineResult:
    argv = build_argv(target, params, ctx)
    ctx.emit("info", f"nmap over ports {params.ports}")

    command = run_command(
        argv,
        timeout_seconds=ctx.timeout_seconds,
        max_output_bytes=ctx.max_output_bytes,
        should_cancel=ctx.should_cancel,
        on_output=ctx.on_output,
    )
    result = EngineResult(argv=command.argv, exit_code=command.exit_code)
    result.stdout = command.stdout
    result.stderr = command.stderr

    if command.truncated:
        raise EngineError(
            "nmap's output exceeded the capture limit and was cut off, so the "
            "scan cannot be read back reliably",
            result=result,
        )
    if not command.ok:
        raise EngineError(f"nmap {command.failure_reason()}", result=result)

    root = _parse(command.stdout)
    if version := root.get("version"):
        result.tool_versions["nmap"] = version
    facts, warnings = _facts_from_root(root, target)
    for warning in warnings:
        ctx.emit("warning", warning)

    if not facts:
        raise EngineError(
            "nmap reported no host; the scan produced nothing to evaluate", result=result
        )

    result.facts.extend(facts)

    open_ports = sorted(
        fact.value["port"] for fact in facts if fact.value.get("open") is True
    )
    result.notes.append(
        f"{len(open_ports)} open port(s): "
        + (", ".join(str(p) for p in open_ports) if open_ports else "none")
    )
    if params.service_detection and ctx.safe_mode:
        result.notes.append(
            "version detection ran with --version-light, so a service may be "
            "identified less precisely than in a full scan"
        )
    if any(f.value.get("service_method") == "table" for f in facts if f.fact_type == "port_state"):
        result.notes.append(
            "some service names came from the local services table, not from the target"
        )
    return result
