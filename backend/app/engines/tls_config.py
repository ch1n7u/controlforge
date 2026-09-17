"""TLS configuration, from testssl.sh's JSON output.

Two flags carry the scope guarantee. ``--ip`` makes testssl connect to the
address the scope layer already authorized instead of resolving the hostname
again, and ``--nodns none`` stops it from making DNS lookups at all. The
hostname is still passed as the URI host, so SNI and the certificate checks
evaluate the name the operator registered, which is what those checks are about.

The parsing is grouped by what an assertion can sensibly ask:

* ``tls_protocol``    - is a protocol version offered at all;
* ``tls_cipher``      - one fact per offered cipher, plus the aggregate cipher
  classes and the server's preference order;
* ``tls_certificate`` - certificate posture, one fact per property;
* ``tls_vulnerability`` - one fact per named attack check, with the verdict and
  the CVEs.

Every entry testssl produced is accounted for. Entries that carry information
this engine does not model (browser client simulations, grading letters, the
PEM body) are counted in a note rather than turned into facts, so the run is
never quietly smaller than the tool's own output.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from app.engines.context import (
    ArtifactDraft,
    EngineContext,
    EngineError,
    EngineResult,
    EngineUnavailable,
    FactDraft,
    TargetView,
)
from app.runner.exec import run_command, tool_version

# Server-side facts a run reports even when nothing else is asked for.
PROTOCOL_IDS = ("SSLv2", "SSLv3", "TLS1", "TLS1_1", "TLS1_2", "TLS1_3")

PROTOCOL_LABELS = {
    "SSLv2": "SSLv2",
    "SSLv3": "SSLv3",
    "TLS1": "TLSv1.0",
    "TLS1_1": "TLSv1.1",
    "TLS1_2": "TLSv1.2",
    "TLS1_3": "TLSv1.3",
}

# Attack checks, named by testssl's id. The CVE attribute is used as a second
# signal, so a check added by a future testssl release is still modelled.
VULNERABILITY_IDS = frozenset(
    {
        "heartbleed",
        "CCS",
        "ticketbleed",
        "ROBOT",
        "CRIME",
        "BREACH",
        "POODLE",
        "SWEET32",
        "FREAK",
        "LOGJAM",
        "LOGJAM-common",
        "LUCKY13",
        "winshock",
        "RC4",
        "DROWN",
        "BEAST",
        "fallback",
        "GOLDENDOODLE",
        "zombie",
    }
)

CERT_PREFIX = "cert_"
CIPHER_PREFIX = "cipher-"
CIPHER_CLASS_PREFIX = "cipherlist_"
CIPHER_ORDER_PREFIX = "cipher_order-"

_COLUMN_SPLIT = re.compile(r"\s{2,}")
_HEX_SUFFIX = re.compile(r"_x([0-9a-fA-F]+)$")
_PARENTHESISED_INT = re.compile(r"\((\d+)\)")


def build_argv(target: TargetView, params, json_path: Path) -> list[str]:
    port = target.port or 443
    argv = [
        "testssl",
        "--quiet",
        "--color", "0",
        "--warnings", "batch",
        # Connect to the authorized address; never resolve the name again.
        "--ip", target.ip,
        "--nodns", "none",
        "--connect-timeout", "10",
        "--openssl-timeout", "15",
        "--jsonfile", str(json_path),
    ]
    if params.starttls:
        argv += ["-t", params.starttls]
    if params.check_vulnerabilities:
        argv.append("--vulnerable")
    argv.append(f"{target.hostname}:{port}")
    return argv


def _verdict(finding: str) -> bool | None:
    """Read testssl's prose into a verdict, or admit it cannot be read.

    Only an explicit statement becomes True or False. A check that was skipped,
    or that phrased its answer in a way this parser does not know, comes back as
    None and is reported with zero confidence - an unreadable answer must not
    become a pass.
    """
    lowered = finding.lower()
    if "not vulnerable" in lowered:
        return False
    if "vulnerable" in lowered:
        return True
    return None


def _protocol_fact(entry: dict[str, Any], target: TargetView) -> FactDraft:
    entry_id = entry["id"]
    finding = str(entry.get("finding", ""))
    lowered = finding.lower()
    if lowered.startswith("offered"):
        offered: bool | None = True
    elif lowered.startswith("not offered"):
        offered = False
    else:
        offered = None

    return FactDraft(
        fact_type="tls_protocol",
        subject=target.hostname,
        key=entry_id,
        confidence=1.0 if offered is not None else 0.0,
        detail=None if offered is not None else f"unreadable protocol result: {finding!r}",
        value={
            "protocol": entry_id,
            "label": PROTOCOL_LABELS.get(entry_id, entry_id),
            "offered": offered,
            "severity": entry.get("severity"),
            "finding": finding,
        },
    )


def _clean_column(value: str) -> str | None:
    """testssl prints an unset field as the literal string "None" or "-".

    A NULL cipher genuinely has no bit length and no encryption algorithm, and a
    fact has to say that as an absence. Left as the string "None" it would read
    as a value that merely happens not to equal "AES".
    """
    return None if value in ("None", "-", "") else value


def _parse_cipher_columns(finding: str) -> dict[str, Any]:
    """Split a cipher line into its columns.

    The layout is ``<version> <hex code> <openssl name> <kx> <enc> <bits>
    <IANA name>`` padded with runs of spaces, so splitting on two-or-more spaces
    keeps the columns intact. The tail is read positionally from both ends
    because the bit length and IANA name are the fields an assertion wants, and
    they are the ones a future release is most likely to vary.
    """
    columns = [part.strip() for part in _COLUMN_SPLIT.split(finding.strip()) if part.strip()]
    parsed: dict[str, Any] = {"columns": columns, "parsed": len(columns) >= 3}
    if len(columns) >= 3:
        parsed["version"] = columns[0]
        parsed["hex_code"] = columns[1]
        parsed["openssl_name"] = columns[2]
    rest = [cleaned for part in columns[3:] if (cleaned := _clean_column(part)) is not None]
    parsed["bits"] = next((int(part) for part in rest if part.isdigit()), None)
    parsed["iana_name"] = (
        rest[-1] if rest and rest[-1].upper().startswith(("TLS_", "SSL_")) else None
    )
    tail = rest[:-1] if parsed["iana_name"] else rest
    parsed["key_exchange"] = tail[0] if tail else None
    parsed["encryption"] = tail[1] if len(tail) > 1 else None
    return parsed


def _cipher_facts(entry: dict[str, Any], target: TargetView) -> FactDraft | None:
    entry_id = entry["id"]
    finding = str(entry.get("finding", ""))
    severity = entry.get("severity")

    if entry_id.startswith(CIPHER_ORDER_PREFIX):
        preference = finding.strip().lower()
        return FactDraft(
            fact_type="tls_cipher",
            subject=target.hostname,
            key=entry_id,
            value={
                "kind": "order",
                "protocol": entry_id[len(CIPHER_ORDER_PREFIX) :],
                "preference": preference if preference in ("server", "client") else None,
                "severity": severity,
                "finding": finding,
            },
        )

    if entry_id.startswith(CIPHER_CLASS_PREFIX):
        # Aggregate classes: NULL, EXPORT, LOW, OBSOLETED, STRONG_FS and so on.
        # testssl answers some of these with a plain offered / not offered and
        # others with a sentence, so anything else stays unread.
        lowered = finding.lower().strip()
        if lowered.startswith("offered") and not lowered.startswith("not offered"):
            offered: bool | None = True
        elif lowered.startswith("not offered"):
            offered = False
        else:
            offered = None
        return FactDraft(
            fact_type="tls_cipher",
            subject=target.hostname,
            key=entry_id,
            confidence=1.0 if offered is not None else 0.0,
            detail=None if offered is not None else f"unreadable cipher class: {finding!r}",
            value={
                "kind": "class",
                "cipher_class": entry_id[len(CIPHER_CLASS_PREFIX) :],
                "offered": offered,
                "severity": severity,
                "finding": finding,
            },
        )

    if entry_id.startswith(CIPHER_PREFIX):
        match = _HEX_SUFFIX.search(entry_id)
        value: dict[str, Any] = {
            "kind": "supported",
            "hex_code": match.group(1) if match else None,
            "severity": severity,
            "finding": finding,
            **_parse_cipher_columns(finding),
        }
        if not value["parsed"]:
            return FactDraft(
                fact_type="tls_cipher",
                subject=target.hostname,
                key=entry_id,
                confidence=0.0,
                detail=f"cipher line could not be split into columns: {finding!r}",
                value=value,
            )
        return FactDraft(
            fact_type="tls_cipher",
            subject=target.hostname,
            key=entry_id,
            value=value,
        )

    return None


def _certificate_fact(entry: dict[str, Any], target: TargetView) -> FactDraft | None:
    entry_id = entry["id"]
    if entry_id == "cert":
        # The PEM body itself belongs in the evidence, not in a fact: it is
        # large, and every question worth asking about it is answered by the
        # fingerprint and property entries that accompany it.
        return None

    finding = str(entry.get("finding", "")).strip()
    value: dict[str, Any] = {
        "property": entry_id[len(CERT_PREFIX) :],
        "severity": entry.get("severity"),
        "finding": finding,
    }

    # An unreadable value leaves the property ``None`` rather than ``False``,
    # and the fact is marked unobserved. A certificate test that answers "--"
    # has said nothing, and a fact claiming "not weak" or "not expired" on that
    # basis would let an assertion pass on an observation nobody made.
    unobserved = False

    if entry_id == "cert_keySize":
        bits = next(
            (int(part) for part in finding.split() if part.isdigit()),
            None,
        )
        value["bits"] = bits
        value["algorithm"] = finding.split()[0] if finding.split() else None
        if bits is None:
            value["weak"] = None
            unobserved = True
        else:
            value["weak"] = bits < 2048
    elif entry_id == "cert_expirationStatus":
        match = _PARENTHESISED_INT.search(finding)
        value["days"] = int(match.group(1)) if match else None
        lowered = finding.lower()
        if "expired" in lowered:
            value["expired"] = "not expired" not in lowered
        elif value["days"] is not None:
            value["expired"] = value["days"] < 0
        else:
            value["expired"] = None
            unobserved = True
    elif entry_id == "cert_trust":
        lowered = finding.lower()
        if lowered.startswith("ok"):
            value["trusted"] = True
        elif lowered and lowered not in {"--", "-", "none", "unknown"}:
            value["trusted"] = False
        else:
            value["trusted"] = None
            unobserved = True

    return FactDraft(
        fact_type="tls_certificate",
        subject=target.hostname,
        key=entry_id,
        confidence=0.0 if unobserved else 1.0,
        detail=None if not unobserved else f"testssl reported no readable value: {finding!r}",
        value=value,
    )


def _cve_list(raw: Any) -> list[str]:
    """testssl exports one space-separated string here, but not always."""
    if isinstance(raw, list):
        return [str(item) for item in raw]
    if isinstance(raw, str):
        return raw.split()
    return []


def _vulnerability_fact(entry: dict[str, Any], target: TargetView) -> FactDraft:
    finding = str(entry.get("finding", ""))
    verdict = _verdict(finding)
    return FactDraft(
        fact_type="tls_vulnerability",
        subject=target.hostname,
        key=entry["id"],
        confidence=1.0 if verdict is not None else 0.0,
        detail=None if verdict is not None else f"unreadable verdict: {finding!r}",
        value={
            "name": entry["id"],
            "vulnerable": verdict,
            "severity": entry.get("severity"),
            "cve": _cve_list(entry.get("cve")),
            "cwe": entry.get("cwe"),
            "finding": finding,
        },
    )


def _facts_from_entries(entries: list[dict[str, Any]], target: TargetView) -> tuple[list[FactDraft], int]:
    facts: list[FactDraft] = []
    unmodelled = 0

    for entry in entries:
        if not isinstance(entry, dict) or "id" not in entry:
            unmodelled += 1
            continue
        entry_id = str(entry["id"])

        if entry_id in PROTOCOL_IDS:
            facts.append(_protocol_fact(entry, target))
        elif entry_id.startswith((CIPHER_PREFIX, CIPHER_CLASS_PREFIX, CIPHER_ORDER_PREFIX)):
            fact = _cipher_facts(entry, target)
            if fact is None:
                unmodelled += 1
            else:
                facts.append(fact)
        elif entry_id.startswith(CERT_PREFIX) or entry_id == "cert":
            fact = _certificate_fact(entry, target)
            if fact is None:
                unmodelled += 1
            else:
                facts.append(fact)
        elif entry_id in VULNERABILITY_IDS or entry.get("cve"):
            facts.append(_vulnerability_fact(entry, target))
        else:
            unmodelled += 1

    return facts, unmodelled


def run(target: TargetView, params, ctx: EngineContext) -> EngineResult:
    json_path = Path(ctx.workdir) / "testssl.json"
    argv = build_argv(target, params, json_path)
    budget = min(ctx.timeout_seconds, params.max_wait_seconds)
    ctx.emit("info", f"testssl against {target.ip}:{target.port or 443} as {target.hostname}")

    command = run_command(
        argv,
        timeout_seconds=budget,
        max_output_bytes=ctx.max_output_bytes,
        should_cancel=ctx.should_cancel,
        on_output=ctx.on_output,
    )
    result = EngineResult(argv=command.argv, exit_code=command.exit_code)
    result.stdout = command.stdout
    result.stderr = command.stderr
    if version := tool_version(["testssl", "--version"]):
        result.tool_versions["testssl"] = version

    if not json_path.exists():
        if command.exit_code is None:
            raise EngineUnavailable(f"testssl could not be run: {command.failure_reason()}")
        raise EngineError(
            f"testssl produced no JSON output ({command.failure_reason() or 'no reason given'})",
            result=result,
        )

    raw = json_path.read_bytes()
    try:
        entries = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise EngineError(f"testssl's JSON could not be parsed: {exc}", result=result) from exc
    if not isinstance(entries, list):
        raise EngineError(
            f"expected a list of findings from testssl, got {type(entries).__name__}",
            result=result,
        )

    facts, unmodelled = _facts_from_entries(entries, target)
    if not facts:
        # testssl writes a JSON stub before it starts scanning and rewrites it as
        # checks complete, so "a file with no entry this engine models" is what a
        # run that was stopped early leaves behind - it says "Scan interrupted".
        # Reporting the parse rather than the stop would bury the real cause.
        if command.timed_out:
            raise EngineError(
                f"testssl was stopped at its {budget}s budget before it reported any "
                f"check, so there is nothing to evaluate; raise the test's timeout",
                result=result,
            )
        if command.cancelled:
            raise EngineError(
                "testssl was cancelled before it reported any check", result=result
            )
        raise EngineError(
            f"testssl returned no entry this engine models ({len(entries)} entry/entries, "
            f"{command.failure_reason() or 'it exited cleanly'}); nothing to evaluate",
            result=result,
        )
    result.facts.extend(facts)

    result.artifacts.append(
        ArtifactDraft(
            filename="testssl.json",
            data=raw,
            content_type="application/json",
        )
    )

    if command.cancelled:
        result.incomplete = True
        result.incomplete_reason = (
            "testssl was cancelled; the protocols and vulnerabilities list is partial"
        )
        result.notes.append("cancelled; only the tests completed before the stop are present")
    if command.timed_out:
        result.incomplete = True
        result.incomplete_reason = (
            "testssl timed out; the protocols and vulnerabilities list is partial"
        )
        result.notes.append("timed out; the test list may be incomplete")
    if command.exit_code not in (0, None):
        result.notes.append(
            f"testssl exited {command.exit_code}; the JSON it produced was still parsed"
        )
    if unmodelled:
        result.notes.append(
            f"{unmodelled} testssl entry/entries were not modelled as facts and are "
            "kept in the evidence only"
        )

    offered = sorted(
        fact.value["label"] for fact in facts
        if fact.fact_type == "tls_protocol" and fact.value.get("offered")
    )
    result.notes.append(
        "protocols offered: " + (", ".join(offered) if offered else "none")
    )
    vulnerable = sorted(
        fact.value["name"] for fact in facts
        if fact.fact_type == "tls_vulnerability" and fact.value.get("vulnerable")
    )
    if vulnerable:
        result.notes.append("vulnerable to: " + ", ".join(vulnerable))

    return result
