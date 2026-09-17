#!/usr/bin/env python3
"""Run one engine against one target and print the facts it produced.

This is the development and verification entry point for the engine layer. It
does **not** go through the API, the queue or the scope authorizer - it takes a
literal address - so it must never be pointed at anything that is not already
authorized. It is a bench tool for "does this parser actually work", not a
runner.

    python scripts/engine_harness.py http_headers 127.0.0.1 --port 8081 --hostname lab.local
    python scripts/engine_harness.py http_exposure 127.0.0.1 --port 8081 \\
        --hostname lab.local --params '{"profile": "dirlist"}'
    python scripts/engine_harness.py nmap 127.0.0.1 --port 8081 --params '{"ports": "8081"}'
    python scripts/engine_harness.py local_baseline 127.0.0.1 --target-type local
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from app.engines.context import EngineContext, EngineError, TargetView  # noqa: E402
from app.engines.runtime import run_engine  # noqa: E402
from app.models.enums import TargetType  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("engine")
    parser.add_argument("address", help="address to connect to (must be authorized)")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--protocol", default="tcp")
    parser.add_argument(
        "--hostname",
        default=None,
        help="name to present in Host/SNI; defaults to the address itself",
    )
    parser.add_argument("--path", default="")
    parser.add_argument(
        "--target-type",
        default=None,
        choices=[t.value for t in TargetType],
        help="defaults to webapp, or local for the local_baseline engine",
    )
    parser.add_argument("--params", default="{}", help="JSON object of engine parameters")
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--max-output-bytes", type=int, default=4 * 1024 * 1024)
    parser.add_argument("--json", action="store_true", help="emit raw JSON only")
    parser.add_argument(
        "--no-safe-mode",
        action="store_true",
        help="disable safe mode; only meaningful for engines that have a lax profile",
    )
    args = parser.parse_args()

    try:
        params = json.loads(args.params)
    except json.JSONDecodeError as exc:
        parser.error(f"--params is not valid JSON: {exc}")

    default_type = TargetType.LOCAL if args.engine == "local_baseline" else TargetType.WEBAPP
    target = TargetView(
        ip=args.address,
        port=args.port,
        protocol=args.protocol,
        hostname=args.hostname or args.address,
        path=args.path,
        target_type=TargetType(args.target_type) if args.target_type else default_type,
    )

    lines: list[str] = []

    def log(level: str, message: str) -> None:
        lines.append(f"[{level}] {message}")
        if not args.json:
            print(f"[{level}] {message}", file=sys.stderr)

    with tempfile.TemporaryDirectory(prefix="cf-harness-") as workdir:
        ctx = EngineContext(
            run_id=0,
            timeout_seconds=args.timeout,
            max_output_bytes=args.max_output_bytes,
            safe_mode=not args.no_safe_mode,
            workdir=Path(workdir),
            log=log,
        )
        try:
            result = run_engine(args.engine, target, params, ctx)
        except EngineError as exc:
            print(f"engine error: {exc}", file=sys.stderr)
            return 2

    payload = {
        "engine": args.engine,
        "target": {
            "ip": target.ip,
            "port": target.port,
            "hostname": target.hostname,
            "target_type": target.target_type.value,
        },
        "argv": result.argv,
        "tool_versions": result.tool_versions,
        "exit_code": result.exit_code,
        "notes": result.notes,
        "facts": [
            {
                "fact_type": fact.fact_type,
                "subject": fact.subject,
                "key": fact.key,
                "confidence": fact.confidence,
                "value": fact.value,
                "detail": fact.detail,
            }
            for fact in result.facts
        ],
        "artifacts": [
            {"filename": a.filename, "bytes": len(a.data), "content_type": a.content_type}
            for a in result.artifacts
        ],
    }

    if args.json:
        print(json.dumps(payload, indent=2, default=str))
    else:
        print(f"\n{len(result.facts)} fact(s):")
        for fact in result.facts:
            confidence = "" if fact.confidence == 1.0 else f" (confidence {fact.confidence})"
            print(f"  {fact.fact_type:<18} {fact.key:<32}{confidence}")
            rendered = json.dumps(fact.value, default=str)
            print(f"      {rendered[:300]}")
        if result.tool_versions:
            print(f"\ntool versions: {result.tool_versions}")
        if result.notes:
            print(f"notes: {'; '.join(result.notes)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
