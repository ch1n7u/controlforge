"""Dispatch an engine id to its implementation.

Parameters arrive from a ``JSONB`` column, not from a request body, so they are
validated here as well as at authoring time. A row edited directly in the
database, or written by a future migration, must not be able to hand an engine
parameters its own schema would have refused.
"""

from __future__ import annotations

from typing import Any

from app.engines.catalogue import ENGINES, ENGINE_SPECS
from app.engines.context import EngineContext, EngineError, EngineResult, TargetView


def build_params(spec, raw: dict[str, Any] | None):
    """Validate stored parameters against the engine's schema."""
    try:
        return spec.params.model_validate(raw or {})
    except Exception as exc:  # pydantic ValidationError
        raise EngineError(
            f"{spec.id} rejected its stored parameters: {' '.join(str(exc).split())[:400]}"
        ) from exc


def load_engine(engine_id: str):
    """Import the module implementing ``engine_id``."""
    from importlib import import_module

    spec = ENGINES.get(engine_id)
    if spec is None:
        known = ", ".join(sorted(s.id for s in ENGINE_SPECS))
        raise EngineError(f"unknown engine {engine_id!r} (known: {known})")
    try:
        module = import_module(f"app.engines.{engine_id}")
    except ImportError as exc:
        raise EngineError(f"engine {engine_id!r} is declared but not implemented") from exc
    if not hasattr(module, "run"):
        raise EngineError(f"engine {engine_id!r} has no run() entry point")
    return spec, module


def run_engine(
    engine_id: str,
    target: TargetView,
    raw_params: dict[str, Any] | None,
    ctx: EngineContext,
) -> EngineResult:
    """Validate, run, and check that what came back matches the declaration."""
    spec, module = load_engine(engine_id)
    if target.target_type not in spec.target_types:
        raise EngineError(
            f"engine {engine_id!r} does not run against a {target.target_type.value} target"
        )

    params = build_params(spec, raw_params)
    result = module.run(target, params, ctx)

    unknown = sorted(
        {fact.fact_type for fact in result.facts} - set(spec.fact_types)
    )
    if unknown:
        # The catalogue is what test authors read. If an engine emits a type it
        # did not declare, assertions written against the declaration would
        # never match, and the mismatch would look like a control that passed.
        raise EngineError(
            f"engine {engine_id!r} emitted undeclared fact type(s): {', '.join(unknown)}"
        )
    return result
