"""Validation engines.

An engine is a wrapper around one observation tool. Its job is narrow: given an
already-authorized target and a set of validated parameters, run the tool and
return *typed facts* plus the raw evidence. Deciding what the facts mean is the
assertion layer's job, and authorizing the target is the scope layer's job.

The declaration of what each engine can do lives in :mod:`app.engines.catalogue`
so the API can validate test definitions without importing anything that shells
out to a security tool.
"""

from app.engines.catalogue import (
    ENGINES,
    ENGINE_SPECS,
    EngineSpec,
    StrictParams,
    all_fact_types,
    fact_types_for,
    get_engine,
)

__all__ = [
    "ENGINES",
    "ENGINE_SPECS",
    "EngineSpec",
    "StrictParams",
    "all_fact_types",
    "fact_types_for",
    "get_engine",
]
