"""Probe a curated list of sensitive paths.

The design decision that makes this engine trustworthy is that a path is only
reported as exposed when the response body looks like *that path*. Without a
marker check, a 200 from a catch-all handler or a soft-404 page would be
reported as a leak, and a findings list full of false positives is worth
nothing. Every probed path emits a fact either way, so an assertion can say
"nothing is exposed" and mean it.

Curated paths carry a marker table. A path supplied by the caller as an
``extra_path`` has no marker to check, so the engine falls back to a soft-404
comparison: one request to a random path that cannot exist, and any answer
indistinguishable from that response is treated as "not there".
"""

from __future__ import annotations

import secrets

from app.engines._http import fetch, scheme_for
from app.engines.catalogue import (
    DIRECTORY_LISTING_MARKERS,
    EXPOSURE_MARKERS,
    EXPOSURE_PATHS,
)
from app.engines.context import (
    MAX_HTTP_BODY_BYTES,
    ArtifactDraft,
    EngineContext,
    EngineError,
    EngineResult,
    FactDraft,
    TargetView,
)

MAX_PATHS_PER_RUN = 64

# Statuses that mean "the server answered", as opposed to a redirect to a login
# page or a hard refusal. A 403 is a refusal, so it is not an exposure.
EXPOSED_STATUSES = (200, 206)

# How close two responses have to be to count as the same page. Bodies are
# compared with a tolerance because a soft-404 page often echoes the requested
# path back, which makes the length differ by exactly that path's length.
SOFT_404_LENGTH_TOLERANCE = 64


def _classify(path: str) -> str:
    if path.endswith("/"):
        return "dir_listing"
    if path.startswith("/."):
        return "source_leak"
    if any(word in path for word in ("actuator", "server-status", "swagger", "openapi")):
        return "admin_surface"
    if any(word in path for word in (".bak", ".zip", ".sql", "phpinfo", "wp-config")):
        return "file_leak"
    return "file_leak"


def _matches_marker(path: str, body_text: str) -> str | None:
    """Return the marker that matched, or None.

    A directory path is judged by the listing markers; anything else by its own
    marker set. ``EXPOSURE_MARKERS`` may legitimately be empty for a path whose
    own existence at a 200 is the finding - that case is handled by the caller.
    """
    lowered = body_text.lower()
    if path.endswith("/"):
        for marker in DIRECTORY_LISTING_MARKERS:
            if marker in lowered:
                return marker
        return None
    for marker in EXPOSURE_MARKERS.get(path, ()):
        if marker.lower() in lowered:
            return marker
    return None


def _has_markers(path: str) -> bool:
    return path.endswith("/") or bool(EXPOSURE_MARKERS.get(path))


def _capture_soft_404(target: TargetView, scheme: str, method: str, timeout: float):
    """Fetch a path that cannot exist, to learn what "not here" looks like.

    A target whose handler answers 200 to everything would otherwise make every
    unmarked path look exposed. If this probe fails, the engine proceeds without
    a baseline and says so, rather than assuming there is nothing to compare to.
    """
    probe = f"/controlforge-nonexistent-{secrets.token_hex(8)}"
    try:
        return fetch(
            target,
            scheme=scheme,
            path=probe,
            method=method,
            max_body_bytes=MAX_HTTP_BODY_BYTES,
            timeout_seconds=timeout,
        )
    except Exception:  # noqa: BLE001 - a missing baseline is not fatal
        return None


def _indistinguishable_from(response, baseline) -> bool:
    """True when a response looks like the same page the soft-404 probe got."""
    if baseline is None:
        return False
    if response.status != baseline.status:
        return False
    if response.header("content-type") != baseline.header("content-type"):
        return False
    return abs(len(response.body) - len(baseline.body)) <= SOFT_404_LENGTH_TOLERANCE


def run(target: TargetView, params, ctx: EngineContext) -> EngineResult:
    result = EngineResult()
    scheme = scheme_for(target)

    paths: list[str] = list(EXPOSURE_PATHS.get(params.profile, ()))
    for extra in params.extra_paths:
        if extra not in paths:
            paths.append(extra)
    paths = paths[:MAX_PATHS_PER_RUN]

    if not paths:
        raise EngineError(f"exposure profile {params.profile!r} contains no paths")

    ctx.emit("info", f"probing {len(paths)} path(s) on {target.hostname}")

    timeout = max(10, min(ctx.timeout_seconds // max(len(paths), 1), 20))
    baseline = _capture_soft_404(target, scheme, params.method, timeout)
    if baseline is None:
        ctx.emit(
            "warning",
            "could not establish a soft-404 baseline; paths without a signature "
            "will be judged on status alone",
        )

    for path in paths:
        if ctx.should_cancel and ctx.should_cancel():
            result.notes.append(f"stopped after {len(result.facts)} paths")
            break
        try:
            response = fetch(
                target,
                scheme=scheme,
                path=path,
                method=params.method,
                max_body_bytes=MAX_HTTP_BODY_BYTES,
                timeout_seconds=timeout,
            )
        except Exception as exc:  # noqa: BLE001 - one bad path must not stop the sweep
            ctx.emit("warning", f"{path}: {exc}")
            result.add(
                FactDraft(
                    fact_type="path_exposed",
                    subject=target.hostname,
                    key=path,
                    confidence=0.0,
                    detail=f"the probe itself failed: {exc}",
                    value={
                        "path": path,
                        "exposed": None,
                        "probe_failed": True,
                        "status_code": None,
                        "kind": _classify(path),
                        "error": str(exc)[:200],
                    },
                )
            )
            continue

        body_text = response.text
        marker = _matches_marker(path, body_text)
        soft_404 = _indistinguishable_from(response, baseline)

        if response.status not in EXPOSED_STATUSES:
            exposed = False
            reason = f"status {response.status}"
        elif soft_404:
            # Same page as a path that cannot exist: the server is answering
            # everything with one template, so nothing can be concluded here.
            exposed = False
            reason = "response is indistinguishable from the soft-404 baseline"
        elif _has_markers(path) and marker is None:
            exposed = False
            reason = "response did not match the expected signature"
        else:
            exposed = True
            reason = (
                f"matched {marker!r}" if marker else "content differs from the soft-404 page"
            )

        result.add(
            FactDraft(
                fact_type="path_exposed",
                subject=target.hostname,
                key=path,
                detail=reason,
                value={
                    "path": path,
                    "exposed": exposed,
                    "probe_failed": False,
                    "status_code": response.status,
                    "kind": _classify(path),
                    "content_type": response.header("content-type"),
                    "body_bytes": len(response.body),
                    "matched_marker": marker,
                    "soft_404_suppressed": soft_404,
                    "baseline_available": baseline is not None,
                    "reason": reason,
                },
            )
        )

        if exposed:
            result.artifacts.append(
                _artifact(path, response)
            )
            ctx.emit("warning", f"{path} appears exposed ({reason})")

    return result


def _artifact(path: str, response) -> ArtifactDraft:
    """A bounded capture of the leak: enough to confirm it, not the whole file."""
    safe = path.strip("/").replace("/", "_") or "root"
    header_block = "".join(f"{k}: {v}\n" for k, v in response.headers)
    head = (
        f"# {response.url}\n"
        f"# status {response.status} {response.reason}\n"
        f"{header_block}\n"
    ).encode()
    return ArtifactDraft(
        filename=f"exposed_{safe}.txt",
        data=head + response.body[:16 * 1024],
        content_type="text/plain",
    )
