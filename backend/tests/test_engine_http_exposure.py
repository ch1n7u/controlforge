"""The http_exposure engine.

The design decision under test: a path is only reported as exposed when the
response looks like *that path* (a marker match), or - for a caller-supplied
path with no marker - when it differs from what a random nonexistent path
returns (the soft-404 baseline). A 200 from a catch-all handler must not
become a finding.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.engines import http_exposure
from app.engines._http import HttpResponse
from app.engines.catalogue import HttpExposureParams
from app.engines.context import EngineContext, TargetView
from app.models.enums import TargetType

NOT_FOUND = b"<html><head><title>404 Not Found</title></head><body>nope</body></html>"


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


def _ctx(tmp_path: Path, should_cancel=None):
    logs: list[tuple[str, str]] = []
    ctx = EngineContext(
        run_id=1,
        timeout_seconds=120,
        max_output_bytes=1_000_000,
        safe_mode=False,
        workdir=tmp_path,
        should_cancel=should_cancel,
        log=lambda level, message: logs.append((level, message)),
    )
    return ctx, logs


def _resp(status, ctype, body, reason="OK"):
    return HttpResponse(
        status=status,
        reason=reason,
        headers=[("Content-Type", ctype), ("Server", "nginx/1.31.6")],
        body=body,
        http_version="1.1",
        elapsed_ms=2,
    )


def _stub_fetch(monkeypatch, server):
    """Stub the name in the engine module's namespace; ``server`` maps a path
    to a response or to an exception to raise. The response's url is filled
    the way the real ``_http.fetch`` does - the exposure artifact quotes it."""
    calls: list[str] = []

    def fake_fetch(target, *, scheme, path, method="GET", max_body_bytes=0, timeout_seconds=0):
        calls.append(path)
        outcome = server(path)
        if isinstance(outcome, BaseException):
            raise outcome
        default_port = 443 if scheme == "https" else 80
        outcome.url = f"{scheme}://{target.authority(default_port=default_port)}{path}"
        return outcome

    monkeypatch.setattr("app.engines.http_exposure.fetch", fake_fetch)
    return calls


def _is_baseline(path: str) -> bool:
    return path.startswith("/controlforge-nonexistent-")


def _by_key(result):
    return {f.key: f for f in result.facts if f.fact_type == "path_exposed"}


def _standard_server(routes):
    def server(path):
        if _is_baseline(path):
            return _resp(404, "text/html", NOT_FOUND, reason="Not Found")
        if path in routes:
            return routes[path]
        return _resp(404, "text/html", NOT_FOUND, reason="Not Found")

    return server


# --------------------------------------------------------------- marker matches --


def test_a_path_whose_body_matches_its_signature_is_exposed(monkeypatch, tmp_path):
    routes = {
        "/.env": _resp(200, "text/plain", b"APP_ENV=production\nDB_PASSWORD=EXAMPLE\n"),
        "/.git/HEAD": _resp(200, "text/plain", b"ref: refs/heads/main\n"),
        "/server-status": _resp(404, "text/html", NOT_FOUND),
        "/robots.txt": _resp(404, "text/html", NOT_FOUND),
    }
    _stub_fetch(monkeypatch, _standard_server(routes))
    ctx, _ = _ctx(tmp_path)
    result = http_exposure.run(_target(), HttpExposureParams(), ctx)

    facts = _by_key(result)
    assert set(facts) == {"/.env", "/.git/HEAD", "/server-status", "/robots.txt"}

    env = facts["/.env"]
    assert env.value["exposed"] is True
    assert env.value["matched_marker"] == "="
    assert env.value["kind"] == "source_leak"
    assert env.value["soft_404_suppressed"] is False
    assert env.confidence == 1.0

    head = facts["/.git/HEAD"]
    assert head.value["exposed"] is True
    assert head.value["matched_marker"] == "ref: refs/"

    assert facts["/robots.txt"].value["exposed"] is False
    assert facts["/robots.txt"].value["reason"] == "status 404"


def test_an_exposed_path_leaves_a_bounded_artifact(monkeypatch, tmp_path):
    routes = {"/.env": _resp(200, "text/plain", b"A=" + b"x" * 100_000)}
    _stub_fetch(monkeypatch, _standard_server(routes))
    ctx, _ = _ctx(tmp_path)
    result = http_exposure.run(_target(), HttpExposureParams(), ctx)

    assert len(result.artifacts) == 1
    artifact = result.artifacts[0]
    assert artifact.filename == "exposed_.env.txt"
    assert artifact.data.startswith(b"# http://")
    assert b"status 200" in artifact.data
    assert len(artifact.data) < 20_000, "the capture must stay bounded"


def test_a_200_without_the_expected_signature_is_not_exposed(monkeypatch, tmp_path):
    """A catch-all handler answering 200 to /server-status is not an exposed
    Apache status page."""
    routes = {"/server-status": _resp(200, "text/html", b"<html>welcome</html>")}
    _stub_fetch(monkeypatch, _standard_server(routes))
    ctx, _ = _ctx(tmp_path)
    result = http_exposure.run(_target(), HttpExposureParams(), ctx)

    fact = _by_key(result)["/server-status"]
    assert fact.value["exposed"] is False
    assert fact.value["status_code"] == 200
    assert fact.value["matched_marker"] is None
    assert "did not match the expected signature" in fact.value["reason"]
    assert not result.artifacts


def test_a_directory_listing_is_recognised(monkeypatch, tmp_path):
    routes = {
        "/files/": _resp(200, "text/html", b"<html><head><title>Index of /files/</title>")
    }
    _stub_fetch(monkeypatch, _standard_server(routes))
    ctx, _ = _ctx(tmp_path)
    result = http_exposure.run(_target(), HttpExposureParams(profile="dirlist"), ctx)

    fact = _by_key(result)["/files/"]
    assert fact.value["exposed"] is True
    assert fact.value["kind"] == "dir_listing"
    assert fact.value["matched_marker"] == "<title>index of"
    # Every probed path emits a fact, exposed or not.
    assert len(result.facts) == len(http_exposure.EXPOSURE_PATHS["dirlist"])


# ----------------------------------------------------------------- soft-404 --


def test_a_soft_404_page_suppresses_even_a_marker_match(monkeypatch, tmp_path):
    """The catch-all body here even contains "DB_PASSWORD=" - the marker for
    /.env. The baseline comparison must win: the server answers one template
    for everything, so nothing can be concluded about any single path."""
    catch_all = b"<html>page not found. DB_PASSWORD= now back to the homepage</html>"

    def server(path):
        return _resp(200, "text/html", catch_all)

    _stub_fetch(monkeypatch, server)
    ctx, _ = _ctx(tmp_path)
    result = http_exposure.run(_target(), HttpExposureParams(), ctx)

    fact = _by_key(result)["/.env"]
    assert fact.value["exposed"] is False
    assert fact.value["soft_404_suppressed"] is True
    assert fact.value["matched_marker"] == "=", "the marker matched, and was still not enough"
    assert "indistinguishable from the soft-404 baseline" in fact.value["reason"]
    assert not result.artifacts


def test_the_soft_404_comparison_tolerates_the_path_echoed_back(monkeypatch, tmp_path):
    """A soft-404 page often echoes the requested path, which makes the length
    differ by exactly that path's length - up to the tolerance, it is still
    the same page."""
    baseline = _resp(200, "text/html", b"x" * 500)
    routes = {"/notes.txt": _resp(200, "text/html", b"y" * 564)}  # 64 longer: tolerated

    def server(path):
        if _is_baseline(path):
            return baseline
        return routes[path]

    _stub_fetch(monkeypatch, server)
    ctx, _ = _ctx(tmp_path)
    result = http_exposure.run(
        _target(), HttpExposureParams(extra_paths=["/notes.txt"]), ctx
    )

    fact = _by_key(result)["/notes.txt"]
    assert fact.value["soft_404_suppressed"] is True
    assert fact.value["exposed"] is False


def test_beyond_the_soft_404_tolerance_the_path_is_exposed(monkeypatch, tmp_path):
    baseline = _resp(200, "text/html", b"x" * 500)
    routes = {"/notes.txt": _resp(200, "text/html", b"y" * 565)}  # 65 longer: a real page

    def server(path):
        if _is_baseline(path):
            return baseline
        return routes[path]

    _stub_fetch(monkeypatch, server)
    ctx, _ = _ctx(tmp_path)
    result = http_exposure.run(
        _target(), HttpExposureParams(extra_paths=["/notes.txt"]), ctx
    )

    fact = _by_key(result)["/notes.txt"]
    assert fact.value["exposed"] is True
    assert fact.value["soft_404_suppressed"] is False
    assert fact.value["matched_marker"] is None
    assert fact.value["reason"] == "content differs from the soft-404 page"


def test_a_different_content_type_is_not_the_soft_404_page(monkeypatch, tmp_path):
    baseline = _resp(200, "text/html", b"x" * 500)
    routes = {"/notes.txt": _resp(200, "application/json", b"y" * 500)}

    def server(path):
        if _is_baseline(path):
            return baseline
        return routes[path]

    _stub_fetch(monkeypatch, server)
    ctx, _ = _ctx(tmp_path)
    result = http_exposure.run(
        _target(), HttpExposureParams(extra_paths=["/notes.txt"]), ctx
    )
    assert _by_key(result)["/notes.txt"].value["exposed"] is True


# ------------------------------------------------------------------- failures --


def test_a_failed_probe_is_unobserved_not_clean(monkeypatch, tmp_path):
    """One bad path must not stop the sweep, and it must not read as 'not
    exposed': the probe failed, so there is nothing to conclude."""

    def server(path):
        if _is_baseline(path):
            return _resp(404, "text/html", NOT_FOUND)
        if path == "/.env":
            raise OSError("connection reset by peer")
        return _resp(404, "text/html", NOT_FOUND)

    _stub_fetch(monkeypatch, server)
    ctx, logs = _ctx(tmp_path)
    result = http_exposure.run(_target(), HttpExposureParams(), ctx)

    fact = _by_key(result)["/.env"]
    assert fact.confidence == 0.0
    assert fact.value["exposed"] is None
    assert fact.value["exposed"] is not False
    assert fact.value["probe_failed"] is True
    assert fact.value["status_code"] is None
    assert "connection reset" in fact.value["error"]
    assert any("connection reset" in message for _, message in logs)

    # The rest of the sweep still ran.
    assert set(_by_key(result)) == {"/.env", "/.git/HEAD", "/server-status", "/robots.txt"}


def test_a_refusal_is_not_an_exposure(monkeypatch, tmp_path):
    routes = {
        "/server-status": _resp(403, "text/html", NOT_FOUND, reason="Forbidden"),
        "/robots.txt": _resp(302, "text/html", b"", reason="Found"),
    }
    _stub_fetch(monkeypatch, _standard_server(routes))
    ctx, _ = _ctx(tmp_path)
    result = http_exposure.run(_target(), HttpExposureParams(), ctx)

    facts = _by_key(result)
    assert facts["/server-status"].value["exposed"] is False
    assert facts["/server-status"].value["reason"] == "status 403"
    assert facts["/robots.txt"].value["exposed"] is False
    assert facts["/robots.txt"].value["reason"] == "status 302"


def test_without_a_baseline_unmarked_paths_are_judged_on_status_alone(monkeypatch, tmp_path):
    """The fallback is explicitly signalled, so an operator can see why a path
    was reported: baseline_available is False and a warning is logged."""

    def server(path):
        if _is_baseline(path):
            raise OSError("baseline probe refused")
        if path == "/notes.txt":
            return _resp(200, "text/plain", b"whatever")
        if path == "/.env":
            return _resp(200, "text/plain", b"TOKEN=abc")
        return _resp(404, "text/html", NOT_FOUND)

    _stub_fetch(monkeypatch, server)
    ctx, logs = _ctx(tmp_path)
    result = http_exposure.run(
        _target(), HttpExposureParams(extra_paths=["/notes.txt"]), ctx
    )

    facts = _by_key(result)
    assert facts["/notes.txt"].value["exposed"] is True
    assert facts["/notes.txt"].value["baseline_available"] is False
    assert facts["/.env"].value["exposed"] is True  # marker match needs no baseline
    assert any("soft-404 baseline" in message for _, message in logs)


def test_cancellation_stops_the_sweep_and_says_so(monkeypatch, tmp_path):
    calls = _stub_fetch(monkeypatch, _standard_server({}))
    ctx, _ = _ctx(tmp_path, should_cancel=lambda: True)
    result = http_exposure.run(_target(), HttpExposureParams(), ctx)

    assert result.facts == []
    assert any(note == "stopped after 0 paths" for note in result.notes)
    # The stop happened before any path probe; only the baseline may have gone out.
    assert all(_is_baseline(path) for path in calls)


# --------------------------------------------------------------- path curation --


def test_extra_paths_are_appended_without_duplicating_the_curated_list(monkeypatch, tmp_path):
    _stub_fetch(monkeypatch, _standard_server({}))
    ctx, _ = _ctx(tmp_path)
    result = http_exposure.run(
        _target(),
        HttpExposureParams(extra_paths=["/.env", "/notes.txt"]),
        ctx,
    )

    keys = list(_by_key(result))
    assert keys == ["/.env", "/.git/HEAD", "/server-status", "/robots.txt", "/notes.txt"]


def test_a_healthy_target_produces_only_negative_facts(monkeypatch, tmp_path):
    """Every probed path emits a fact either way, so an assertion that says
    'nothing is exposed' has observations behind it."""
    _stub_fetch(monkeypatch, _standard_server({}))
    ctx, _ = _ctx(tmp_path)
    result = http_exposure.run(_target(), HttpExposureParams(), ctx)

    assert len(result.facts) == len(http_exposure.EXPOSURE_PATHS["minimal"])
    assert all(f.value["exposed"] is False for f in result.facts)
    assert all(f.confidence == 1.0 for f in result.facts)
    assert not result.artifacts
