"""The http_headers engine.

The engine builds its one request in ``app.engines._http`` and calls it as
``fetch`` imported into its own namespace, so the stub goes on
``app.engines.http_headers.fetch``. No tool output is involved: the responses
below are plausible lab responses shaped to exercise each branch.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from app.engines import http_headers
from app.engines._http import HttpResponse
from app.engines.catalogue import HttpHeadersParams
from app.engines.context import EngineContext, TargetView
from app.models.enums import TargetType

SESSION_SECRET = "s3cr3t-session-token-9f2c"  # noqa: S105 - test value


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


def _ctx(tmp_path: Path):
    logs: list[tuple[str, str]] = []
    ctx = EngineContext(
        run_id=1,
        timeout_seconds=60,
        max_output_bytes=1_000_000,
        safe_mode=False,
        workdir=tmp_path,
        log=lambda level, message: logs.append((level, message)),
    )
    return ctx, logs


def _response(status=200, reason="OK", headers=(), body=b"<html>ok</html>", **overrides):
    values = dict(
        status=status,
        reason=reason,
        headers=[(str(k), str(v)) for k, v in headers],
        body=body,
        http_version="1.1",
        elapsed_ms=3,
        url="",
    )
    values.update(overrides)
    return HttpResponse(**values)


def _stub_fetch(monkeypatch, responder):
    """Stub the name the engine module actually looks up, and fill the
    response's url the way the real ``_http.fetch`` does (the engine quotes it
    in facts and redirect handling)."""
    calls: list[dict] = []

    def fake_fetch(target, *, scheme, path, method="GET", max_body_bytes=0, timeout_seconds=0):
        calls.append(
            {
                "target": target,
                "scheme": scheme,
                "path": path,
                "method": method,
                "max_body_bytes": max_body_bytes,
                "timeout_seconds": timeout_seconds,
            }
        )
        response = responder(calls[-1]) if callable(responder) else responder
        default_port = 443 if scheme == "https" else 80
        response.url = f"{scheme}://{target.authority(default_port=default_port)}{path}"
        return response

    monkeypatch.setattr("app.engines.http_headers.fetch", fake_fetch)
    return calls


def _facts(result, fact_type):
    return [f for f in result.facts if f.fact_type == fact_type]


def _serialised(result) -> str:
    return json.dumps([dataclasses.asdict(f) for f in result.facts])


# ------------------------------------------------------------------- cookies --


def test_a_cookie_value_is_never_written_into_a_fact(monkeypatch, tmp_path):
    """A Set-Cookie value is a live credential. Only the name, its length and
    the flags may reach facts, evidence or the UI."""
    headers = [
        ("Server", "nginx/1.31.6"),
        (
            "Set-Cookie",
            f"sessionid={SESSION_SECRET}; Path=/; Domain=lab-headers.local; "
            "HttpOnly; Secure; SameSite=Lax; Max-Age=3600",
        ),
    ]
    _stub_fetch(monkeypatch, _response(headers=headers))
    ctx, _ = _ctx(tmp_path)
    result = http_headers.run(_target(), HttpHeadersParams(), ctx)

    # The value must not appear anywhere in the facts, however nested.
    assert SESSION_SECRET not in _serialised(result)
    # Nor may the cookie have slipped in as a plain header fact.
    assert not [
        f for f in _facts(result, "http_header") if f.value["name"] == "set-cookie"
    ]

    cookie = _facts(result, "http_cookie")[0]
    assert cookie.key == "sessionid"
    assert cookie.value["name"] == "sessionid"
    assert cookie.value["value_length"] == len(SESSION_SECRET)
    assert cookie.value["secure"] is True
    assert cookie.value["httponly"] is True
    # Lowercased: the attribute's value is case-insensitive in HTTP, and an
    # assertion should not have to guess which casing a server chose.
    assert cookie.value["samesite"] == "lax"
    assert cookie.value["domain"] == "lab-headers.local"
    assert cookie.value["path"] == "/"
    assert cookie.value["max_age"] == "3600"
    assert cookie.value["credential_like"] is True
    assert "credential" in cookie.detail


def test_cookie_prefixes_and_flags_are_reported(monkeypatch, tmp_path):
    headers = [
        ("Set-Cookie", "__Host-sid=abcdef; Path=/; Secure"),
        ("Set-Cookie", "__Secure-token=ghijkl; HttpOnly"),
        ("Set-Cookie", "theme=dark"),
    ]
    _stub_fetch(monkeypatch, _response(headers=headers))
    ctx, _ = _ctx(tmp_path)
    result = http_headers.run(_target(), HttpHeadersParams(), ctx)

    cookies = {f.key: f for f in _facts(result, "http_cookie")}
    assert set(cookies) == {"__Host-sid", "__Secure-token", "theme"}
    assert cookies["__Host-sid"].value["host_prefix"] is True
    assert cookies["__Host-sid"].value["credential_like"] is True
    assert cookies["__Secure-token"].value["secure_prefix"] is True
    assert cookies["theme"].value["credential_like"] is False
    assert cookies["theme"].value["secure"] is False


def test_a_cookie_without_flags_reports_them_as_absent_not_defaulted(monkeypatch, tmp_path):
    _stub_fetch(monkeypatch, _response(headers=[("Set-Cookie", "tracking=1")]))
    ctx, _ = _ctx(tmp_path)
    result = http_headers.run(_target(), HttpHeadersParams(), ctx)

    cookie = _facts(result, "http_cookie")[0]
    assert cookie.value["secure"] is False
    assert cookie.value["httponly"] is False
    # Absent is False, not null: the response was read, and it carries no
    # SameSite at all - an observation, and one an assertion can fail on.
    assert cookie.value["samesite"] is False


# ------------------------------------------------------------------- headers --


def test_a_header_sent_twice_is_recorded_once_per_distinct_value(monkeypatch, tmp_path):
    headers = [
        ("X-Robots-Tag", "noindex"),
        ("X-Robots-Tag", "noindex"),
        ("X-Robots-Tag", "nofollow"),
    ]
    _stub_fetch(monkeypatch, _response(headers=headers))
    ctx, _ = _ctx(tmp_path)
    result = http_headers.run(_target(), HttpHeadersParams(), ctx)

    values = sorted(f.value["value"] for f in _facts(result, "http_header"))
    assert values == ["nofollow", "noindex"]


def test_header_names_are_normalised_but_the_raw_name_is_kept(monkeypatch, tmp_path):
    _stub_fetch(monkeypatch, _response(headers=[("Content-Security-Policy", "default-src 'self'")]))
    ctx, _ = _ctx(tmp_path)
    result = http_headers.run(_target(), HttpHeadersParams(), ctx)

    header = _facts(result, "http_header")[0]
    assert header.key == "content-security-policy"
    assert header.value["name"] == "content-security-policy"
    assert header.value["raw_name"] == "Content-Security-Policy"
    assert header.value["value"] == "default-src 'self'"


def test_the_response_fact_describes_the_response(monkeypatch, tmp_path):
    headers = [
        ("Server", "nginx/1.31.6"),
        ("Content-Type", "text/html"),
        ("Content-Length", "495"),
    ]
    _stub_fetch(monkeypatch, _response(headers=headers, body=b"x" * 495))
    ctx, _ = _ctx(tmp_path)
    result = http_headers.run(_target(), HttpHeadersParams(), ctx)

    response = _facts(result, "http_response")[0]
    assert response.value["status_code"] == 200
    assert response.value["reason"] == "OK"
    assert response.value["server"] == "nginx/1.31.6"
    assert response.value["content_type"] == "text/html"
    assert response.value["content_length"] == "495"
    assert response.value["url"] == "http://lab-headers.local:8081/"
    assert response.value["redirect_to"] is None
    assert response.value["body_bytes"] == 495
    assert response.value["method"] == "GET"


def test_the_request_goes_to_the_pinned_ip_with_the_hostname_authority(monkeypatch, tmp_path):
    calls = _stub_fetch(monkeypatch, _response())
    ctx, _ = _ctx(tmp_path)
    http_headers.run(_target(), HttpHeadersParams(path="admin"), ctx)

    assert calls[0]["target"].ip == "127.0.0.1"
    assert calls[0]["path"] == "/admin", "a bare path is normalised"
    assert calls[0]["scheme"] == "http"
    assert calls[0]["method"] == "GET"


def test_the_scheme_follows_the_port(monkeypatch, tmp_path):
    calls = _stub_fetch(monkeypatch, _response())
    ctx, _ = _ctx(tmp_path)
    result = http_headers.run(_target(port=8443, target_type=TargetType.TLS), HttpHeadersParams(), ctx)
    assert calls[0]["scheme"] == "https"
    assert _facts(result, "http_response")[0].value["url"] == "https://lab-headers.local:8443/"


def test_a_head_request_is_forwarded_as_one(monkeypatch, tmp_path):
    calls = _stub_fetch(monkeypatch, _response(body=b""))
    ctx, _ = _ctx(tmp_path)
    result = http_headers.run(_target(), HttpHeadersParams(method="HEAD"), ctx)
    assert calls[0]["method"] == "HEAD"
    assert _facts(result, "http_response")[0].value["method"] == "HEAD"


# ----------------------------------------------------------------- redirects --


def _redirect(location, *, status=302):
    return _response(status=status, reason="Found", headers=[("Location", location)])


def test_redirects_are_not_followed_by_default(monkeypatch, tmp_path):
    calls = _stub_fetch(monkeypatch, _redirect("/login"))
    ctx, _ = _ctx(tmp_path)
    result = http_headers.run(_target(), HttpHeadersParams(), ctx)

    assert len(calls) == 1
    assert _facts(result, "http_response")[0].value["redirect_to"] == "/login"


def test_a_same_origin_redirect_is_followed_and_chained(monkeypatch, tmp_path):
    def responder(call):
        if call["path"] == "/":
            return _redirect("/login")
        return _response(body=b"<html>login</html>")

    calls = _stub_fetch(monkeypatch, responder)
    ctx, _ = _ctx(tmp_path)
    result = http_headers.run(_target(), HttpHeadersParams(follow_redirects=True), ctx)

    assert [c["path"] for c in calls] == ["/", "/login"]
    response = _facts(result, "http_response")[0]
    assert response.value["redirect_chain"] == ["/login"]
    assert response.value["url"] == "http://lab-headers.local:8081/login"


def test_an_off_origin_redirect_is_refused_with_a_note(monkeypatch, tmp_path):
    """Following it would move the request off the address scope authorized."""
    calls = _stub_fetch(monkeypatch, _redirect("http://evil.example/login"))
    ctx, logs = _ctx(tmp_path)
    result = http_headers.run(_target(), HttpHeadersParams(follow_redirects=True), ctx)

    assert len(calls) == 1, "the off-origin hop must not be requested"
    assert any("refused to follow a redirect" in note for note in result.notes)
    assert any(level == "warning" for level, _ in logs)


def test_a_redirect_to_a_different_scheme_is_refused(monkeypatch, tmp_path):
    calls = _stub_fetch(monkeypatch, _redirect("https://lab-headers.local:8081/login"))
    ctx, _ = _ctx(tmp_path)
    result = http_headers.run(_target(), HttpHeadersParams(follow_redirects=True), ctx)

    assert len(calls) == 1
    assert any("off-origin" in note for note in result.notes)


def test_a_redirect_loop_is_capped(monkeypatch, tmp_path):
    calls = _stub_fetch(
        monkeypatch,
        _response(status=302, reason="Found", headers=[("Location", "/next")]),
    )
    ctx, _ = _ctx(tmp_path)
    http_headers.run(_target(), HttpHeadersParams(follow_redirects=True), ctx)

    # initial request + at most three hops
    assert len(calls) == 4


def test_a_relative_redirect_with_a_query_is_recomposed(monkeypatch, tmp_path):
    def responder(call):
        if call["path"] == "/":
            return _redirect("/search?q=1")
        return _response()

    calls = _stub_fetch(monkeypatch, responder)
    ctx, _ = _ctx(tmp_path)
    http_headers.run(_target(), HttpHeadersParams(follow_redirects=True), ctx)
    assert [c["path"] for c in calls] == ["/", "/search?q=1"]
