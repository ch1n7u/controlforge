"""Fetch one HTTP response and turn it into facts.

Everything this engine reports is something a security control can be written
against: the status line, the presence and value of each response header, and
the flags on each cookie. It changes nothing on the target.
"""

from __future__ import annotations

from urllib.parse import urlparse

from app.engines._http import fetch, scheme_for
from app.engines.context import (
    MAX_HTTP_BODY_BYTES,
    EngineContext,
    EngineResult,
    FactDraft,
    TargetView,
)

# Values in Set-Cookie that are credentials, not configuration. The cookie's
# flags are the security-relevant part; its value is a live session token, and
# writing one into facts, evidence or the UI would be leaking a credential.
CREDENTIAL_COOKIE_HINTS = ("session", "auth", "token", "jwt", "sid", "csrf", "remember")


def _bool_attr(attributes: list[str], name: str) -> bool:
    return any(attribute.strip().lower() == name for attribute in attributes)


def _cookie_facts(
    target: TargetView, set_cookies: list[str]
) -> list[FactDraft]:
    facts: list[FactDraft] = []
    for raw in set_cookies:
        parts = [part.strip() for part in raw.split(";")]
        if not parts or not parts[0]:
            continue
        name, _, value = parts[0].partition("=")
        name = name.strip()
        attributes = parts[1:]

        # SameSite is reported as the lowercased value it was sent with, or
        # False when the attribute is absent. Absent is an observation - the
        # response was read and said nothing - and a null here would be read by
        # the evaluator as "not readable", turning a missing flag into an
        # inconclusive instead of a finding. The rest of the optional
        # attributes keep null, where absence really is just absent.
        samesite: str | bool = False
        domain = path = expires = max_age = None
        for attribute in attributes:
            key, _, attr_value = attribute.partition("=")
            key = key.strip().lower()
            attr_value = attr_value.strip()
            if key == "samesite":
                samesite = attr_value.lower() or False
            elif key == "domain":
                domain = attr_value or None
            elif key == "path":
                path = attr_value or None
            elif key == "expires":
                expires = attr_value or None
            elif key == "max-age":
                max_age = attr_value or None

        facts.append(
            FactDraft(
                fact_type="http_cookie",
                subject=target.hostname,
                key=name,
                detail=(
                    "A Set-Cookie value is a credential, so only the name, length and "
                    "flags are recorded."
                ),
                value={
                    "name": name,
                    "value_length": len(value),
                    "secure": _bool_attr(attributes, "secure"),
                    "httponly": _bool_attr(attributes, "httponly"),
                    "samesite": samesite,
                    "domain": domain,
                    "path": path,
                    "expires": expires,
                    "max_age": max_age,
                    "host_prefix": name.startswith("__Host-"),
                    "secure_prefix": name.startswith("__Secure-"),
                    "credential_like": any(
                        hint in name.lower() for hint in CREDENTIAL_COOKIE_HINTS
                    ),
                },
            )
        )
    return facts


def _is_same_origin(location: str, scheme: str, authority: str) -> bool:
    """Only a same-scheme, same-host, same-port redirect may be followed.

    Anything else would move the request off the address the scope layer
    authorized, which is exactly what an attacker-controlled redirect is for.
    """
    parsed = urlparse(location)
    if not parsed.netloc:  # relative: same origin by definition
        return True
    return (
        parsed.scheme == scheme
        and parsed.netloc.lower() == authority.lower()
    )


def run(target: TargetView, params, ctx: EngineContext) -> EngineResult:
    result = EngineResult()
    scheme = scheme_for(target)
    default_port = 443 if scheme == "https" else 80
    authority = target.authority(default_port=default_port)

    path = params.path or "/"
    if not path.startswith("/"):
        path = "/" + path

    timeout = min(ctx.timeout_seconds, 60)
    chain: list[str] = []

    response = fetch(
        target,
        scheme=scheme,
        path=path,
        method=params.method,
        max_body_bytes=MAX_HTTP_BODY_BYTES,
        timeout_seconds=timeout,
    )

    if params.follow_redirects:
        hops = 0
        while response.redirect_to and hops < 3:
            location = response.redirect_to
            if not _is_same_origin(location, scheme, authority):
                ctx.emit(
                    "warning",
                    f"redirect to {location!r} left the authorized origin; not followed",
                )
                result.notes.append(
                    f"refused to follow a redirect to {location!r}: off-origin"
                )
                break
            chain.append(location)
            next_path = urlparse(location).path or "/"
            query = urlparse(location).query
            if query:
                next_path = f"{next_path}?{query}"
            response = fetch(
                target,
                scheme=scheme,
                path=next_path,
                method=params.method,
                max_body_bytes=MAX_HTTP_BODY_BYTES,
                timeout_seconds=timeout,
            )
            hops += 1

    result.argv = []

    result.add(
        FactDraft(
            fact_type="http_response",
            subject=target.hostname,
            key="response",
            value={
                "status_code": response.status,
                "reason": response.reason,
                "url": response.url,
                "http_version": response.http_version,
                "server": response.header("server"),
                "content_type": response.header("content-type"),
                "content_length": response.header("content-length"),
                "elapsed_ms": response.elapsed_ms,
                "redirect_to": response.redirect_to,
                "redirect_chain": chain,
                "body_truncated": response.body_truncated,
                "body_bytes": len(response.body),
                "method": params.method,
            },
        )
    )

    seen: set[str] = set()
    for name, value in response.headers:
        if name.lower() == "set-cookie":
            continue  # handled below, and never as a plain header value
        key = name.lower()
        # A header sent twice (Set-Cookie aside) is recorded once per value, so
        # an assertion on it sees every value rather than whichever came first.
        fingerprint = f"{key}={value}"
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        result.add(
            FactDraft(
                fact_type="http_header",
                subject=target.hostname,
                key=key,
                value={"name": key, "raw_name": name, "value": value},
            )
        )

    result.facts.extend(_cookie_facts(target, response.all_headers("set-cookie")))
    return result
