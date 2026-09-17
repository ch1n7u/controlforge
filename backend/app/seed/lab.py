"""The lab catalog: frameworks, controls, tests, targets and the lab scope.

Everything here is seeded so the platform has something real to validate the
moment it comes up: the same deliberately vulnerable lab the engines are tested
against, described the way an operator would describe it - a control, the
expectation, and the evidence that would satisfy it.

The lab fails several of these controls *on purpose*. That is the point: the
seeded suite exercises the whole loop end to end (a control fails, a finding
opens, fixing the lab would close it again), and a demonstration suite in which
nothing can be found would prove nothing.

Seeding is idempotent and additive: rows are created when their key is missing
and otherwise left alone, so a control someone has edited in the UI is not
reverted the next time the seeder runs.
"""

from __future__ import annotations

import argparse
import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from app.core import audit
from app.core.assertions import validate_assertion
from app.engines.catalogue import fact_types_for, get_engine
from app.models.enums import (
    RunStatus,
    ScopeEntryKind,
    Severity,
    TargetType,
    TriggerKind,
)
from app.models.registry import (
    Control,
    Framework,
    FrameworkRef,
    Scope,
    ScopeEntry,
    Target,
    TargetScope,
)
from app.models.testing import ValidationRun, ValidationTest, ValidationTestVersion
from app.queue import jobs

logger = logging.getLogger("valtros.seed.lab")

LAB_SCOPE_NAME = "lab-loopback"
HOST_SCOPE_NAME = "valtros-host"

# The ports the lab publishes on loopback. The scope says exactly this much and
# no more: a target outside this list is refused before a packet is sent.
LAB_PORTS = "8081,8082,8083,8084,8443,2222"


# ------------------------------------------------------------------ frameworks --

FRAMEWORKS: tuple[dict[str, Any], ...] = (
    {
        "key": "owasp-asvs",
        "name": "OWASP Application Security Verification Standard",
        "version": "4.0.3",
        "source": "https://owasp.org/www-project-application-security-verification-standard/",
        "description": "Application-level verification requirements, used here for the "
        "web and transport controls.",
    },
    {
        "key": "cis-linux",
        "name": "CIS Distribution Independent Linux Benchmark",
        "version": "2.0.0",
        "source": "https://www.cisecurity.org/benchmark/distribution_independent_linux",
        "description": "Host hardening recommendations, used here for the sysctl, file "
        "permission and sshd controls.",
    },
    {
        "key": "nist-800-53",
        "name": "NIST SP 800-53",
        "version": "Rev. 5",
        "source": "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final",
        "description": "Federal control catalog; the technical controls below carry "
        "their 800-53 identifiers where one applies.",
    },
)

# -------------------------------------------------------------------- controls --

CONTROLS: tuple[dict[str, Any], ...] = (
    {
        "key": "CF-TLS-PROTOCOLS",
        "title": "TLS listeners negotiate only modern protocol versions",
        "category": "cryptography",
        "default_severity": Severity.HIGH,
        "description": "SSLv2, SSLv3, TLS 1.0 and TLS 1.1 are deprecated: each has "
        "practical attacks (POODLE, BEAST, Sweet32 against their mandatory ciphers) and "
        "no current client needs them.",
        "expected_state": "TLS 1.2 and TLS 1.3 are offered; SSLv2, SSLv3, TLS 1.0 and "
        "TLS 1.1 are not offered at all.",
        "remediation": "Raise the protocol floor in the listener configuration "
        "(nginx: `ssl_protocols TLSv1.2 TLSv1.3;`, Apache: "
        "`SSLProtocol -all +TLSv1.2 +TLSv1.3`, haproxy: `ssl-min-ver TLSv1.2`). Where a "
        "legacy client genuinely needs an old version, give it a separate listener and "
        "record that listener as an accepted exception rather than lowering the floor "
        "everywhere.",
        "refs": (
            ("owasp-asvs", "9.1.1", "Use only up-to-date TLS versions"),
            ("nist-800-53", "SC-8", "Transmission confidentiality and integrity"),
        ),
    },
    {
        "key": "CF-TLS-CIPHERS",
        "title": "TLS listeners do not offer weak or NULL cipher suites",
        "category": "cryptography",
        "default_severity": Severity.HIGH,
        "description": "NULL suites provide no encryption, EXPORT and LOW suites are "
        "broken by design, and RC4 and single-DES are no longer considered sound.",
        "expected_state": "No NULL, EXPORT, LOW or RC4 suite is offered, and every "
        "offered suite provides at least 128-bit encryption.",
        "remediation": "Restrict the cipher list to ECDHE-based AEAD suites "
        "(nginx: `ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305'; "
        "`ssl_prefer_server_ciphers on;`). Disabling TLS 1.0/1.1 removes the weak suites "
        "they force as a side effect.",
        "refs": (
            ("owasp-asvs", "9.1.2", "Use only approved ciphers"),
            ("nist-800-53", "SC-13", "Cryptographic protection"),
        ),
    },
    {
        "key": "CF-TLS-CERTIFICATE",
        "title": "TLS certificates use strong keys and are within their validity period",
        "category": "cryptography",
        "default_severity": Severity.MEDIUM,
        "description": "A 1024-bit RSA key is within reach of a well-funded adversary, "
        "and an expired certificate trains users to click through the warning that "
        "protects them.",
        "expected_state": "Every certificate presented uses an RSA key of at least 2048 "
        "bits (or an ECDSA key of at least 256 bits) and is not expired.",
        "remediation": "Reissue the certificate with a 2048-bit or larger RSA key (or "
        "ECDSA P-256), and automate renewal so it cannot lapse - ACME for public names, "
        "the internal CA's renewal job for private ones. Alerting on expiry is not a "
        "substitute for automating it.",
        "refs": (
            ("owasp-asvs", "9.1.3", "Use certificates issued by a trusted CA with "
             "adequate key strength"),
            ("nist-800-53", "SC-17", "Public key infrastructure certificates"),
        ),
    },
    {
        "key": "CF-WEB-SECURITY-HEADERS",
        "title": "HTTP responses carry the baseline security headers",
        "category": "network",
        "default_severity": Severity.MEDIUM,
        "description": "MIME sniffing protection, framing restrictions and a content "
        "policy are enforced by the browser only when the response asks for them; "
        "without the headers the browser's permissive defaults apply.",
        "expected_state": "Responses carry `X-Content-Type-Options: nosniff`, an "
        "`X-Frame-Options` (or an equivalent CSP frame-ancestors directive) and a "
        "`Content-Security-Policy`.",
        "remediation": "Add the headers at the edge (nginx `add_header ... always;`) or "
        "in application middleware so every response gets them, including error pages. "
        "Roll a CSP out in report-only mode first: a policy that breaks the application "
        "is a policy that gets switched off.",
        "refs": (
            ("owasp-asvs", "14.4.1", "Responses carry a Content-Type that browsers will "
             "not sniff past (MIME sniffing protection)"),
            ("owasp-asvs", "14.4.7", "Responses define and enforce a content security "
             "policy"),
            ("nist-800-53", "SI-10", "Information input validation"),
        ),
    },
    {
        "key": "CF-SESSION-COOKIE-FLAGS",
        "title": "Session cookies are marked Secure, HttpOnly and SameSite",
        "category": "data_protection",
        "default_severity": Severity.HIGH,
        "description": "A session cookie without Secure travels over plaintext and can "
        "be read by a network attacker; without HttpOnly it is readable by any XSS; "
        "without SameSite it rides along on cross-site requests.",
        "expected_state": "Every session cookie is set with Secure, HttpOnly and an "
        "explicit SameSite of Lax or Strict.",
        "remediation": "Set the flags where the cookie is issued "
        "(`Set-Cookie: session=...; Secure; HttpOnly; SameSite=Lax`) and prefer the "
        "`__Host-` name prefix, which a subdomain cannot overwrite and which requires "
        "the flags to be present.",
        "refs": (
            ("owasp-asvs", "3.4.1", "Cookie-based session tokens use the Secure "
             "attribute"),
            ("owasp-asvs", "3.4.2", "Cookie-based session tokens use the HttpOnly "
             "attribute"),
            ("owasp-asvs", "3.4.3", "Cookie-based session tokens use the SameSite "
             "attribute"),
        ),
    },
    {
        "key": "CF-SENSITIVE-EXPOSURE",
        "title": "Source metadata, configuration files and directory indexes are not "
        "exposed over HTTP",
        "category": "data_protection",
        "default_severity": Severity.HIGH,
        "description": "A deployed document root that still contains version control "
        "metadata, environment files or a directory index hands an attacker the source, "
        "the credentials, or a map of everything else on the host.",
        "expected_state": "Requests for VCS metadata (`/.git/`), environment files "
        "(`/.env`), backup archives and administrative surfaces do not return content, "
        "and directory listings are disabled.",
        "remediation": "Deny the paths at the edge (`location ~ /\\.(git|env|svn|hg) "
        "{ deny all; }`), turn autoindex off, and deploy only built artefacts - source "
        "and dotfiles never belong in the document root. Add the check to the build "
        "pipeline so it fails there rather than in production.",
        "refs": (
            ("owasp-asvs", "14.3.2", "No backup files, source metadata or other "
             "unnecessary files are served"),
            ("nist-800-53", "SC-28", "Protection of information at rest"),
        ),
    },
    {
        "key": "CF-SERVICE-AVAILABILITY",
        "title": "Registered service ports are reachable",
        "category": "network",
        "default_severity": Severity.MEDIUM,
        "description": "The platform can only validate a service it can reach: a port "
        "that stopped answering turns every other control on that target into an "
        "unanswered question.",
        "expected_state": "The port recorded on the target accepts a TCP connection "
        "from the validator.",
        "remediation": "If the service is meant to be up, check the listener, the host "
        "firewall and the service's own logs. If it is not, disable the target so the "
        "platform stops reporting a control state it can no longer verify.",
        "refs": (("nist-800-53", "CM-8", "System component inventory"),),
    },
    {
        "key": "CF-HOST-KERNEL-HARDENING",
        "title": "Host kernel hardening sysctls are set to their recommended values",
        "category": "hardening",
        "default_severity": Severity.MEDIUM,
        "description": "ASLR, reverse path filtering, redirect handling, SYN cookies and "
        "the kernel information restrictions are cheap defences that cost nothing at "
        "runtime and are usually left at their permissive defaults.",
        "expected_state": "Every sysctl in the baseline reports its expected value.",
        "remediation": "Set them persistently in `/etc/sysctl.d/` (for example "
        "`net.ipv4.conf.all.accept_redirects = 0`) and apply with `sysctl --system`. A "
        "one-off `sysctl -w` is lost at the next boot, which is the reboot the control "
        "exists to survive.",
        "refs": (
            ("cis-linux", "1.5", "Kernel hardening parameters are set"),
            ("nist-800-53", "CM-6", "Configuration settings"),
        ),
    },
    {
        "key": "CF-HOST-FILE-PERMISSIONS",
        "title": "Security-relevant files carry permissions no wider than the baseline",
        "category": "hardening",
        "default_severity": Severity.MEDIUM,
        "description": "Credential stores, daemon configuration and service state "
        "directories are only as private as their mode bits; a world-readable secrets "
        "file is a credential leak waiting for a backup to copy it somewhere worse.",
        "expected_state": "Password hashes, the sshd configuration, Valtros's own "
        "secrets file and its state directories are readable only by their intended "
        "users.",
        "remediation": "Tighten the mode (`chmod 0640 /etc/valtros/"
        "valtros.env`), confirm ownership still matches the service account, and "
        "if a wider mode is genuinely required, record the exception in the baseline "
        "rather than leaving the difference unexplained.",
        "refs": (
            ("cis-linux", "6.1", "System file permissions are configured"),
            ("nist-800-53", "AC-6", "Least privilege"),
        ),
    },
    {
        "key": "CF-HOST-SSHD-CONFIG",
        "title": "The SSH daemon refuses root login, password authentication and "
        "forwarding it does not need",
        "category": "access_control",
        "default_severity": Severity.HIGH,
        "description": "SSH is the management path that survives every other control "
        "failing; password authentication makes it brute-forceable and direct root "
        "login removes the audit trail a named account would have left.",
        "expected_state": "sshd_config sets PermitRootLogin no, "
        "PasswordAuthentication no, X11Forwarding no and MaxAuthTries at or below 4, "
        "with public key authentication available.",
        "remediation": "Set the directives in `/etc/ssh/sshd_config` or a drop-in under "
        "`/etc/ssh/sshd_config.d/`, check the result with `sshd -t`, and reload. Do it "
        "from a second session: a typo here locks out the connection you are working "
        "over.",
        "refs": (
            ("cis-linux", "5.2", "SSH server configuration is hardened"),
            ("nist-800-53", "AC-17", "Remote access"),
        ),
    },
)

# ---------------------------------------------------------------------- tests --

# Every assertion below selects facts by type and field, never by tool text -
# the evaluator is what turns the selection into a verdict, and an empty
# selection is INCONCLUSIVE rather than a pass.

TESTS: tuple[dict[str, Any], ...] = (
    {
        "key": "cf-tls-protocol-floor",
        "name": "TLS protocol versions offered",
        "control": "CF-TLS-PROTOCOLS",
        "engine": "tls_config",
        "engine_params": {"check_vulnerabilities": False, "max_wait_seconds": 300},
        "assertion": {
            "all": [
                {"fact": "tls_protocol", "where": {"key": "SSLv2"},
                 "op": "eq", "value_path": "offered", "value": False},
                {"fact": "tls_protocol", "where": {"key": "SSLv3"},
                 "op": "eq", "value_path": "offered", "value": False},
                {"fact": "tls_protocol", "where": {"key": "TLS1"},
                 "op": "eq", "value_path": "offered", "value": False},
                {"fact": "tls_protocol", "where": {"key": "TLS1_1"},
                 "op": "eq", "value_path": "offered", "value": False},
                {"fact": "tls_protocol", "where": {"key": "TLS1_2"},
                 "op": "eq", "value_path": "offered", "value": True},
            ]
        },
        "severity": Severity.HIGH,
        "tags": ["lab", "tls", "crypto"],
        "selector": {"tags": ["tls"]},
        "description": "testssl.sh reports each protocol version's offer state; the "
        "assertion reads those facts, so a version the tool could not assess leaves the "
        "control INCONCLUSIVE instead of passing it.",
    },
    {
        "key": "cf-tls-cipher-strength",
        "name": "TLS cipher suites offered",
        "control": "CF-TLS-CIPHERS",
        "engine": "tls_config",
        "engine_params": {"check_vulnerabilities": False, "max_wait_seconds": 300},
        "assertion": {
            "all": [
                {"fact": "tls_cipher", "where": {"key": "cipherlist_NULL"},
                 "op": "eq", "value_path": "offered", "value": False},
                {"fact": "tls_cipher", "where": {"key": "cipherlist_EXPORT"},
                 "op": "eq", "value_path": "offered", "value": False},
                {"fact": "tls_cipher", "where": {"key": "cipherlist_LOW"},
                 "op": "eq", "value_path": "offered", "value": False},
                {"fact": "tls_cipher", "where": {"value.kind": "supported"},
                 "op": "gte", "value_path": "bits", "value": 128},
            ]
        },
        "severity": Severity.HIGH,
        "tags": ["lab", "tls", "crypto"],
        "selector": {"tags": ["tls"]},
        "description": "The last assertion reads the bit length of every supported "
        "suite. A suite whose columns could not be parsed reports no bit length, which "
        "makes that fact inconclusive rather than silently compliant.",
    },
    {
        "key": "cf-tls-certificate-posture",
        "name": "TLS certificate key strength and validity",
        "control": "CF-TLS-CERTIFICATE",
        "engine": "tls_config",
        "engine_params": {"check_vulnerabilities": False, "max_wait_seconds": 300},
        "assertion": {
            "all": [
                {"fact": "tls_certificate", "where": {"key": "cert_keySize"},
                 "op": "eq", "value_path": "weak", "value": False},
                {"fact": "tls_certificate", "where": {"key": "cert_expirationStatus"},
                 "op": "eq", "value_path": "expired", "value": False},
            ]
        },
        "severity": Severity.MEDIUM,
        "tags": ["lab", "tls", "crypto"],
        "selector": {"tags": ["tls"]},
        "note": "Issuer trust is deliberately not asserted here: the lab certificate is "
        "self-signed by design, and a control that always fails on a lab artefact "
        "teaches an operator to ignore it.",
        "description": "Key strength and expiry are the two certificate properties a "
        "tool can read objectively; trust depends on the verifying system's trust store "
        "and is not this control's question.",
    },
    {
        "key": "cf-web-security-headers",
        "name": "Baseline security headers on a response",
        "control": "CF-WEB-SECURITY-HEADERS",
        "engine": "http_headers",
        "engine_params": {"path": "/", "method": "GET"},
        "assertion": {
            "all": [
                {"fact": "http_header", "where": {"key": "x-content-type-options"},
                 "op": "eq", "value_path": "value", "value": "nosniff"},
                {"fact": "http_header", "where": {"key": "x-frame-options"},
                 "op": "exists",
                 "reason": "responses must restrict how the page may be framed"},
                {"fact": "http_header", "where": {"key": "content-security-policy"},
                 "op": "exists",
                 "reason": "responses must state a content policy, even a permissive "
                 "one, so it can be tightened deliberately"},
            ]
        },
        "severity": Severity.MEDIUM,
        "tags": ["lab", "web", "headers"],
        "selector": {"tags": ["headers"]},
        "description": "Header presence is an existence question, so a missing header "
        "is a FAIL rather than an inconclusive - the response was read and did not "
        "carry it.",
    },
    {
        "key": "cf-session-cookie-flags",
        "name": "Session cookie attributes",
        "control": "CF-SESSION-COOKIE-FLAGS",
        "engine": "http_headers",
        "engine_params": {"path": "/login", "method": "GET"},
        "assertion": {
            "all": [
                {"fact": "http_cookie", "where": {"key": "session"},
                 "op": "eq", "value_path": "secure", "value": True},
                {"fact": "http_cookie", "where": {"key": "session"},
                 "op": "eq", "value_path": "httponly", "value": True},
                {"fact": "http_cookie", "where": {"key": "session"},
                 "op": "in", "value_path": "samesite", "value": ["strict", "lax"]},
            ]
        },
        "severity": Severity.HIGH,
        "tags": ["lab", "web", "cookies"],
        "selector": {"tags": ["app"]},
        "description": "The SameSite assertion is a membership test rather than "
        "`not none`, so a cookie that carries no SameSite attribute fails it: the "
        "engine reports an absent attribute as false, not as an unreadable value.",
    },
    {
        "key": "cf-exposure-config-and-source",
        "name": "Configuration files and VCS metadata are not served",
        "control": "CF-SENSITIVE-EXPOSURE",
        "engine": "http_exposure",
        "engine_params": {"profile": "web", "method": "GET"},
        "assertion": {
            "fact": "path_exposed",
            "where": {"value.exposed": True},
            "op": "not_exists",
            "reason": "no probed path may return content",
        },
        "severity": Severity.HIGH,
        "tags": ["lab", "web", "exposure"],
        "selector": {"tags": ["app"]},
        "description": "The engine compares each response against a soft-404 baseline "
        "before calling it exposed, so a server that answers everything with 200 does "
        "not produce eleven findings from one template.",
    },
    {
        "key": "cf-exposure-directory-listing",
        "name": "Directory listings are disabled",
        "control": "CF-SENSITIVE-EXPOSURE",
        "engine": "http_exposure",
        "engine_params": {"profile": "dirlist", "method": "GET"},
        "assertion": {
            "fact": "path_exposed",
            "where": {"value.exposed": True},
            "op": "not_exists",
            "reason": "no directory may list its contents",
        },
        "severity": Severity.MEDIUM,
        "tags": ["lab", "web", "exposure"],
        "selector": {"tags": ["headers"]},
        "description": "A second test for the same control: the control is one "
        "expectation, and more than one procedure can verify it.",
    },
    {
        "key": "cf-web-nuclei-exposures",
        "name": "Template checks find nothing on the web surface",
        "control": "CF-WEB-SECURITY-HEADERS",
        "engine": "nuclei",
        "engine_params": {
            "template_tags": ["headers", "misconfiguration", "exposure", "cors"],
            "severities": ["info", "low", "medium", "high", "critical"],
            "rate_limit": 25,
        },
        "assertion": {
            "fact": "nuclei_finding",
            "op": "not_exists",
            "reason": "no template matched at any severity",
        },
        "severity": Severity.LOW,
        "tags": ["lab", "web", "nuclei"],
        "selector": {"tags": ["headers"]},
        "description": "Restricted to the non-intrusive HTTP template classes, with "
        "interactsh and template auto-update both off, so the run reaches nothing "
        "except the authorized target.",
    },
    {
        "key": "cf-service-port-reachable",
        "name": "The registered port accepts a connection",
        "control": "CF-SERVICE-AVAILABILITY",
        "engine": "nmap",
        "engine_params": {"ports": "8081,8082,8083,8084", "service_detection": True},
        "assertion": {
            "fact": "port_state",
            "where": {"value.open": True},
            "op": "count_gte",
            "value": 1,
            "reason": "at least one scanned port answers",
        },
        "severity": Severity.MEDIUM,
        "tags": ["lab", "network", "inventory"],
        # Tag sets are a subset match (a target must carry every tag), so the
        # selector names one tag: "web" reaches all three HTTP listeners.
        "selector": {"tags": ["web"]},
        "description": "Runs against every web and API target in the lab, scanning the "
        "four published ports. A target which stops answering fails here before its "
        "other controls start returning inconclusives.",
    },
    {
        "key": "cf-host-kernel-hardening",
        "name": "Kernel hardening sysctls",
        "control": "CF-HOST-KERNEL-HARDENING",
        "engine": "local_baseline",
        "engine_params": {"checks": ["sysctls"]},
        "assertion": {
            "fact": "sysctl",
            "op": "eq",
            "value_path": "compliant",
            "value": True,
            "reason": "every readable sysctl matches the baseline",
        },
        "severity": Severity.MEDIUM,
        "tags": ["lab", "host", "hardening"],
        "selector": {"tags": ["local"]},
        "description": "A sysctl this process cannot read is reported at zero "
        "confidence and left out of the comparison, so the control is judged only on "
        "the values that were actually observed.",
    },
    {
        "key": "cf-host-file-permissions",
        "name": "File permissions against the baseline",
        "control": "CF-HOST-FILE-PERMISSIONS",
        "engine": "local_baseline",
        "engine_params": {"checks": ["file_modes"]},
        "assertion": {
            "fact": "file_mode",
            "op": "eq",
            "value_path": "compliant",
            "value": True,
            "reason": "no path is more permissive than its rule allows",
        },
        "severity": Severity.MEDIUM,
        "tags": ["lab", "host", "hardening"],
        "selector": {"tags": ["local"]},
        "description": "Includes Valtros's own secrets file and state "
        "directories: the platform is subject to the same baseline it verifies.",
    },
    {
        "key": "cf-host-sshd-config",
        "name": "sshd configuration against the baseline",
        "control": "CF-HOST-SSHD-CONFIG",
        "engine": "local_baseline",
        "engine_params": {"checks": ["sshd_config"]},
        "assertion": {
            "all": [
                {"fact": "sshd_setting", "where": {"key": "permitrootlogin"},
                 "op": "eq", "value_path": "compliant", "value": True},
                {"fact": "sshd_setting", "where": {"key": "passwordauthentication"},
                 "op": "eq", "value_path": "compliant", "value": True},
                {"fact": "sshd_setting", "where": {"key": "x11forwarding"},
                 "op": "eq", "value_path": "compliant", "value": True},
                {"fact": "sshd_setting", "where": {"key": "maxauthtries"},
                 "op": "eq", "value_path": "compliant", "value": True},
                {"fact": "sshd_setting", "where": {"key": "pubkeyauthentication"},
                 "op": "eq", "value_path": "compliant", "value": True},
            ]
        },
        "severity": Severity.HIGH,
        "tags": ["lab", "host", "access"],
        "selector": {"tags": ["local"]},
        "description": "A keyword the file does not set reports a null compliance "
        "rather than a false one - the sshd default applies and this engine cannot read "
        "which default that build compiled in - so that keyword comes back "
        "INCONCLUSIVE while a keyword that is set and wrong fails the control.",
    },
)

# -------------------------------------------------------------------- targets --

TARGETS: tuple[dict[str, Any], ...] = (
    {
        "name": "lab-headers",
        "target_type": TargetType.WEBAPP,
        "host": "127.0.0.1",
        "port": 8081,
        "protocol": "http",
        "tags": ["lab", "web", "headers", "nginx"],
        "criticality": Severity.MEDIUM,
        "owner": "platform team",
        "notes": "nginx with server_tokens on, no security headers and autoindex "
        "enabled on /files/ - the deliberate counterpart to the header and listing "
        "controls.",
    },
    {
        "name": "lab-webapp",
        "target_type": TargetType.WEBAPP,
        "host": "127.0.0.1",
        "port": 8082,
        "protocol": "http",
        "tags": ["lab", "web", "app"],
        "criticality": Severity.HIGH,
        "owner": "platform team",
        "notes": "A small Python application with the weaknesses a real one grows: an "
        "unauthenticated /admin, exposed .git and .env, a session cookie with no flags, "
        "wildcard CORS and a traceback on error. All values in its .env are fake.",
    },
    {
        "name": "lab-api",
        "target_type": TargetType.API,
        "host": "127.0.0.1",
        "port": 8083,
        "protocol": "http",
        "tags": ["lab", "api"],
        "criticality": Severity.MEDIUM,
        "owner": "platform team",
        "notes": "Stub API surface with an unauthenticated administrative endpoint.",
    },
    {
        "name": "juice-shop",
        "target_type": TargetType.WEBAPP,
        "host": "127.0.0.1",
        "port": 8084,
        "protocol": "http",
        "tags": ["lab", "web", "juice"],
        "criticality": Severity.LOW,
        "owner": "platform team",
        "notes": "OWASP Juice Shop, kept as a third-party target whose behaviour the "
        "platform did not design - the honesty check on the engines.",
    },
    {
        "name": "lab-weaktls",
        "target_type": TargetType.TLS,
        "host": "127.0.0.1",
        "port": 8443,
        "protocol": "tcp",
        "tags": ["lab", "tls"],
        "criticality": Severity.HIGH,
        "owner": "platform team",
        "notes": "TLS 1.0/1.1 with NULL cipher suites and a 1024-bit self-signed "
        "certificate - everything the cryptography controls exist to catch.",
    },
    {
        "name": "lab-ssh",
        "target_type": TargetType.SSH,
        "host": "127.0.0.1",
        "port": 2222,
        "protocol": "tcp",
        "tags": ["lab", "ssh"],
        "criticality": Severity.MEDIUM,
        "owner": "platform team",
        "notes": "sshd permitting root login and password authentication (lab toy "
        "credentials only).",
    },
    {
        "name": "valtros-host",
        "target_type": TargetType.LOCAL,
        "host": "127.0.0.1",
        "port": 0,
        "protocol": "tcp",
        "tags": ["lab", "local"],
        "criticality": Severity.HIGH,
        "owner": "platform team",
        "notes": "The machine Valtros runs on, validated by the local baseline "
        "engine, which opens no sockets at all.",
    },
)

# --------------------------------------------------------------------- scopes --

SCOPES: tuple[dict[str, Any], ...] = (
    {
        "name": LAB_SCOPE_NAME,
        "description": "The platform's own lab containers, published on loopback.",
        "is_lab": True,
        "entries": (
            {
                "kind": ScopeEntryKind.HOST,
                "value": "127.0.0.1",
                "ports": LAB_PORTS,
                "protocol": "tcp",
                "note": "the lab's published ports",
            },
        ),
        "targets": (
            "lab-headers",
            "lab-webapp",
            "lab-api",
            "juice-shop",
            "lab-weaktls",
            "lab-ssh",
        ),
    },
    {
        "name": HOST_SCOPE_NAME,
        "description": "The machine Valtros runs on. Registered so the local "
        "baseline has a scope to run under, with no network ports: every network "
        "engine pointed at this target is refused before it starts.",
        "is_lab": True,
        "entries": (
            {
                "kind": ScopeEntryKind.HOST,
                "value": "127.0.0.1",
                "ports": "",
                "protocol": "tcp",
                "note": "local inspection only - no port is authorized",
            },
        ),
        "targets": ("valtros-host",),
    },
)


# ------------------------------------------------------------------ seeding --


# The catalogue rows the seeder is responsible for, with the field that names
# each one in an audit record.
_CATALOGUE: dict[str, tuple[Any, Any]] = {
    "framework": (Framework, lambda row: row.key),
    "control": (Control, lambda row: row.key),
    "target": (Target, lambda row: row.name),
    "scope": (Scope, lambda row: row.name),
    "test": (ValidationTest, lambda row: row.key),
}


def _get_or_create(db: OrmSession, model, *, key_field: str, keys: dict, **values) -> tuple[Any, bool]:
    existing = db.execute(
        select(model).where(getattr(model, key_field) == keys[key_field])
    ).scalar_one_or_none()
    if existing is not None:
        return existing, False
    row = model(**keys, **values)
    db.add(row)
    db.flush()
    return row, True


def _seed_frameworks(db: OrmSession) -> dict[str, Framework]:
    frameworks: dict[str, Framework] = {}
    for spec in FRAMEWORKS:
        values = {k: v for k, v in spec.items() if k != "key"}
        framework, _ = _get_or_create(
            db, Framework, key_field="key", keys={"key": spec["key"]}, **values
        )
        frameworks[spec["key"]] = framework
    return frameworks


def _seed_controls(
    db: OrmSession, frameworks: dict[str, Framework]
) -> dict[str, Control]:
    controls: dict[str, Control] = {}
    for spec in CONTROLS:
        values = {
            key: value
            for key, value in spec.items()
            if key not in ("key", "refs")
        }
        control, _ = _get_or_create(
            db, Control, key_field="key", keys={"key": spec["key"]}, **values
        )
        controls[spec["key"]] = control

        for framework_key, ref_code, title in spec.get("refs", ()):
            framework = frameworks[framework_key]
            exists = db.execute(
                select(FrameworkRef).where(
                    FrameworkRef.framework_id == framework.id,
                    FrameworkRef.ref_code == ref_code,
                )
            ).scalar_one_or_none()
            if exists is None:
                db.add(
                    FrameworkRef(
                        framework_id=framework.id,
                        control_id=control.id,
                        ref_code=ref_code,
                        title=title,
                    )
                )
    db.flush()
    return controls


def _seed_targets(db: OrmSession) -> dict[str, Target]:
    targets: dict[str, Target] = {}
    for spec in TARGETS:
        identity = {
            "host": spec["host"],
            "port": spec["port"],
            "protocol": spec["protocol"],
            "path": spec.get("path", ""),
        }
        existing = db.execute(
            select(Target).where(
                Target.host == identity["host"],
                Target.port == identity["port"],
                Target.protocol == identity["protocol"],
                Target.path == identity["path"],
            )
        ).scalar_one_or_none()
        if existing is not None:
            targets[spec["name"]] = existing
            continue
        target = Target(
            name=spec["name"],
            target_type=spec["target_type"],
            tags=list(spec.get("tags", ())),
            criticality=spec.get("criticality", Severity.MEDIUM),
            owner=spec.get("owner"),
            notes=spec.get("notes"),
            **identity,
        )
        db.add(target)
        db.flush()
        targets[spec["name"]] = target
    return targets


def _seed_scopes(db: OrmSession, targets: dict[str, Target]) -> dict[str, Scope]:
    scopes: dict[str, Scope] = {}
    for spec in SCOPES:
        scope, _ = _get_or_create(
            db,
            Scope,
            key_field="name",
            keys={"name": spec["name"]},
            description=spec["description"],
            is_lab=spec["is_lab"],
            active=True,
        )
        scopes[spec["name"]] = scope

        for entry in spec["entries"]:
            exists = db.execute(
                select(ScopeEntry).where(
                    ScopeEntry.scope_id == scope.id,
                    ScopeEntry.kind == entry["kind"],
                    ScopeEntry.value == entry["value"],
                    ScopeEntry.ports == entry["ports"],
                    ScopeEntry.protocol == entry["protocol"],
                )
            ).scalar_one_or_none()
            if exists is None:
                db.add(ScopeEntry(scope_id=scope.id, **entry))

        for target_name in spec["targets"]:
            target = targets[target_name]
            link = db.get(TargetScope, (target.id, scope.id))
            if link is None:
                db.add(TargetScope(target_id=target.id, scope_id=scope.id))
    db.flush()
    return scopes


def _seed_tests(db: OrmSession, controls: dict[str, Control]) -> dict[str, ValidationTest]:
    tests: dict[str, ValidationTest] = {}
    for spec in TESTS:
        control = controls[spec["control"]]
        engine = get_engine(spec["engine"])
        if engine is None:
            raise RuntimeError(
                f"test {spec['key']!r} names engine {spec['engine']!r}, which is not "
                "in the catalogue"
            )
        # Both checks happen against the same catalogue the API validates with:
        # a parameter typo or an assertion over a fact type the engine never
        # emits should fail here, at seeding, not silently at the first run.
        engine.params.model_validate(spec["engine_params"])
        validate_assertion(spec["assertion"], fact_types_for(spec["engine"]))

        test, created = _get_or_create(
            db,
            ValidationTest,
            key_field="key",
            keys={"key": spec["key"]},
            name=spec["name"],
            description=spec.get("description"),
            control_id=control.id,
            tags=list(spec.get("tags", ())),
            target_selector=spec.get("selector", {}),
            enabled=True,
        )
        tests[spec["key"]] = test

        if created or not test.versions:
            version = ValidationTestVersion(
                version=1,
                engine_id=spec["engine"],
                engine_params=spec["engine_params"],
                assertion=spec["assertion"],
                control_id=control.id,
                severity=spec.get("severity", control.default_severity),
                note=spec.get("note"),
            )
            test.versions.append(version)
            test.current_version = 1
    db.flush()
    return tests


def seed_lab(db: OrmSession) -> dict[str, int]:
    """Seed the lab catalog. Idempotent: run it as often as you like."""
    before = {
        name: set(db.execute(select(model.id)).scalars())
        for name, (model, _) in _CATALOGUE.items()
    }

    frameworks = _seed_frameworks(db)
    controls = _seed_controls(db, frameworks)
    targets = _seed_targets(db)
    scopes = _seed_scopes(db, targets)
    tests = _seed_tests(db, controls)
    db.commit()

    created: dict[str, list[str]] = {}
    for name, (model, label) in _CATALOGUE.items():
        seen = before[name]
        stmt = select(model) if not seen else select(model).where(model.id.notin_(seen))
        rows = db.execute(stmt).scalars().all()
        if rows:
            created[name] = sorted(label(row) for row in rows)

    if created:
        audit.record(
            db,
            action="catalog.seed",
            object_type="catalog",
            detail=created,
            commit=True,
        )

    counts = {
        "frameworks": len(frameworks),
        "controls": len(controls),
        "targets": len(targets),
        "scopes": len(scopes),
        "tests": len(tests),
    }
    logger.info(
        "lab catalog present: %s controls, %s tests, %s targets, %s scopes",
        counts["controls"],
        counts["tests"],
        counts["targets"],
        counts["scopes"],
    )
    return counts


# --------------------------------------------------------------- running it --


def _targets_for(db: OrmSession, test: ValidationTest) -> list[Target]:
    """The enabled targets a test's selector names, filtered by engine support.

    The selector is a tag set: a test tagged ``{"tags": ["headers"]}`` runs
    against the targets carrying that tag. Tag matching is deliberately not a
    query language - a selector nobody can read is a selector nobody will audit.
    """
    wanted = set((test.target_selector or {}).get("tags", ()))
    spec = get_engine(test.versions[-1].engine_id) if test.versions else None
    if spec is None:
        return []

    targets = db.execute(select(Target).where(Target.enabled.is_(True))).scalars().all()
    return [
        target
        for target in targets
        if wanted <= set(target.tags or ()) and target.target_type in spec.target_types
    ]


def enqueue_suite(
    db: OrmSession,
    *,
    tags: list[str] | None = None,
    user_id: int | None = None,
) -> list[ValidationRun]:
    """Queue every enabled test against every target its selector matches.

    A (test version, target) pair that is already queued or running is skipped,
    so pressing the button twice does not double the queue.
    """
    wanted = set(tags or ())
    tests = db.execute(select(ValidationTest).where(ValidationTest.enabled.is_(True))).scalars().all()

    active = set(
        db.execute(
            select(ValidationRun.test_id, ValidationRun.target_id).where(
                ValidationRun.status.in_((RunStatus.QUEUED, RunStatus.RUNNING))
            )
        ).all()
    )

    queued: list[ValidationRun] = []
    for test in tests:
        if wanted and not (wanted & set(test.tags or ())):
            continue
        if not test.versions:
            logger.warning("test %s has no version; skipped", test.key)
            continue
        version = test.versions[-1]
        spec = get_engine(version.engine_id)
        if spec is None:
            logger.warning("test %s names unknown engine %s; skipped", test.key, version.engine_id)
            continue
        for target in _targets_for(db, test):
            if (test.id, target.id) in active:
                logger.info(
                    "skipped %s against %s: a run is already queued or running",
                    test.key,
                    target.name,
                )
                continue
            run = jobs.enqueue(
                db,
                test_id=test.id,
                test_version_id=version.id,
                target_id=target.id,
                engine_id=version.engine_id,
                timeout_seconds=spec.default_timeout,
                trigger=TriggerKind.MANUAL,
                authorized_by_user_id=user_id,
            )
            queued.append(run)
            logger.info("queued %s against %s (run %s)", test.key, target.name, run.id)
    db.commit()
    return queued


def main() -> None:
    from app.db import SessionLocal, engine

    parser = argparse.ArgumentParser(description="Seed the Valtros lab catalog.")
    parser.add_argument(
        "--run",
        action="store_true",
        help="also queue every enabled test against the targets its selector matches",
    )
    parser.add_argument(
        "--tag",
        action="append",
        default=None,
        help="only queue tests carrying this tag (repeatable); implies --run",
    )
    parser.add_argument("--user", default=None, help="username to attribute the runs to")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    with SessionLocal() as db:
        counts = seed_lab(db)

        queued: list[ValidationRun] = []
        if args.run or args.tag:
            user_id = None
            if args.user:
                from app.models.auth import User

                user = db.execute(
                    select(User).where(User.username == args.user)
                ).scalar_one_or_none()
                if user is None:
                    raise SystemExit(f"no user named {args.user!r}")
                user_id = user.id
            queued = enqueue_suite(db, tags=args.tag, user_id=user_id)

    engine.dispose()

    print(f"frameworks : {counts['frameworks']}")
    print(f"controls   : {counts['controls']}")
    print(f"tests      : {counts['tests']}")
    print(f"targets    : {counts['targets']}")
    print(f"scopes     : {counts['scopes']}")
    if args.run or args.tag:
        print(f"queued     : {len(queued)} run(s)")
        for run in queued:
            print(f"  run {run.id}")


if __name__ == "__main__":
    main()
