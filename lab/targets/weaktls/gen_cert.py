#!/usr/bin/env python3
"""Generate a deliberately weak self-signed X.509 certificate + RSA key using
ONLY the Python standard library (no OpenSSL CLI, no `cryptography` package).

Why hand-rolled DER: the Valtros lab must build fully offline from three
already-pulled base images, none of which ship the `openssl` CLI. This script
runs in a python:3.12-alpine build stage.

Weaknesses baked in on purpose (for the lab-weaktls target):
  * RSA-1024 key (flagged by testssl.sh / nuclei as too weak)
  * 2-day validity (makes cert-expiry assertions meaningful)
  * self-signed, CN only, no SAN (no subjectAltName)
  * SHA-256 signature (kept valid so TLS stacks actually accept the cert;
    protocol/cipher weaknesses are the point of this target, not the hash)

Outputs: <outdir>/server.crt (PEM cert), <outdir>/server.key (PEM PKCS#1 key)
"""
import base64
import hashlib
import math
import os
import secrets
import sys
import time

# --------------------------------------------------------------------------
# Minimal DER encoder
# --------------------------------------------------------------------------

def der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + der_len(len(payload)) + payload


def der_uint(i: int) -> bytes:
    """DER INTEGER from a non-negative Python int (two's-complement minimal)."""
    b = i.to_bytes(max(1, (i.bit_length() + 7) // 8), "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return tlv(0x02, b)


def der_oid(dotted: str) -> bytes:
    parts = [int(x) for x in dotted.split(".")]
    body = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        enc = [p & 0x7F]
        p >>= 7
        while p:
            enc.append(0x80 | (p & 0x7F))
            p >>= 7
        body += bytes(reversed(enc))
    return tlv(0x06, body)


def der_utf8(s: str) -> bytes:
    return tlv(0x0C, s.encode("utf-8"))


def der_utctime(epoch: float) -> bytes:
    return tlv(0x17, time.strftime("%y%m%d%H%M%SZ", time.gmtime(epoch)).encode())


def pem(der: bytes, label: str) -> str:
    b64 = base64.b64encode(der).decode()
    lines = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN {label}-----\n{lines}\n-----END {label}-----\n"


# --------------------------------------------------------------------------
# RSA key generation (Miller-Rabin, pure stdlib)
# --------------------------------------------------------------------------

_SMALL_PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
    71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149,
    151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
    233, 239, 241, 251,
]


def is_probable_prime(n: int, rounds: int = 32) -> bool:
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_prime(bits: int) -> int:
    while True:
        cand = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if cand.bit_length() != bits:
            continue
        if is_probable_prime(cand):
            return cand


def gen_rsa(bits: int = 1024):
    e = 65537
    while True:
        p = gen_prime(bits // 2)
        q = gen_prime(bits // 2)
        if p == q:
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        lcm = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)
        if math.gcd(e, lcm) != 1:
            continue
        d = pow(e, -1, lcm)
        return n, e, d, p, q


# --------------------------------------------------------------------------
# X.509 certificate (v3, self-signed)
# --------------------------------------------------------------------------

def build_cert(n, e, d, p_, q_, cn="lab-weaktls.local", days=2):
    A = "1.2.840.113549.1.1"
    alg_sha256_rsa = tlv(0x30, der_oid(f"{A}.11") + tlv(0x05, b""))  # sha256WithRSAEncryption
    alg_rsa_enc = tlv(0x30, der_oid(f"{A}.1") + tlv(0x05, b""))      # rsaEncryption

    # Name: RDNSequence = SEQ { SET { SEQ { OID commonName, UTF8String } } }
    name = tlv(0x30, tlv(0x31, tlv(0x30, der_oid("2.5.4.3") + der_utf8(cn))))

    spki = tlv(0x30, alg_rsa_enc + tlv(0x03, b"\x00" + tlv(0x30, der_uint(n) + der_uint(e))))

    now = time.time()
    serial = secrets.randbits(62) | (1 << 61)

    tbs = tlv(
        0x30,
        tlv(0xA0, der_uint(2))                                   # version v3
        + der_uint(serial)
        + alg_sha256_rsa
        + name                                                   # issuer == subject (self-signed)
        + tlv(0x30, der_utctime(now - 3600) + der_utctime(now + days * 86400))
        + name
        + spki,
    )

    digest = hashlib.sha256(tbs).digest()
    digest_info = tlv(0x30, alg_sha256_rsa + tlv(0x04, digest))
    k = (n.bit_length() + 7) // 8
    ps_len = k - len(digest_info) - 3
    if ps_len < 8:
        raise RuntimeError("RSA modulus too small for PKCS#1 v1.5 padding")
    em = b"\x00\x01" + b"\xff" * ps_len + b"\x00" + digest_info
    sig = pow(int.from_bytes(em, "big"), d, n).to_bytes(k, "big")

    cert = tlv(0x30, tbs + alg_sha256_rsa + tlv(0x03, b"\x00" + sig))
    key = tlv(
        0x30,
        der_uint(0)
        + der_uint(n) + der_uint(e) + der_uint(d)
        + der_uint(p_) + der_uint(q_)
        + der_uint(d % (p_ - 1)) + der_uint(d % (q_ - 1)) + der_uint(pow(q_, -1, p_)),
    )
    return cert, key


def main() -> int:
    outdir = sys.argv[1] if len(sys.argv) > 1 else "/certs"
    os.makedirs(outdir, exist_ok=True)

    n, e, d, p, q = gen_rsa(1024)
    cert, key = build_cert(n, e, d, p, q)

    crt_path = os.path.join(outdir, "server.crt")
    key_path = os.path.join(outdir, "server.key")
    with open(crt_path, "w") as f:
        f.write(pem(cert, "CERTIFICATE"))
    with open(key_path, "w", newline="\n") as f:
        f.write(pem(key, "RSA PRIVATE KEY"))
    os.chmod(key_path, 0o600)
    os.chmod(crt_path, 0o644)

    print(f"wrote {crt_path} ({len(cert)} bytes DER) and {key_path} (RSA-1024, {2}-day validity)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
