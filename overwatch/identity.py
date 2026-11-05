"""Identity certificates (PID) for OverWatch users.

When a user is created, OverWatch captures the fingerprint of the connection
they were created on and issues a structured, signed **identity certificate**
with a stable persistent id (PID). The certificate is an application-level
credential — a canonical JSON document signed with an HMAC over the server
secret, tamper-evident and verifiable — not an X.509/CA certificate (transport
PKI is handled separately by the user-designated TLS certs).

The certificate and the connection fingerprint are stored in the shared SQLite
database so the identity can be cross-referenced across the platform (users,
devices, and the activity log).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import socket
from datetime import datetime, timezone
from typing import Optional

CERT_TYPE = "overwatch-identity-certificate"
CERT_VERSION = 1


def _canonical(data: dict) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def fingerprint_hash(conn_fp: dict) -> str:
    return hashlib.sha256(_canonical(conn_fp).encode("utf-8")).hexdigest()


def connection_fingerprint(request) -> dict:
    """Best-effort fingerprint of the HTTP connection a user is created on."""
    forwarded = request.headers.get("X-Forwarded-For", "")
    client_ip = (forwarded.split(",")[0].strip() if forwarded else "") or (
        request.remote_addr or ""
    )
    env = request.environ
    # Populated only under mTLS front-ends; harmless when absent.
    client_cert_subject = env.get("SSL_CLIENT_S_DN", "") or env.get(
        "HTTP_X_SSL_CLIENT_S_DN", ""
    )
    return {
        "ip": client_ip,
        "scheme": request.scheme,
        "user_agent": request.headers.get("User-Agent", "")[:300],
        "accept_language": request.headers.get("Accept-Language", "")[:120],
        "client_cert_subject": client_cert_subject[:300],
    }


def local_fingerprint(origin: str = "cli") -> dict:
    """Fingerprint for a non-HTTP creation path (e.g. the CLI)."""
    return {
        "ip": "local",
        "scheme": origin,
        "user_agent": f"overwatch-{origin}",
        "accept_language": "",
        "client_cert_subject": "",
        "host": socket.gethostname(),
    }


def _sign(secret_key: str, cert: dict) -> str:
    payload = {k: v for k, v in cert.items() if k != "signature"}
    return hmac.new(
        secret_key.encode("utf-8"), _canonical(payload).encode("utf-8"), hashlib.sha256
    ).hexdigest()


def issue_certificate(
    secret_key: str,
    user_id: int,
    username: str,
    conn_fp: dict,
    role: str = "viewer",
) -> tuple[str, dict]:
    """Issue a signed identity certificate. Returns (pid, cert_dict).

    The PID aligns to the connection fingerprint: it embeds a short hash of the
    fingerprint the user was created on, so the identity and its origin are
    bound together."""
    fph = fingerprint_hash(conn_fp)
    pid = f"OW-{user_id:06d}-{fph[:12]}"
    cert = {
        "version": CERT_VERSION,
        "type": CERT_TYPE,
        "serial": secrets.token_hex(8),
        "pid": pid,
        "subject": username,
        "role": role,
        "issuer": "OverWatch",
        "issued_at": _now(),
        "connection_fingerprint": conn_fp,
        "fingerprint_sha256": fph,
    }
    cert["signature"] = _sign(secret_key, cert)
    return pid, cert


def verify_certificate(secret_key: str, cert: Optional[dict]) -> bool:
    """Return True if the certificate's signature matches the server secret."""
    if not isinstance(cert, dict) or "signature" not in cert:
        return False
    expected = _sign(secret_key, cert)
    return hmac.compare_digest(expected, str(cert.get("signature", "")))
