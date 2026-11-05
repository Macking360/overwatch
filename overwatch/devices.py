"""Device token helpers for BYOD network enrollment.

A device token has the form ``<device_id>.<secret>``. Only a hash of the secret
is stored (via Werkzeug), so the database never holds a usable token. The
device presents the full token as a Bearer credential when posting events.
"""

from __future__ import annotations

import secrets
from typing import Optional

from werkzeug.security import check_password_hash, generate_password_hash

from .db import Database


def issue_token(db: Database, name: str, platform: str = "", fingerprint: str = "") -> str:
    """Create a device row and return its one-time full token."""
    secret = secrets.token_urlsafe(24)
    device_id = db.add_device(name, generate_password_hash(secret), platform, fingerprint)
    return f"{device_id}.{secret}"


def verify_token(db: Database, token: str) -> Optional[int]:
    """Return the device id if the token is valid and the device is active."""
    if not token or "." not in token:
        return None
    id_part, _, secret = token.partition(".")
    if not id_part.isdigit():
        return None
    device = db.get_device(int(id_part))
    if device is None or device["status"] != "active":
        return None
    if not check_password_hash(device["token_hash"], secret):
        return None
    return int(device["id"])
