"""Runtime configuration for OverWatch.

Everything is read from the environment with safe defaults so the app runs with
zero setup, while still letting an operator pin values (secret key, DB path,
alert webhook) explicitly. The Flask secret key is generated once and persisted
to the instance dir with tight permissions — never hard-coded.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
DEFAULT_INSTANCE = APP_DIR.parent / "instance"


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def _load_or_create_secret(instance_dir: Path) -> str:
    env = os.environ.get("OVERWATCH_SECRET_KEY")
    if env:
        return env
    instance_dir.mkdir(parents=True, exist_ok=True)
    secret_file = instance_dir / "secret_key"
    if secret_file.exists():
        existing = secret_file.read_text(encoding="utf-8").strip()
        if existing:
            return existing
    value = secrets.token_hex(32)
    secret_file.write_text(value, encoding="utf-8")
    try:
        os.chmod(secret_file, 0o600)
    except OSError:
        # Best effort on platforms/filesystems that don't support chmod.
        pass
    return value


def _load_or_create_enroll_key(instance_dir: Path) -> str:
    env = os.environ.get("OVERWATCH_ENROLL_KEY")
    if env:
        return env
    instance_dir.mkdir(parents=True, exist_ok=True)
    key_file = instance_dir / "enroll_key"
    if key_file.exists():
        existing = key_file.read_text(encoding="utf-8").strip()
        if existing:
            return existing
    value = secrets.token_urlsafe(24)
    key_file.write_text(value, encoding="utf-8")
    try:
        os.chmod(key_file, 0o600)
    except OSError:
        pass
    return value


class Config:
    """Resolved configuration. Construct once per process."""

    def __init__(self, instance_dir: str | os.PathLike[str] | None = None) -> None:
        self.instance_dir = Path(
            instance_dir
            or os.environ.get("OVERWATCH_INSTANCE")
            or DEFAULT_INSTANCE
        ).resolve()
        self.instance_dir.mkdir(parents=True, exist_ok=True)

        self.database = Path(
            os.environ.get("OVERWATCH_DB", self.instance_dir / "overwatch.db")
        )
        self.log_file = Path(
            os.environ.get("OVERWATCH_LOG", self.instance_dir / "activity.log")
        )
        self.secret_key = _load_or_create_secret(self.instance_dir)

        # Alerting is opt-in. Empty webhook == alerts disabled.
        self.alert_webhook = os.environ.get("OVERWATCH_ALERT_WEBHOOK", "").strip()
        self.alert_timeout = float(os.environ.get("OVERWATCH_ALERT_TIMEOUT", "3"))

        # Open self-registration is only ever sensible for first-run bootstrap.
        # After the first user exists the web form refuses new sign-ups unless
        # this is explicitly set.
        self.allow_open_registration = _truthy(
            os.environ.get("OVERWATCH_OPEN_REGISTRATION")
        )

        # Seconds between process/registry baseline sweeps.
        self.poll_interval = float(os.environ.get("OVERWATCH_POLL_INTERVAL", "5"))

        self.host = os.environ.get("OVERWATCH_HOST", "127.0.0.1")
        self.port = int(os.environ.get("OVERWATCH_PORT", "8771"))

        # BYOD network fleet: devices enroll with this shared key, then receive
        # a per-device token. Generated once and persisted if not set.
        self.enroll_key = _load_or_create_enroll_key(self.instance_dir)

        # Agent mode: when running as a reporting node, forward events here.
        self.agent_server = os.environ.get("OVERWATCH_SERVER", "").strip().rstrip("/")
        self.agent_token = os.environ.get("OVERWATCH_DEVICE_TOKEN", "").strip()
        self.device_name = os.environ.get("OVERWATCH_DEVICE_NAME", "").strip()

        # Optional heartbeat: seconds between "alive" events (0 = off).
        self.heartbeat_interval = float(os.environ.get("OVERWATCH_HEARTBEAT", "0"))

        # User-designated certificates.
        #  - Server TLS: serve HTTPS from this cert/key pair.
        #  - Agent trust: CA bundle to verify the server (pin your own CA).
        #  - Client mTLS: present this client cert/key to the server.
        self.tls_cert = os.environ.get("OVERWATCH_TLS_CERT", "").strip()
        self.tls_key = os.environ.get("OVERWATCH_TLS_KEY", "").strip()
        self.ca_cert = os.environ.get("OVERWATCH_CA_CERT", "").strip()
        self.client_cert = os.environ.get("OVERWATCH_CLIENT_CERT", "").strip()
        self.client_key = os.environ.get("OVERWATCH_CLIENT_KEY", "").strip()

    def requests_verify(self):
        """`verify=` value for requests: a CA path, or True (system trust)."""
        return self.ca_cert or True

    def requests_cert(self):
        """`cert=` value for requests: (cert, key), a cert path, or None."""
        if self.client_cert and self.client_key:
            return (self.client_cert, self.client_key)
        return self.client_cert or None

    def ssl_context(self):
        """`ssl_context=` for Flask's server, or None when no TLS configured."""
        if self.tls_cert and self.tls_key:
            return (self.tls_cert, self.tls_key)
        return None

    def as_dict(self) -> dict[str, object]:
        return {
            "instance_dir": str(self.instance_dir),
            "database": str(self.database),
            "log_file": str(self.log_file),
            "alerts_enabled": bool(self.alert_webhook),
            "allow_open_registration": self.allow_open_registration,
            "poll_interval": self.poll_interval,
            "host": self.host,
            "port": self.port,
            "agent_mode": bool(self.agent_server),
            "agent_server": self.agent_server,
            "heartbeat_interval": self.heartbeat_interval,
            "tls_enabled": bool(self.ssl_context()),
            "mtls_client": bool(self.requests_cert()),
            "pinned_ca": bool(self.ca_cert),
        }
