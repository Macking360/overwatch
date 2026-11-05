"""SQLite data layer for OverWatch.

A connection is opened per operation (WAL mode) so the web request thread and
the background monitor threads never share a handle. All writes commit before
returning.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    username         TEXT NOT NULL UNIQUE,
    password_hash    TEXT NOT NULL,
    role             TEXT NOT NULL DEFAULT 'viewer',
    pid              TEXT,
    credential       TEXT,
    conn_fingerprint TEXT,
    created_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       TEXT NOT NULL,
    source   TEXT NOT NULL DEFAULT 'local',
    monitor  TEXT NOT NULL,
    severity TEXT NOT NULL,
    target   TEXT NOT NULL,
    action   TEXT NOT NULL,
    detail   TEXT
);

CREATE TABLE IF NOT EXISTS devices (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    token_hash  TEXT NOT NULL,
    platform    TEXT,
    fingerprint TEXT,
    status      TEXT NOT NULL DEFAULT 'active',
    enrolled_at TEXT NOT NULL,
    last_seen   TEXT
);

CREATE TABLE IF NOT EXISTS baselines (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    kind       TEXT NOT NULL,
    key        TEXT NOT NULL,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(kind, key)
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
"""

SEVERITIES = ("info", "notice", "warning", "critical")
ROLES = ("admin", "viewer")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Database:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def init(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = self.connect()
        try:
            conn.executescript(SCHEMA)
            # Lightweight migrations for pre-existing databases.
            user_cols = {r["name"] for r in conn.execute("PRAGMA table_info(users)")}
            if "role" not in user_cols:
                conn.execute(
                    "ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'viewer'"
                )
            for col in ("pid", "credential", "conn_fingerprint"):
                if col not in user_cols:
                    conn.execute(f"ALTER TABLE users ADD COLUMN {col} TEXT")
            event_cols = {r["name"] for r in conn.execute("PRAGMA table_info(events)")}
            if "source" not in event_cols:
                conn.execute(
                    "ALTER TABLE events ADD COLUMN source TEXT NOT NULL DEFAULT 'local'"
                )
            dev_cols = {r["name"] for r in conn.execute("PRAGMA table_info(devices)")}
            if dev_cols and "fingerprint" not in dev_cols:
                conn.execute("ALTER TABLE devices ADD COLUMN fingerprint TEXT")
            conn.commit()
        finally:
            conn.close()

    # -- users ---------------------------------------------------------------

    def count_users(self) -> int:
        conn = self.connect()
        try:
            row = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()
            return int(row["n"])
        finally:
            conn.close()

    def add_user(self, username: str, password_hash: str, role: str = "viewer") -> int:
        if role not in ROLES:
            role = "viewer"
        conn = self.connect()
        try:
            cur = conn.execute(
                "INSERT INTO users (username, password_hash, role, created_at) "
                "VALUES (?, ?, ?, ?)",
                (username, password_hash, role, _now()),
            )
            conn.commit()
            return int(cur.lastrowid)
        finally:
            conn.close()

    def list_users(self) -> list[sqlite3.Row]:
        conn = self.connect()
        try:
            return conn.execute(
                "SELECT id, username, role, pid, created_at FROM users ORDER BY id"
            ).fetchall()
        finally:
            conn.close()

    def get_user_by_pid(self, pid: str) -> Optional[sqlite3.Row]:
        conn = self.connect()
        try:
            return conn.execute(
                "SELECT * FROM users WHERE pid = ?", (pid,)
            ).fetchone()
        finally:
            conn.close()

    def set_user_credential(
        self, user_id: int, pid: str, credential_json: str, conn_fingerprint: str
    ) -> None:
        conn = self.connect()
        try:
            conn.execute(
                "UPDATE users SET pid = ?, credential = ?, conn_fingerprint = ? WHERE id = ?",
                (pid, credential_json, conn_fingerprint, user_id),
            )
            conn.commit()
        finally:
            conn.close()

    def count_admins(self) -> int:
        conn = self.connect()
        try:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM users WHERE role = 'admin'"
            ).fetchone()
            return int(row["n"])
        finally:
            conn.close()

    def set_role(self, user_id: int, role: str) -> None:
        if role not in ROLES:
            raise ValueError(f"unknown role: {role}")
        conn = self.connect()
        try:
            conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
            conn.commit()
        finally:
            conn.close()

    def set_password(self, user_id: int, password_hash: str) -> None:
        conn = self.connect()
        try:
            conn.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (password_hash, user_id),
            )
            conn.commit()
        finally:
            conn.close()

    def delete_user(self, user_id: int) -> None:
        conn = self.connect()
        try:
            conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
            conn.commit()
        finally:
            conn.close()

    def get_user(self, username: str) -> Optional[sqlite3.Row]:
        conn = self.connect()
        try:
            return conn.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()
        finally:
            conn.close()

    def get_user_by_id(self, user_id: int) -> Optional[sqlite3.Row]:
        conn = self.connect()
        try:
            return conn.execute(
                "SELECT * FROM users WHERE id = ?", (user_id,)
            ).fetchone()
        finally:
            conn.close()

    # -- events --------------------------------------------------------------

    def add_event(
        self,
        monitor: str,
        target: str,
        action: str,
        severity: str = "info",
        detail: str = "",
        source: str = "local",
        ts: str | None = None,
    ) -> int:
        if severity not in SEVERITIES:
            severity = "info"
        conn = self.connect()
        try:
            cur = conn.execute(
                "INSERT INTO events (ts, source, monitor, severity, target, action, detail) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (ts or _now(), source or "local", monitor, severity, target, action, detail),
            )
            conn.commit()
            return int(cur.lastrowid)
        finally:
            conn.close()

    def recent_events(
        self, limit: int = 100, monitor: Optional[str] = None
    ) -> list[sqlite3.Row]:
        conn = self.connect()
        try:
            if monitor:
                return conn.execute(
                    "SELECT * FROM events WHERE monitor = ? ORDER BY id DESC LIMIT ?",
                    (monitor, limit),
                ).fetchall()
            return conn.execute(
                "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        finally:
            conn.close()

    def clear_events(self) -> int:
        conn = self.connect()
        try:
            cur = conn.execute("DELETE FROM events")
            conn.commit()
            return cur.rowcount
        finally:
            conn.close()

    def event_counts(self) -> dict[str, int]:
        conn = self.connect()
        try:
            rows = conn.execute(
                "SELECT severity, COUNT(*) AS n FROM events GROUP BY severity"
            ).fetchall()
            return {r["severity"]: int(r["n"]) for r in rows}
        finally:
            conn.close()

    # -- baselines -----------------------------------------------------------

    def set_baseline(self, kind: str, key: str, value: str) -> None:
        conn = self.connect()
        try:
            conn.execute(
                "INSERT INTO baselines (kind, key, value, updated_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(kind, key) DO UPDATE SET value=excluded.value, "
                "updated_at=excluded.updated_at",
                (kind, key, value, _now()),
            )
            conn.commit()
        finally:
            conn.close()

    def replace_baseline(self, kind: str, mapping: dict[str, str]) -> None:
        """Atomically replace all rows for ``kind`` in a single transaction.

        Writing a 400-process baseline one connection per row took seconds and
        starved the monitor threads; this does it in one round trip."""
        now = _now()
        conn = self.connect()
        try:
            conn.execute("DELETE FROM baselines WHERE kind = ?", (kind,))
            conn.executemany(
                "INSERT INTO baselines (kind, key, value, updated_at) VALUES (?, ?, ?, ?)",
                [(kind, str(k), str(v), now) for k, v in mapping.items()],
            )
            conn.commit()
        finally:
            conn.close()

    def get_baseline(self, kind: str) -> dict[str, str]:
        conn = self.connect()
        try:
            rows = conn.execute(
                "SELECT key, value FROM baselines WHERE kind = ?", (kind,)
            ).fetchall()
            return {r["key"]: r["value"] for r in rows}
        finally:
            conn.close()

    def clear_baseline(self, kind: str) -> None:
        conn = self.connect()
        try:
            conn.execute("DELETE FROM baselines WHERE kind = ?", (kind,))
            conn.commit()
        finally:
            conn.close()

    # -- devices (BYOD network fleet) ---------------------------------------

    def add_device(
        self, name: str, token_hash: str, platform: str = "", fingerprint: str = ""
    ) -> int:
        conn = self.connect()
        try:
            cur = conn.execute(
                "INSERT INTO devices (name, token_hash, platform, fingerprint, status, enrolled_at) "
                "VALUES (?, ?, ?, ?, 'active', ?)",
                (name, token_hash, platform, fingerprint, _now()),
            )
            conn.commit()
            return int(cur.lastrowid)
        finally:
            conn.close()

    def get_device(self, device_id: int) -> Optional[sqlite3.Row]:
        conn = self.connect()
        try:
            return conn.execute(
                "SELECT * FROM devices WHERE id = ?", (device_id,)
            ).fetchone()
        finally:
            conn.close()

    def list_devices(self) -> list[sqlite3.Row]:
        conn = self.connect()
        try:
            return conn.execute("SELECT * FROM devices ORDER BY id").fetchall()
        finally:
            conn.close()

    def set_device_status(self, device_id: int, status: str) -> None:
        conn = self.connect()
        try:
            conn.execute(
                "UPDATE devices SET status = ? WHERE id = ?", (status, device_id)
            )
            conn.commit()
        finally:
            conn.close()

    def touch_device(self, device_id: int) -> None:
        conn = self.connect()
        try:
            conn.execute(
                "UPDATE devices SET last_seen = ? WHERE id = ?", (_now(), device_id)
            )
            conn.commit()
        finally:
            conn.close()

    def delete_device(self, device_id: int) -> None:
        conn = self.connect()
        try:
            conn.execute("DELETE FROM devices WHERE id = ?", (device_id,))
            conn.commit()
        finally:
            conn.close()
