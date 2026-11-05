"""Network client for OverWatch agent (BYOD) mode.

An agent runs the same monitors locally but forwards each event to a central
OverWatch server over HTTPS/HTTP using its per-device Bearer token. Enrollment
exchanges a shared enroll key for a device token.
"""

from __future__ import annotations

import collections
import logging
import threading
from typing import Optional

try:
    import requests
except Exception:  # pragma: no cover
    requests = None  # type: ignore[assignment]

log = logging.getLogger("overwatch.net")


def enroll(
    server: str,
    enroll_key: str,
    name: str,
    platform: str = "",
    fingerprint: Optional[dict] = None,
    timeout: float = 10.0,
    verify=True,
    cert=None,
) -> Optional[str]:
    """Exchange the enroll key for a device token. Returns the token or None.

    ``verify`` and ``cert`` are passed to requests for user-designated TLS
    (pinned CA bundle and/or client mTLS certificate)."""
    if requests is None:
        raise RuntimeError("requests is required for enrollment")
    url = f"{server.rstrip('/')}/api/enroll"
    resp = requests.post(
        url,
        json={"name": name, "platform": platform, "fingerprint": fingerprint or {}},
        headers={"X-Enroll-Key": enroll_key},
        timeout=timeout,
        verify=verify,
        cert=cert,
    )
    if resp.status_code == 201:
        return resp.json().get("token")
    log.error("enrollment failed: %s %s", resp.status_code, resp.text[:200])
    return None


class RemoteForwarder:
    """Posts events to a central OverWatch server, with a bounded retry buffer.

    Each event is appended to an in-memory queue and the whole queue is flushed
    on every call (a retry loop): if the network is down, events accumulate (up
    to ``max_buffer``) and are re-sent on the next event or heartbeat, so a
    transient outage never drops data. Failures are swallowed — events always
    remain in the agent's local log regardless."""

    def __init__(
        self,
        server: str,
        token: str,
        timeout: float = 5.0,
        max_buffer: int = 2000,
        verify=True,
        cert=None,
    ) -> None:
        self.url = f"{server.rstrip('/')}/api/events"
        self.token = token
        self.timeout = timeout
        self.verify = verify
        self.cert = cert
        self._buffer: collections.deque = collections.deque(maxlen=max_buffer)
        self._lock = threading.Lock()

    @property
    def pending(self) -> int:
        with self._lock:
            return len(self._buffer)

    def _post(self, events: list) -> bool:
        if requests is None or not events:
            return False
        try:
            resp = requests.post(
                self.url,
                json={"events": events},
                headers={"Authorization": f"Bearer {self.token}"},
                timeout=self.timeout,
                verify=self.verify,
                cert=self.cert,
            )
            return 200 <= resp.status_code < 300
        except Exception as exc:  # noqa: BLE001
            log.warning("event forward failed (%d buffered): %s", self.pending, exc)
            return False

    def __call__(self, event: dict) -> bool:
        with self._lock:
            self._buffer.append(event)
            batch = list(self._buffer)
        if self._post(batch):
            with self._lock:
                # Drop exactly the events we just delivered (FIFO); anything
                # appended during the POST stays queued for the next flush.
                for _ in range(len(batch)):
                    if self._buffer:
                        self._buffer.popleft()
            return True
        return False

    def flush(self) -> bool:
        """Attempt to drain the buffer without adding a new event."""
        with self._lock:
            batch = list(self._buffer)
        if not batch:
            return True
        if self._post(batch):
            with self._lock:
                for _ in range(len(batch)):
                    if self._buffer:
                        self._buffer.popleft()
            return True
        return False
