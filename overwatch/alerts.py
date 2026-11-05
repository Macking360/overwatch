"""Opt-in outbound alerting.

Alerts are disabled unless an operator configures a webhook URL
(OVERWATCH_ALERT_WEBHOOK). Delivery failures never raise into the monitors —
the local activity log remains the source of truth.
"""

from __future__ import annotations

import logging

try:
    import requests
except Exception:  # pragma: no cover
    requests = None  # type: ignore[assignment]

log = logging.getLogger("overwatch.alerts")


def send_alert(webhook: str, text: str, timeout: float = 3.0) -> bool:
    """POST a simple {"text": ...} payload. Returns True on apparent success."""
    if not webhook or requests is None:
        return False
    try:
        resp = requests.post(webhook, json={"text": text}, timeout=timeout)
        return 200 <= resp.status_code < 300
    except Exception as exc:  # noqa: BLE001 - alerting must never crash a monitor
        log.warning("alert delivery failed: %s", exc)
        return False
