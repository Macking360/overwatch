"""Device fingerprinting.

Collects read-only identity and hardware facts about the machine the agent runs
on, so each enrolled device can be told apart in the fleet console. All fields
are best-effort; anything that can't be read is simply omitted.
"""

from __future__ import annotations

import platform
import socket
import uuid

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None  # type: ignore[assignment]


def _mac_from_node() -> str:
    node = uuid.getnode()
    return ":".join(f"{(node >> shift) & 0xFF:02x}" for shift in range(40, -1, -8))


def _interfaces() -> dict:
    if psutil is None:
        return {}
    out: dict[str, dict] = {}
    af_link = getattr(psutil, "AF_LINK", None)
    try:
        for name, addrs in psutil.net_if_addrs().items():
            macs = [a.address for a in addrs if af_link is not None and a.family == af_link]
            ipv4 = [a.address for a in addrs if a.family == socket.AF_INET]
            out[name] = {"mac": macs, "ipv4": ipv4}
    except Exception:  # noqa: BLE001
        return out
    return out


def collect() -> dict:
    """Return a best-effort device fingerprint."""
    data: dict[str, object] = {
        "hostname": socket.gethostname(),
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "arch": platform.architecture()[0],
        "python": platform.python_version(),
        "primary_mac": _mac_from_node(),
    }
    if psutil is not None:
        for key, getter in (
            ("cpu_logical", lambda: psutil.cpu_count(logical=True)),
            ("cpu_physical", lambda: psutil.cpu_count(logical=False)),
            ("mem_total", lambda: int(psutil.virtual_memory().total)),
            ("boot_time", lambda: int(psutil.boot_time())),
        ):
            try:
                data[key] = getter()
            except Exception:  # noqa: BLE001
                pass
        interfaces = _interfaces()
        if interfaces:
            data["interfaces"] = interfaces
    return data
