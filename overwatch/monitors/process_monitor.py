"""Process monitoring (read-only).

Takes periodic snapshots of running processes and reports which ones started or
exited between sweeps. It never terminates, hides, or alters a process — it
only observes.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

try:  # psutil is the supported path; absence is handled gracefully.
    import psutil
except Exception:  # pragma: no cover - exercised only when psutil missing
    psutil = None  # type: ignore[assignment]

# pid -> process name
Snapshot = Dict[int, str]
# list of (pid, name)
Delta = List[Tuple[int, str]]


def available() -> bool:
    return psutil is not None


def snapshot() -> Snapshot:
    """Current pid -> name map. Empty if psutil is unavailable."""
    if psutil is None:
        return {}
    result: Snapshot = {}
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            result[int(proc.info["pid"])] = proc.info.get("name") or "?"
        except (psutil.NoSuchProcess, psutil.AccessDenied, KeyError):
            continue
    return result


def _safe(getter):
    try:
        return getter()
    except Exception:  # noqa: BLE001 - psutil raises a family of access errors
        return None


def details(pid: int) -> dict:
    """Read-only deep details for a PID: exe path, user, cmdline, parent.

    Returns at least ``{"pid": pid}``; fields the OS won't disclose are omitted.
    Never modifies or signals the process.
    """
    if psutil is None:
        return {"pid": pid}
    try:
        proc = psutil.Process(pid)
    except Exception:  # noqa: BLE001
        return {"pid": pid}
    info: dict[str, object] = {"pid": pid}
    name = _safe(proc.name)
    if name:
        info["name"] = name
    exe = _safe(proc.exe)
    if exe:
        info["exe"] = exe
    user = _safe(proc.username)
    if user:
        info["username"] = user
    ppid = _safe(proc.ppid)
    if ppid is not None:
        info["ppid"] = ppid
    cmd = _safe(proc.cmdline)
    if cmd:
        info["cmdline"] = " ".join(cmd)[:400]
    return info


def describe(pid: int) -> str:
    """One-line human string of a PID's fingerprint, for event detail."""
    d = details(pid)
    parts = []
    if d.get("exe"):
        parts.append(f"exe={d['exe']}")
    if d.get("username"):
        parts.append(f"user={d['username']}")
    if d.get("ppid") is not None:
        parts.append(f"ppid={d['ppid']}")
    return " ".join(parts)


def diff(previous: Snapshot, current: Snapshot) -> Tuple[Delta, Delta]:
    """Return (started, stopped) as lists of (pid, name)."""
    started = [(pid, name) for pid, name in current.items() if pid not in previous]
    stopped = [(pid, name) for pid, name in previous.items() if pid not in current]
    started.sort()
    stopped.sort()
    return started, stopped
