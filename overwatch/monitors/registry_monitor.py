"""Registry autorun monitoring (read-only, Windows only).

OverWatch reads the common autorun locations (the HKLM/HKCU ...\\Run keys) and
compares them against a stored baseline so new, changed, or removed autostart
entries are surfaced. It opens every key read-only and never writes to the
registry. On non-Windows hosts the reader reports "unsupported" and the diff
logic still works for tests.
"""

from __future__ import annotations

import sys
from typing import Dict, List, Tuple

IS_WINDOWS = sys.platform == "win32"

# Each entry: (hive_name, subkey). Values become "hive\\subkey\\value_name".
RUN_LOCATIONS = [
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
]

# key -> command string
RegistryState = Dict[str, str]
# list of (key, detail)
RegistryDelta = List[Tuple[str, str]]


def available() -> bool:
    return IS_WINDOWS


def read_autoruns() -> RegistryState:
    """Read autorun values. Returns an empty dict off Windows."""
    if not IS_WINDOWS:
        return {}

    import winreg  # imported lazily; only exists on Windows

    hives = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}
    state: RegistryState = {}
    for hive_name, subkey in RUN_LOCATIONS:
        hive = hives[hive_name]
        try:
            handle = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
        except FileNotFoundError:
            continue
        except OSError:
            continue
        try:
            index = 0
            while True:
                try:
                    name, value, _vtype = winreg.EnumValue(handle, index)
                except OSError:
                    break
                state[f"{hive_name}\\{subkey}\\{name}"] = str(value)
                index += 1
        finally:
            winreg.CloseKey(handle)
    return state


def diff(baseline: RegistryState, current: RegistryState) -> Tuple[RegistryDelta, RegistryDelta, RegistryDelta]:
    """Return (added, changed, removed) autorun entries."""
    added = [
        (key, current[key]) for key in current if key not in baseline
    ]
    changed = [
        (key, f"{baseline[key]} -> {current[key]}")
        for key in current
        if key in baseline and baseline[key] != current[key]
    ]
    removed = [
        (key, baseline[key]) for key in baseline if key not in current
    ]
    added.sort()
    changed.sort()
    removed.sort()
    return added, changed, removed
