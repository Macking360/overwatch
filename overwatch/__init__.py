"""OverWatch — a defensive host-integrity monitor for Windows (and POSIX).

OverWatch watches files, running processes, and registry autorun keys on the
machine it runs on, records every change to a local activity log, and can
optionally fire an opt-in webhook alert. It is read-only with respect to the
host: it detects and records changes, it never hides files or processes and
never modifies the registry.
"""

from __future__ import annotations

__version__ = "1.0.0"
