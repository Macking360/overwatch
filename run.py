"""Convenience launcher so the app can be started as a plain script.

    python apps/overwatch/run.py

Equivalent to ``python -m overwatch run`` but works without the package being
on sys.path (it adds its own directory).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from overwatch.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main(["run"]))
