import sys
from pathlib import Path

# Make the `overwatch` package importable without installation.
APP_DIR = Path(__file__).resolve().parents[1]
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))
