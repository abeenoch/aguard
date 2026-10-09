"""Repo-local shim for the a-guard CLI.

The implementation lives in `aguard.cli` so `pip install a-guard` can expose it as
the `agctl` console script. This shim keeps the `python scripts/agctl.py ...`
form used throughout the docs working from a source checkout.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aguard.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
