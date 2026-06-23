"""Resolve bundled resource paths whether running from source or PyInstaller frozen binary."""

from __future__ import annotations

import sys
from pathlib import Path


def resource_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS)  # type: ignore[attr-defined]
    return Path(__file__).resolve().parent.parent


def rules_dir() -> Path:
    return resource_root() / "rules"


def templates_dir() -> Path:
    return resource_root() / "templates"
