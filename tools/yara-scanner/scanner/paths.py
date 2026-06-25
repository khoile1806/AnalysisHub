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


def scenarios_dir() -> Path:
    """Directory of scenario-specific YARA rule sets (one .yar per scenario).

    These are NOT auto-loaded with the base rules; they are opt-in via the
    --scenario flag so a focused scan only pulls the rules it needs.
    """
    return rules_dir() / "yara" / "scenarios"


def available_scenarios() -> list[str]:
    """List scenario ids derived from rules/yara/scenarios/<id>.yar filenames."""
    d = scenarios_dir()
    if not d.exists():
        return []
    return sorted(p.stem for p in d.glob("*.yar"))


def templates_dir() -> Path:
    return resource_root() / "templates"
