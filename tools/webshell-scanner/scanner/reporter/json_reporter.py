from __future__ import annotations

from pathlib import Path

from scanner.models import ScanReport


def write_json(report: ScanReport, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
