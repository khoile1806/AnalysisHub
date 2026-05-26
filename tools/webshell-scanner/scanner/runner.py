from __future__ import annotations

import hashlib
import json
import logging
import socket
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from scanner import __version__
from scanner.engines import PatternEngine, YaraEngine
from scanner.engines.base import Engine, EngineHit
from scanner.enumerator import enumerate_targets
from scanner.models import Finding, ScanReport, ScanStats
from scanner.paths import rules_dir
from scanner.scorer import aggregate

log = logging.getLogger(__name__)


@dataclass
class ScanOptions:
    targets: list[str]
    out_dir: Path
    formats: list[str]
    min_severity: str = "low"
    excludes: list[str] | None = None
    max_size_mb: float = 50.0
    progress: str = "auto"  # auto | none | json


_SEVERITY_RANK = {"clean": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _emit_progress(mode: str, payload: dict) -> None:
    if mode == "json":
        sys.stdout.write(json.dumps(payload) + "\n")
        sys.stdout.flush()


def run_scan(
    opts: ScanOptions,
    engines: Iterable[Engine] | None = None,
    progress_cb: Callable[[dict], None] | None = None,
) -> ScanReport:
    engines = list(engines) if engines is not None else _default_engines()

    report = ScanReport(
        scanner_version=__version__,
        rules_version=_rules_version(),
        hostname=socket.gethostname(),
        targets=[str(Path(t).resolve()) for t in opts.targets],
        stats=ScanStats(),
    )

    files = list(enumerate_targets(
        opts.targets,
        max_size_mb=opts.max_size_mb,
        excludes=opts.excludes,
    ))
    report.stats.total_files = len(files)
    _emit_progress(opts.progress, {"event": "start", "total": len(files)})
    if progress_cb:
        progress_cb({"event": "start", "total": len(files)})

    min_rank = _SEVERITY_RANK.get(opts.min_severity, 1)

    for idx, path in enumerate(files, 1):
        try:
            content = path.read_bytes()
        except OSError as exc:
            log.debug("read fail %s: %s", path, exc)
            report.stats.errors += 1
            continue

        hits: list[EngineHit] = []
        for eng in engines:
            try:
                hit = eng.scan(path, content)
            except Exception as exc:  # noqa: BLE001
                log.debug("engine %s error on %s: %s", eng.name, path, exc)
                continue
            if hit and hit.score > 0:
                hits.append(hit)

        report.stats.scanned += 1
        if not hits:
            _emit_progress(opts.progress, {"event": "progress", "scanned": idx, "total": len(files)})
            if progress_cb:
                progress_cb({"event": "progress", "scanned": idx, "total": len(files)})
            continue

        score, severity, reasons, engine_names, snippet = aggregate(hits)
        if _SEVERITY_RANK.get(severity, 0) < min_rank:
            _emit_progress(opts.progress, {"event": "progress", "scanned": idx, "total": len(files)})
            continue

        finding = Finding(
            path=str(path),
            sha256=hashlib.sha256(content).hexdigest(),
            size_bytes=len(content),
            severity=severity,
            score=score,
            reasons=reasons,
            engines=engine_names,
            snippet=snippet,
        )
        report.findings.append(finding)
        report.stats.matched += 1

        _emit_progress(opts.progress, {
            "event": "finding",
            "path": finding.path,
            "severity": severity,
            "score": score,
        })
        if progress_cb:
            progress_cb({"event": "finding", "path": finding.path, "severity": severity, "score": score})

    _emit_progress(opts.progress, {"event": "done", "matched": report.stats.matched})
    if progress_cb:
        progress_cb({"event": "done", "matched": report.stats.matched})
    return report


def _default_engines() -> list[Engine]:
    return [YaraEngine(), PatternEngine()]


def _rules_version() -> str:
    """Hash of files inside rules/ — surfaces in report and lets integration version-track rules."""
    h = hashlib.sha256()
    root = rules_dir()
    if not root.exists():
        return "none"
    for p in sorted(root.rglob("*")):
        if p.is_file():
            h.update(p.name.encode())
            h.update(p.read_bytes())
    return h.hexdigest()[:12]
