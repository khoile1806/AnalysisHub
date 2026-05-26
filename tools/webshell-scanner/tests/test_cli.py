"""End-to-end CLI tests via Typer's CliRunner — argument parsing, exit codes,
output file generation, progress mode, severity filtering."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from scanner.cli import app

runner = CliRunner()
SAMPLES = Path(__file__).parent / "samples"


def test_version_command():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.stdout.strip()


def test_scan_clean_dir_exit_zero(tmp_path: Path):
    result = runner.invoke(app, [
        "scan", str(SAMPLES / "clean"),
        "--out", str(tmp_path),
        "--progress", "none",
    ])
    assert result.exit_code == 0
    assert (tmp_path / "report.json").exists()


def test_scan_malicious_dir_exit_one(tmp_path: Path):
    result = runner.invoke(app, [
        "scan", str(SAMPLES / "malicious"),
        "--out", str(tmp_path),
        "--progress", "none",
    ])
    assert result.exit_code == 1


def test_invalid_min_severity_exits_two(tmp_path: Path):
    result = runner.invoke(app, [
        "scan", str(SAMPLES / "clean"),
        "--out", str(tmp_path),
        "--min-severity", "bogus",
        "--progress", "none",
    ])
    assert result.exit_code == 2


def test_format_json_only_skips_html(tmp_path: Path):
    result = runner.invoke(app, [
        "scan", str(SAMPLES / "clean"),
        "--out", str(tmp_path),
        "--format", "json",
        "--progress", "none",
    ])
    assert result.exit_code == 0
    assert (tmp_path / "report.json").exists()
    assert not (tmp_path / "report.html").exists()


def test_format_html_only_skips_json(tmp_path: Path):
    result = runner.invoke(app, [
        "scan", str(SAMPLES / "clean"),
        "--out", str(tmp_path),
        "--format", "html",
        "--progress", "none",
    ])
    assert result.exit_code == 0
    assert (tmp_path / "report.html").exists()
    assert not (tmp_path / "report.json").exists()


def test_progress_json_emits_jsonl(tmp_path: Path):
    result = runner.invoke(app, [
        "scan", str(SAMPLES / "clean"),
        "--out", str(tmp_path),
        "--format", "json",
        "--progress", "json",
    ])
    assert result.exit_code == 0
    lines = [ln for ln in result.stdout.splitlines() if ln.strip()]
    assert lines, "expected at least one progress event"
    events = [json.loads(ln) for ln in lines]
    assert events[0]["event"] == "start"
    assert events[-1]["event"] == "done"


def test_min_severity_filter_drops_low(tmp_path: Path):
    """`--min-severity high` keeps only high+critical findings.

    Reads the actual report.json from disk to verify both that the file is
    not quarantined by AV (snippets are base64-encoded so signatures don't
    match) and that the severity filter is applied to persisted findings.
    """
    result = runner.invoke(app, [
        "scan", str(SAMPLES / "malicious"),
        "--out", str(tmp_path),
        "--min-severity", "high",
        "--format", "json",
        "--progress", "none",
    ])
    assert result.exit_code == 1

    report_path = tmp_path / "report.json"
    assert report_path.exists(), "report.json should have been written"
    data = json.loads(report_path.read_text(encoding="utf-8"))
    assert data["snippet_encoding"] == "base64"
    assert data["findings"], "high+ corpus should still report findings"
    for f in data["findings"]:
        assert f["severity"] in {"high", "critical"}, f"unexpected severity: {f}"


def test_exclude_glob_drops_files(tmp_path: Path):
    """Exclude every malicious sample by glob -> no actionable finding -> exit 0."""
    result = runner.invoke(app, [
        "scan", str(SAMPLES / "malicious"),
        "--out", str(tmp_path),
        "--format", "json",
        "--exclude", "*malicious*",
        "--progress", "none",
    ])
    assert result.exit_code == 0
