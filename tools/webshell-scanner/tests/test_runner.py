"""End-to-end runner test: scan the real fixture corpus and render JSON + HTML.

Snippets in JSON/HTML are stored base64 (see ``Finding._encode_snippet`` and
the ``b64encode`` Jinja filter) so AV signature scanners do not flag the
report file. Tests therefore decode the snippet before asserting on it.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

from scanner.models import Finding, ScanReport, ScanStats
from scanner.reporter import write_html, write_json
from scanner.runner import ScanOptions, run_scan

SAMPLES = Path(__file__).parent / "samples"


def _synthetic_report() -> ScanReport:
    return ScanReport(
        scanner_version="0.0.0-test",
        rules_version="testhash",
        hostname="testhost",
        targets=["/fake/target"],
        stats=ScanStats(total_files=2, scanned=2, matched=1),
        findings=[
            Finding(
                path="/fake/target/sample.txt",
                sha256="0" * 64,
                size_bytes=10,
                severity="high",
                score=80,
                reasons=["test:demo_rule"],
                engines=["test"],
                snippet="harmless placeholder snippet",
            ),
        ],
    )


def test_run_scan_produces_findings(tmp_path: Path):
    opts = ScanOptions(
        targets=[str(SAMPLES / "malicious")],
        out_dir=tmp_path,
        formats=["json", "html"],
        progress="none",
    )
    report = run_scan(opts)
    assert report.stats.scanned > 0
    assert report.stats.matched > 0
    assert report.findings, "should produce at least one finding"
    for f in report.findings:
        assert f.score > 0
        assert f.engines


def test_run_scan_clean_dir_empty(tmp_path: Path):
    opts = ScanOptions(
        targets=[str(SAMPLES / "clean")],
        out_dir=tmp_path,
        formats=["json"],
        progress="none",
    )
    report = run_scan(opts)
    actionable = [f for f in report.findings if f.severity in {"medium", "high", "critical"}]
    assert not actionable, f"clean dir produced findings: {actionable}"


def test_write_json_synthetic_round_trip(tmp_path: Path):
    """Writer contract test using fabricated data — independent of AV."""
    report = _synthetic_report()
    json_path = tmp_path / "report.json"
    html_path = tmp_path / "report.html"
    write_json(report, json_path)
    write_html(report, html_path)

    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["scanner_version"] == "0.0.0-test"
    assert data["rules_version"] == "testhash"
    assert data["snippet_encoding"] == "base64"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["severity"] == "high"

    decoded = base64.b64decode(data["findings"][0]["snippet"]).decode("utf-8")
    assert decoded == "harmless placeholder snippet"

    html = html_path.read_text(encoding="utf-8")
    assert "Webshell Scan Report" in html
    assert "tailwindcss" in html
    assert "/fake/target/sample.txt" in html


def test_write_real_corpus_json_is_av_safe(tmp_path: Path):
    """Scan the real malicious corpus, write report.json, then read it back.

    Before introducing base64 encoding for snippets, this exact flow tripped
    Windows Defender's real-time scan (snippets contained literal
    ``eval($_POST...)`` etc.) and the file became unreadable. With base64
    snippets the JSON now contains only opaque strings so AV signatures no
    longer match.
    """
    out_dir = tmp_path / "out"
    opts = ScanOptions(
        targets=[str(SAMPLES / "malicious")],
        out_dir=out_dir,
        formats=["json"],
        progress="none",
    )
    report = run_scan(opts)
    json_path = out_dir / "report.json"
    write_json(report, json_path)

    raw = json_path.read_text(encoding="utf-8")
    data = json.loads(raw)
    assert data["snippet_encoding"] == "base64"
    assert data["findings"], "real corpus must produce findings"

    # The on-disk JSON must NOT contain a literal webshell string.
    assert "eval($_POST" not in raw
    assert "system($_GET" not in raw
    assert "Runtime.getRuntime" not in raw

    # Decoding gives back the real snippet (when one was captured).
    decoded_count = 0
    for finding in data["findings"]:
        if finding["snippet"]:
            decoded = base64.b64decode(finding["snippet"]).decode("utf-8", errors="replace")
            assert decoded, "snippet decoded to empty string"
            decoded_count += 1
    assert decoded_count >= 1, "expected at least one snippet to be captured"


def test_write_real_corpus_html_is_av_safe(tmp_path: Path):
    """HTML must also avoid embedding raw webshell strings — snippets are kept
    base64-encoded inside an Alpine.js ``data-`` attribute and decoded in the
    browser via ``atob()`` only when the user clicks "Show snippet"."""
    out_dir = tmp_path / "out"
    opts = ScanOptions(
        targets=[str(SAMPLES / "malicious")],
        out_dir=out_dir,
        formats=["html"],
        progress="none",
    )
    report = run_scan(opts)
    html_path = out_dir / "report.html"
    write_html(report, html_path)

    html = html_path.read_text(encoding="utf-8")
    assert "Webshell Scan Report" in html
    assert "atob(b64)" in html, "HTML must use client-side base64 decode for snippets"
    assert "eval($_POST" not in html
    assert "system($_GET" not in html
    assert "Runtime.getRuntime" not in html
