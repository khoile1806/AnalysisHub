from __future__ import annotations

import base64
from collections import Counter
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from scanner.models import ScanReport
from scanner.paths import templates_dir


def _b64encode(value: str | None) -> str:
    if not value:
        return ""
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def write_html(report: ScanReport, out_path: Path) -> None:
    env = Environment(
        loader=FileSystemLoader(str(templates_dir())),
        autoescape=select_autoescape(["html", "j2"]),
    )
    env.filters["b64encode"] = _b64encode
    tmpl = env.get_template("report.html.j2")

    severity_counts = Counter(f.severity for f in report.findings)
    rendered = tmpl.render(
        report=report,
        severity_counts=dict(severity_counts),
        sorted_findings=sorted(report.findings, key=lambda f: -f.score),
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(rendered, encoding="utf-8")
