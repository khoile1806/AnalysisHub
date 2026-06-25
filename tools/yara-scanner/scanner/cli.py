from __future__ import annotations

import logging
from collections import Counter
from pathlib import Path
from typing import Annotated

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from scanner import __version__
from scanner.models import Severity, ScanReport
from scanner.reporter import write_html, write_json
from scanner.runner import ScanOptions, run_scan

app = typer.Typer(add_completion=False, help="Multi-engine webshell scanner")

_SEV_COLOR = {
    "critical": "red1",
    "high":     "orange3",
    "medium":   "yellow",
    "low":      "bright_black",
    "clean":    "green",
}
_EXT_LANG = {
    "php": "php", "phtml": "php",
    "py": "python",
    "js": "javascript", "mjs": "javascript",
    "rb": "ruby",
    "pl": "perl", "pm": "perl",
    "sh": "bash", "bash": "bash",
    "jsp": "java", "jspx": "java",
    "asp": "html", "aspx": "html",
}


def _print_terminal_report(report: ScanReport, out_dir: Path, formats: list[str]) -> None:
    c = Console(stderr=True)
    sev_cnt = Counter(f.severity for f in report.findings)

    c.rule("[bold cyan]Webshell Scanner Report[/bold cyan]")
    c.print(
        f"  [dim]Host:[/dim] [bold]{report.hostname}[/bold]  "
        f"[dim]Rules:[/dim] {report.rules_version}  "
        f"[dim]Time:[/dim] {report.scanned_at.strftime('%Y-%m-%d %H:%M:%S UTC')}"
    )
    c.print()

    # ── Summary stats table ──────────────────────────────────────────────────
    t = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold dim")
    for col in ("Total", "Scanned", "Errors", "Matched", "Critical", "High", "Medium", "Low"):
        t.add_column(col, justify="center")
    t.add_row(
        str(report.stats.total_files),
        str(report.stats.scanned),
        f"[red]{report.stats.errors}[/red]" if report.stats.errors else "0",
        f"[bold]{report.stats.matched}[/bold]",
        f"[red1 bold]{sev_cnt.get('critical', 0)}[/red1 bold]",
        f"[orange3 bold]{sev_cnt.get('high', 0)}[/orange3 bold]",
        f"[yellow bold]{sev_cnt.get('medium', 0)}[/yellow bold]",
        f"[bright_black]{sev_cnt.get('low', 0)}[/bright_black]",
    )
    c.print(t)

    if not report.findings:
        c.print("[bold green]\u2713 No actionable findings.[/bold green]")
    else:
        c.rule(f"[bold]Findings ({len(report.findings)})[/bold]")
        for f in sorted(report.findings, key=lambda x: -x.score):
            color = _SEV_COLOR.get(f.severity, "white")

            # Finding metadata block
            info = (
                f"[bold dim]Path   :[/bold dim]  [bold]{f.path}[/bold]\n"
                f"[bold dim]SHA256 :[/bold dim]  [dim]{f.sha256}[/dim]\n"
                f"[bold dim]Size   :[/bold dim]  {f.size_bytes:,} bytes\n"
                f"[bold dim]Engines:[/bold dim]  [cyan]{', '.join(f.engines)}[/cyan]\n"
                f"[bold dim]Rules  :[/bold dim]\n"
                + "\n".join(f"  [dim]\u25b8[/dim] [yellow]{r}[/yellow]" for r in f.reasons)
            )
            c.print(Panel(
                Text.from_markup(info),
                title=f"[{color} bold]{f.severity.upper()}  score {f.score}/100[/{color} bold]",
                border_style=color,
                expand=True,
            ))

            # Code snippet block
            if f.snippet:
                ext = Path(f.path).suffix.lower().lstrip(".")
                lang = _EXT_LANG.get(ext, "text")
                c.print(Panel(
                    Syntax(
                        f.snippet,
                        lang,
                        theme="monokai",
                        word_wrap=True,
                        background_color="default",
                    ),
                    title="[dim]Detected shell code[/dim]",
                    border_style="dim",
                    padding=(0, 1),
                ))
            c.print()

    # ── Output files summary ─────────────────────────────────────────────────
    c.rule("[dim]Output[/dim]")
    if "json" in formats:
        c.print(f"  [dim]JSON:[/dim] {out_dir / 'report.json'}")
    if "html" in formats:
        c.print(f"  [dim]HTML:[/dim] {out_dir / 'report.html'}")
    c.print()


@app.command()
def scan(
    targets: Annotated[list[str], typer.Argument(help="One or more files/dirs to scan")],
    out: Annotated[Path, typer.Option("--out", "-o", help="Output dir")] = Path("./report"),
    fmt: Annotated[str, typer.Option("--format", "-f", help="Comma list: json,html")] = "json,html",
    min_severity: Annotated[str, typer.Option("--min-severity", help="Drop findings below this")] = "low",
    exclude: Annotated[list[str] | None, typer.Option("--exclude", help="Glob exclude (repeatable)")] = None,
    max_size: Annotated[float, typer.Option("--max-size", help="Skip files larger than N MB")] = 50.0,
    progress: Annotated[str, typer.Option("--progress", help="auto|none|json")] = "auto",
    all_files: Annotated[bool, typer.Option("--all-files", help="Scan all files, ignoring extension whitelist")] = False,
    extensions: Annotated[str | None, typer.Option("--extensions", help="Comma-separated list of extensions to scan (e.g. .php,.exe)")] = None,
    yara_rules: Annotated[Path | None, typer.Option("--yara-rules", help="Path to custom YARA rules directory or file")] = None,
    yara_base64: Annotated[str | None, typer.Option("--yara-base64", help="Base64 encoded YARA rule string")] = None,
    scenario: Annotated[str | None, typer.Option("--scenario", help="Threat scenario rule set to add on top of base rules (e.g. ransomware, credential_theft, persistence, lateral_movement, powershell, linux, c2, or 'all'). See list-scenarios.")] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Debug logging")] = False,
) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=__import__("sys").stderr,
    )

    formats = [s.strip().lower() for s in fmt.split(",") if s.strip()]
    valid_severities: set[Severity] = {"critical", "high", "medium", "low"}
    if min_severity not in valid_severities:
        typer.echo(f"Invalid --min-severity: {min_severity}", err=True)
        raise typer.Exit(2)

    opts = ScanOptions(
        targets=targets,
        out_dir=out,
        formats=formats,
        min_severity=min_severity,
        excludes=exclude,
        max_size_mb=max_size,
        progress=progress,
        all_files=all_files,
        extensions=[e.strip().lower() for e in extensions.split(",")] if extensions else None,
        yara_rules=yara_rules,
        yara_base64=yara_base64,
        scenario=scenario,
    )

    report = run_scan(opts)
    out.mkdir(parents=True, exist_ok=True)

    if "json" in formats:
        write_json(report, out / "report.json")
    if "html" in formats:
        write_html(report, out / "report.html")

    _print_terminal_report(report, out, formats)

    has_actionable = any(f.severity in {"critical", "high", "medium"} for f in report.findings)
    raise typer.Exit(1 if has_actionable else 0)


@app.command()
def version() -> None:
    """Print version and exit."""
    typer.echo(__version__)


@app.command(name="list-scenarios")
def list_scenarios() -> None:
    """List the available --scenario rule sets (one per rules/yara/scenarios/*.yar)."""
    from scanner.paths import available_scenarios
    for s in available_scenarios():
        typer.echo(s)


@app.command()
def health() -> None:
    """Check if the scanner environment is healthy (YARA, dependencies, rules)."""
    c = Console(stderr=True)
    c.rule("[bold cyan]Scanner Health Check[/bold cyan]")
    
    # 1. Check YARA
    try:
        import yara
        c.print("[green]\u2713[/green] YARA engine: [bold]Ready[/bold]")
    except ImportError:
        c.print("[red1]\u2717[/red1] YARA engine: [bold]Missing[/bold] (yara-python not installed)")
        
    # 2. Check Magic (File type detection)
    try:
        import magic
        # Test it
        magic.from_buffer(b"GIF89a", mime=True)
        c.print("[green]\u2713[/green] Magic engine: [bold]Ready[/bold]")
    except Exception as e:
        c.print(f"[red1]\u2717[/red1] Magic engine: [bold]Error[/bold] ({e})")
        
    # 3. Check Rules
    from scanner.paths import rules_dir
    rdir = rules_dir()
    if rdir.exists():
        yara_rules = list(rdir.glob("yara/*.yar")) + list(rdir.glob("yara/*.yara"))
        c.print(f"[green]\u2713[/green] Rule library: [bold]{len(yara_rules)} YARA rules found[/bold]")
    else:
        c.print(f"[red1]\u2717[/red1] Rule library: [bold]Missing[/bold] ({rdir})")
    
    c.print(f"\n[dim]Scanner Version: {__version__}[/dim]")
    c.print("[dim]Platform: [/dim]" + __import__("platform").platform())
    c.rule()


if __name__ == "__main__":
    app()
