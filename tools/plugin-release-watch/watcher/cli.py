"""Command line entry point.

    plugin-release-watch run --watchlist plugins.txt
    plugin-release-watch run --watchlist plugins.txt --security-only --quiet
    plugin-release-watch run --from-dir F:/Claude Code Work Place/wp-cve-hunt/targets
    plugin-release-watch add wpforo mycred
    plugin-release-watch watch --json ../../backend/data/plugin-watch/report.json
"""

from __future__ import annotations

import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import typer
from rich.console import Console

from .models import Signal
from .report import render_console, write_html, write_json
from .runner import run_watch
from .state import StateStore

app = typer.Typer(add_completion=False, help="Theo doi ban phat hanh moi cua plugin WordPress.")
console = Console()

DEFAULT_STATE = Path("state/release-state.json")
DEFAULT_WATCHLIST = Path("watchlist.txt")


def _read_watchlist(path: Path) -> list[str]:
    if not path.exists():
        raise typer.BadParameter(f"khong tim thay watchlist: {path}")
    slugs = []
    for line in path.read_text(encoding="utf-8").splitlines():
        slug = line.split("#", 1)[0].strip()
        if slug:
            slugs.append(slug)
    return slugs


def _slugs_from_dir(path: Path) -> list[str]:
    """Every immediate subdirectory is a plugin slug.

    Lets the watcher point straight at an existing corpus (wp-cve-hunt/targets)
    instead of duplicating the list into a watchlist file that then drifts.
    """
    if not path.is_dir():
        raise typer.BadParameter(f"khong phai thu muc: {path}")
    return sorted(child.name for child in path.iterdir()
                  if child.is_dir() and not child.name.startswith((".", "_")))


@app.command()
def run(
    watchlist: Path = typer.Option(DEFAULT_WATCHLIST, "--watchlist", "-w",
                                   help="File danh sach slug, moi dong mot slug."),
    from_dir: Path | None = typer.Option(None, "--from-dir",
                                         help="Lay slug tu ten thu muc con."),
    state_path: Path = typer.Option(DEFAULT_STATE, "--state",
                                    help="Noi luu phien ban da thay lan truoc."),
    security_only: bool = typer.Option(False, "--security-only",
                                       help="Chi bao ban phat hanh co dau hieu va bao mat."),
    discover_new: bool = typer.Option(False, "--discover-new",
                                      help="Bao them plugin vua xuat hien tren wp.org."),
    repo_wide: bool = typer.Option(False, "--repo",
                                   help="Theo doi TOAN BO kho wp.org, khong chi watchlist."),
    repo_pages: int = typer.Option(1, "--repo-pages",
                                   help="So trang 100 plugin doc tu danh sach vua cap nhat."),
    min_installs: int = typer.Option(0, "--min-installs", help="Bo qua plugin it nguoi dung."),
    json_out: Path | None = typer.Option(None, "--json", help="Ghi report.json."),
    html_out: Path | None = typer.Option(None, "--html", help="Ghi report.html."),
    delay: float = typer.Option(0.25, "--delay", help="Giay nghi giua hai lan goi API."),
    quiet: bool = typer.Option(False, "--quiet", help="Chi in mot dong tom tat."),
) -> None:
    """Kiem tra mot luot va bao nhung gi da thay doi.

    Lan chay dau chi ghi moc, khong bao gi - de them mot slug moi vao danh sach
    khong sinh ra canh bao gia cho ban phat hanh tu nhieu thang truoc.
    """
    slugs = _slugs_from_dir(from_dir) if from_dir else _read_watchlist(watchlist)
    if not slugs and not repo_wide:
        console.print("[yellow]Danh sach theo doi rong.[/yellow]")
        raise typer.Exit(code=1)

    store = StateStore(state_path)
    baseline = not any(store.known(slug) for slug in slugs)

    def progress(index: int, total: int, slug: str) -> None:
        if not quiet and index % 25 == 0:
            console.print(f"[dim]  {index}/{total}[/dim]", highlight=False)

    if not quiet:
        console.print(f"[dim]Dang kiem tra {len(slugs)} plugin...[/dim]")

    result = run_watch(
        slugs, store,
        security_only=security_only,
        discover_new=discover_new,
        repo_wide=repo_wide,
        repo_pages=repo_pages,
        min_installs=min_installs,
        delay=delay,
        on_progress=progress,
    )
    store.prune()
    store.save()

    if json_out:
        write_json(result, json_out)
    if html_out:
        write_html(result, html_out)

    if quiet:
        security = len(result.security_events)
        console.print(f"{len(result.events)} thay doi, {security} ban va bao mat"
                      + (f", ghi vao {json_out}" if json_out else ""))
    else:
        if baseline:
            console.print("[dim]Lan chay dau: chi ghi moc, se bao tu lan sau.[/dim]")
        render_console(result, console)

    # Exit code lets a scheduled task or CI step react without parsing output.
    raise typer.Exit(code=2 if result.security_events else 0)


@app.command()
def add(
    slugs: list[str] = typer.Argument(..., help="Slug can them."),
    watchlist: Path = typer.Option(DEFAULT_WATCHLIST, "--watchlist", "-w"),
) -> None:
    """Them slug vao danh sach theo doi (bo qua slug da co)."""
    existing = _read_watchlist(watchlist) if watchlist.exists() else []
    added = [s for s in slugs if s not in existing]
    if added:
        watchlist.parent.mkdir(parents=True, exist_ok=True)
        with watchlist.open("a", encoding="utf-8") as handle:
            for slug in added:
                handle.write(slug + "\n")
    console.print(f"Da them {len(added)} slug, danh sach hien co {len(existing) + len(added)}.")


@app.command()
def watch(
    interval: int = typer.Option(300, "--interval", "-i",
                                 help="Giay giua hai lan kiem tra."),
    watchlist: Path = typer.Option(DEFAULT_WATCHLIST, "--watchlist", "-w"),
    state_path: Path = typer.Option(DEFAULT_STATE, "--state"),
    json_out: Path = typer.Option(..., "--json", help="Report cuon cho backend doc."),
    repo_wide: bool = typer.Option(True, "--repo/--no-repo",
                                   help="Theo doi toan bo kho wp.org."),
    repo_pages: int = typer.Option(1, "--repo-pages"),
    discover_new: bool = typer.Option(True, "--discover-new/--no-discover-new"),
    min_installs: int = typer.Option(0, "--min-installs"),
    delay: float = typer.Option(0.25, "--delay"),
    keep_hours: int = typer.Option(24, "--keep-hours",
                                   help="Giu event bao lau trong report cuon."),
) -> None:
    """Chay lien tuc: kiem tra moi `interval` giay va ghi report cuon.

    Day la che do danh cho service. Mot lan chay that bai KHONG lam dung vong
    lap - mat mang mot lat thi lan sau bat kip, vi wp.org van giu 100 ban cap
    nhat gan nhat (khoang 6 gio) trong danh sach.
    """
    store_path = state_path
    console.print(f"[dim]plugin-release-watch: moi {interval}s, ghi {json_out}[/dim]")

    while True:
        started = time.monotonic()
        try:
            slugs = _read_watchlist(watchlist) if watchlist.exists() else []
            store = StateStore(store_path)
            result = run_watch(
                slugs, store,
                discover_new=discover_new,
                repo_wide=repo_wide,
                repo_pages=repo_pages,
                min_installs=min_installs,
                delay=delay,
            )
            store.prune()
            store.save()
            write_json(result, json_out, keep_hours=keep_hours)

            if result.events:
                security = len(result.security_events)
                console.print(f"{_now()} {len(result.events)} thay doi"
                              + (f", {security} ban va bao mat" if security else ""))
        except Exception as exc:  # noqa: BLE001 - a watcher must not die on one bad cycle
            console.print(f"[yellow]{_now()} chu ky loi: {exc}[/yellow]")

        # Measure from the START of the cycle so a slow run does not stretch the
        # gap: what matters is how stale the feed can be, not how long work took.
        time.sleep(max(5.0, interval - (time.monotonic() - started)))


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


@app.command("list")
def list_watched(
    watchlist: Path = typer.Option(DEFAULT_WATCHLIST, "--watchlist", "-w"),
    state_path: Path = typer.Option(DEFAULT_STATE, "--state"),
) -> None:
    """Xem dang theo doi nhung gi va phien ban ghi nhan lan cuoi."""
    slugs = _read_watchlist(watchlist)
    store = StateStore(state_path)
    for slug in slugs:
        version = store.previous_version(slug) or "(chua co moc)"
        console.print(f"  {slug:44} {version}")
    console.print(f"\nTong: {len(slugs)} plugin.")


def main() -> None:
    try:
        app()
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
