"""Render a WatchResult for the three audiences that consume it.

  console   a human deciding what to open next
  JSON      the AnalysisHub backend, and any other tooling
  HTML      a self-contained page that survives being emailed or archived

Every renderer suggests the follow-up command, because the point of a release
alert is the diff that comes after it - not the alert itself.
"""

from __future__ import annotations

import html
import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from rich.console import Console
from rich.table import Table

from .models import Event, Signal, WatchResult

_LABEL = {
    Signal.SECURITY_FIX: ("VA BAO MAT", "bold red"),
    Signal.NEW_PLUGIN: ("PLUGIN MOI", "bold yellow"),
    Signal.RELEASE: ("ban moi", "dim"),
}


def next_step(event: Event) -> str:
    """What to run now that this release exists.

    A security release is only useful if somebody diffs it against the version
    before, which is where the vendor's own patch shows which control they
    added - and which sibling handlers they forgot.
    """
    if event.signal is Signal.NEW_PLUGIN:
        return f"fetch_plugin.py {event.slug}"
    if event.signal is Signal.SECURITY_FIX:
        return f"incomplete_fix.py {event.slug}"
    return (f"diff_versions.py {event.slug} "
            f"--from {event.previous_version} --to {event.current_version}")


def render_console(result: WatchResult, console: Console | None = None) -> None:
    console = console or Console()

    if not result.events:
        console.print(f"[dim]Khong co thay doi. Da kiem tra {result.watched} plugin.[/dim]")
        if result.unreachable:
            console.print(f"[yellow]Khong ket noi duoc: {len(result.unreachable)}[/yellow]")
        return

    table = Table(title=f"{len(result.events)} thay doi / {result.watched} plugin theo doi")
    table.add_column("Loai", no_wrap=True)
    table.add_column("Cai dat", justify="right", no_wrap=True)
    table.add_column("Plugin", no_wrap=True)
    table.add_column("Phien ban", no_wrap=True)
    table.add_column("Buoc tiep theo")

    for event in result.events:
        label, style = _LABEL[event.signal]
        version = (f"{event.previous_version} -> {event.current_version}"
                   if event.previous_version else event.current_version)
        table.add_row(f"[{style}]{label}[/{style}]", f"{event.active_installs:,}",
                      event.slug, version, next_step(event))
    console.print(table)

    for event in result.events:
        if not event.matches:
            continue
        console.print(f"\n[bold]{event.slug}[/bold] - dong changelog dang chu y:")
        for match in event.matches:
            console.print(f"  [red]*[/red] {match.line}")

    if result.unreachable:
        console.print(f"\n[yellow]Khong ket noi duoc ({len(result.unreachable)}):[/yellow] "
                      + ", ".join(result.unreachable[:12]))


def write_json(result: WatchResult, path: str | Path, *, keep_hours: int = 24) -> Path:
    """Serialise for the AnalysisHub backend. See models.py for the contract.

    The file is a ROLLING window, not just this run's delta. The tool and the
    backend are on independent schedules: if the file held only the newest run,
    every event produced between two backend reads would be overwritten and lost
    for good — and the events most likely to be lost are exactly the ones from a
    burst of releases, which is when the feed matters most.

    Carrying the last `keep_hours` of events makes the hand-off self-healing: the
    backend can read late, twice, or not at all for a while, and still sees
    everything. Re-reading costs nothing because it dedupes on slug@version.

    Written atomically — the backend polls this path every minute and must never
    observe a half-written file.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)

    merged = _merge_recent(result, target, keep_hours)

    fd, tmp = tempfile.mkstemp(dir=str(target.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(merged.model_dump_json(indent=2))
        os.replace(tmp, target)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return target


def _merge_recent(result: WatchResult, target: Path, keep_hours: int) -> WatchResult:
    """This run's events plus the still-recent ones already on disk.

    Identity is slug@version — the same key the backend dedupes on — so an event
    that reappears keeps its first-seen position rather than being duplicated.
    A missing or unreadable previous report is not an error: it just means there
    is nothing to carry forward.
    """
    if keep_hours <= 0:
        return result

    carried: list[Event] = []
    try:
        previous = WatchResult.model_validate_json(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return result

    cutoff = datetime.now(timezone.utc) - timedelta(hours=keep_hours)
    stamp = previous.generated_at
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    if stamp >= cutoff:
        fresh = {(e.slug, e.current_version) for e in result.events}
        carried = [e for e in previous.events if (e.slug, e.current_version) not in fresh]

    return WatchResult(
        generated_at=result.generated_at,
        watched=result.watched,
        unreachable=result.unreachable,
        events=result.events + carried,
    )


def write_html(result: WatchResult, path: str | Path) -> Path:
    """A single file with no external assets, so it still works offline."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)

    rows = []
    for event in result.events:
        label, _ = _LABEL[event.signal]
        version = (f"{html.escape(event.previous_version)} &rarr; {html.escape(event.current_version)}"
                   if event.previous_version else html.escape(event.current_version))
        lines = "".join(
            f"<li>{html.escape(match.line)}</li>" for match in event.matches
        )
        rows.append(
            f'<tr class="{event.signal.value}">'
            f"<td>{label}</td>"
            f"<td class=num>{event.active_installs:,}</td>"
            f"<td><a href='https://wordpress.org/plugins/{html.escape(event.slug)}/'>"
            f"{html.escape(event.slug)}</a></td>"
            f"<td>{version}</td>"
            f"<td><code>{html.escape(next_step(event))}</code></td>"
            f"</tr>"
            + (f'<tr class="detail"><td colspan=5><ul>{lines}</ul></td></tr>' if lines else "")
        )

    target.write_text(
        _HTML_TEMPLATE.format(
            generated=html.escape(result.generated_at.strftime("%Y-%m-%d %H:%M UTC")),
            watched=result.watched,
            changed=len(result.events),
            security=len(result.security_events),
            rows="\n".join(rows) or '<tr><td colspan=5>Khong co thay doi.</td></tr>',
        ),
        encoding="utf-8",
    )
    return target


_HTML_TEMPLATE = """<!doctype html>
<html lang="vi"><head><meta charset="utf-8">
<title>Plugin Release Watch</title>
<style>
 body{{font:14px/1.5 Segoe UI,system-ui,sans-serif;margin:2rem;color:#1a1a1a;background:#fff}}
 h1{{font-size:1.3rem;margin:0 0 .3rem}}
 .meta{{color:#666;margin-bottom:1.2rem}}
 table{{border-collapse:collapse;width:100%}}
 th,td{{padding:.45rem .6rem;border-bottom:1px solid #e5e5e5;text-align:left;vertical-align:top}}
 th{{background:#fafafa;font-weight:600}}
 td.num{{text-align:right;font-variant-numeric:tabular-nums}}
 tr.security_fix td:first-child{{color:#b00020;font-weight:700}}
 tr.new_plugin td:first-child{{color:#8a6d00;font-weight:700}}
 tr.release td:first-child{{color:#888}}
 tr.detail td{{background:#fff8f8;border-bottom:2px solid #e5e5e5}}
 tr.detail ul{{margin:.2rem 0 .2rem 1rem;padding:0}}
 code{{background:#f3f3f3;padding:.1rem .35rem;border-radius:3px}}
 @media(prefers-color-scheme:dark){{
   body{{background:#161616;color:#e8e8e8}} th{{background:#222}}
   th,td{{border-color:#333}} tr.detail td{{background:#241c1c}}
   code{{background:#262626}} a{{color:#7fb3ff}}
 }}
</style></head><body>
<h1>Plugin Release Watch</h1>
<div class=meta>{generated} &middot; theo doi {watched} plugin &middot;
 {changed} thay doi &middot; <strong>{security} ban va bao mat</strong></div>
<table>
 <tr><th>Loai</th><th>Cai dat</th><th>Plugin</th><th>Phien ban</th><th>Buoc tiep theo</th></tr>
 {rows}
</table>
</body></html>
"""
