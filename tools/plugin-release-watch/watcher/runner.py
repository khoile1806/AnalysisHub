"""Tie the pieces together: fetch, compare against state, produce events.

Kept free of CLI and rendering concerns so the AnalysisHub backend can call
`run_watch()` directly (or shell out to the CLI and read report.json) without
dragging typer and rich along.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence

from .detect import find_matches
from .models import Event, Signal, WatchResult
from .sources import (SourceError, fetch_new_plugins, fetch_recently_updated,
                      fetch_release)
from .state import StateStore

ProgressFn = Callable[[int, int, str], None]


def run_watch(
    slugs: Sequence[str],
    store: StateStore,
    *,
    security_only: bool = False,
    discover_new: bool = False,
    repo_wide: bool = False,
    repo_pages: int = 1,
    min_installs: int = 0,
    delay: float = 0.25,
    timeout: int = 45,
    on_progress: ProgressFn | None = None,
) -> WatchResult:
    """Check every slug once and return what changed.

    State is updated for every plugin successfully fetched, including ones that
    produce no event - that is what turns the next run into a pure delta.
    """
    result = WatchResult(watched=len(slugs))

    for index, slug in enumerate(slugs, start=1):
        if on_progress:
            on_progress(index, len(slugs), slug)
        try:
            release = fetch_release(slug, timeout=timeout)
        except SourceError:
            result.unreachable.append(slug)
            continue
        finally:
            if delay:
                time.sleep(delay)

        first_sighting = not store.known(slug)
        previous = store.previous_version(slug)
        store.record(release)

        if first_sighting or previous == release.version:
            continue
        if release.active_installs < min_installs:
            continue

        matches = find_matches(release.changelog_head)
        signal = Signal.SECURITY_FIX if matches else Signal.RELEASE
        if security_only and signal is not Signal.SECURITY_FIX:
            continue

        result.events.append(Event(
            slug=release.slug,
            name=release.name,
            signal=signal,
            previous_version=previous,
            current_version=release.version,
            active_installs=release.active_installs,
            downloaded=release.downloaded,
            last_updated=release.last_updated,
            changelog_head=release.changelog_head,
            matches=matches,
        ))

    if repo_wide:
        result.watched += watch_repository(
            store, result,
            security_only=security_only,
            min_installs=min_installs,
            pages=repo_pages,
            delay=delay,
            timeout=timeout,
        )

    if discover_new and not security_only:
        # The very first run only takes a baseline. Without this the tool opens
        # with 200 "new plugin" alerts for plugins that were published before it
        # was ever installed — the same day-one flood the per-slug path already
        # guards against, and the reason a feed stops being read by day three.
        seeding = not store.has_new_plugin_baseline()
        for release in fetch_new_plugins(timeout=timeout):
            if store.is_new_plugin_seen(release.slug):
                continue
            store.mark_new_plugin_seen(release.slug)
            if seeding:
                continue
            if release.active_installs < min_installs:
                continue
            result.events.append(Event(
                slug=release.slug,
                name=release.name,
                signal=Signal.NEW_PLUGIN,
                previous_version=None,
                current_version=release.version,
                active_installs=release.active_installs,
                downloaded=release.downloaded,
                last_updated=release.last_updated,
                changelog_head=release.changelog_head,
            ))

    result.events.sort(key=lambda event: event.sort_key)
    return result


def watch_repository(
    store: StateStore,
    result: WatchResult,
    *,
    security_only: bool = False,
    min_installs: int = 0,
    pages: int = 1,
    delay: float = 0.25,
    timeout: int = 45,
) -> int:
    """Report every plugin in the whole repository whose version just moved.

    Two-stage on purpose. The listing endpoint is cheap but carries no changelog,
    so stage one is one request per 100 plugins purely to spot version changes;
    stage two fetches the full record ONLY for those, which is where the vendor's
    own description of what they fixed lives. Classifying a release as a security
    fix without reading its changelog is not possible, and reading 100 changelogs
    to find two is not polite.

    Returns how many plugins were examined.
    """
    listed = fetch_recently_updated(pages=pages, timeout=timeout, delay=delay)
    if not listed:
        return 0

    for item in listed:
        previous = store.previous_version(item.slug)
        first_sighting = not store.known(item.slug)

        # A plugin seen for the first time is only baselined. Otherwise the first
        # repository-wide run would report several hundred releases that shipped
        # before this tool ever ran.
        if first_sighting or previous == item.version:
            store.record(item)
            continue

        # The version moved: now it is worth a second request for the changelog.
        try:
            release = fetch_release(item.slug, timeout=timeout)
        except SourceError:
            result.unreachable.append(item.slug)
            continue
        finally:
            if delay:
                time.sleep(delay)
        store.record(release)

        if release.active_installs < min_installs:
            continue

        matches = find_matches(release.changelog_head)
        signal = Signal.SECURITY_FIX if matches else Signal.RELEASE
        if security_only and signal is not Signal.SECURITY_FIX:
            continue

        result.events.append(Event(
            slug=release.slug,
            name=release.name,
            signal=signal,
            previous_version=previous,
            current_version=release.version,
            active_installs=release.active_installs,
            downloaded=release.downloaded,
            last_updated=release.last_updated,
            changelog_head=release.changelog_head,
            matches=matches,
        ))
    return len(listed)
