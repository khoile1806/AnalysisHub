"""What we saw last time, so this run can report only the difference.

The rule that keeps the tool trustworthy: the first time a plugin is observed
it is recorded and NOT reported. Without that, adding a slug to the watchlist
would fire an alert for a release that shipped months ago, and a watcher that
cries wolf on day one stops being read by day three.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from .models import Release


class StateStore:
    """Last-seen version per slug, persisted as JSON."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        self._data: dict = self._load()

    def _load(self) -> dict:
        try:
            with self.path.open(encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return {"plugins": {}, "seen_new": []}
        data.setdefault("plugins", {})
        data.setdefault("seen_new", [])
        return data

    def known(self, slug: str) -> bool:
        return slug in self._data["plugins"]

    def previous_version(self, slug: str) -> str | None:
        entry = self._data["plugins"].get(slug)
        return entry.get("version") if entry else None

    def record(self, release: Release) -> None:
        self._data["plugins"][release.slug] = {
            "version": release.version,
            "last_updated": release.last_updated,
        }

    def has_new_plugin_baseline(self) -> bool:
        """True once the newest-plugin list has been observed at least once.

        Distinguishes "nothing is new" from "we have never looked", which is the
        difference between a quiet feed and 200 false alarms on install day.
        """
        return bool(self._data["seen_new"])

    def is_new_plugin_seen(self, slug: str) -> bool:
        return slug in self._data["seen_new"]

    def mark_new_plugin_seen(self, slug: str) -> None:
        if slug not in self._data["seen_new"]:
            self._data["seen_new"].append(slug)

    def prune(self, max_plugins: int = 250_000, max_seen_new: int = 50_000) -> int:
        """Bound the file so repository-wide watching cannot grow it forever.

        Watchlist mode touches a handful of slugs; repository-wide mode records
        every plugin it lists, which at ~400 releases a day means the state file
        grows without limit and eventually costs more to load than the run itself.

        Entries are dropped oldest-first by `last_updated`, which is the right
        order here: a plugin that has not shipped in years is the one least
        likely to ship next, and re-learning its baseline costs one skipped
        event, not a false alarm.
        """
        dropped = 0
        plugins = self._data["plugins"]
        if len(plugins) > max_plugins:
            ordered = sorted(plugins.items(), key=lambda kv: kv[1].get("last_updated") or "")
            for slug, _ in ordered[: len(plugins) - max_plugins]:
                del plugins[slug]
                dropped += 1
        seen = self._data["seen_new"]
        if len(seen) > max_seen_new:
            # These carry no timestamp; keep the tail, which is the most recent.
            dropped += len(seen) - max_seen_new
            self._data["seen_new"] = seen[-max_seen_new:]
        return dropped

    def save(self) -> None:
        """Write atomically.

        A watcher is usually run unattended on a schedule. A half-written state
        file after an interrupted run would either replay old alerts or lose the
        baseline entirely, so the new content lands in a temp file first and is
        moved into place in one step.
        """
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._data["seen_new"] = sorted(self._data["seen_new"])
        fd, tmp = tempfile.mkstemp(dir=str(self.path.parent), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(self._data, handle, indent=2, ensure_ascii=False)
            os.replace(tmp, self.path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
