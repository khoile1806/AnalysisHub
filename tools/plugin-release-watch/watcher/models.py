"""Data shapes shared by every stage of the watcher.

These models are also the integration contract: `report.json` is a serialised
`WatchResult`, and the AnalysisHub backend reads it without needing to know
anything about how the data was gathered. Changing a field name here is a
breaking change for that consumer, so treat the JSON names as an API.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class Signal(str, Enum):
    """Why a release ended up in the report.

    Ordered by how much attention it deserves, which is also the sort order
    used by the reporters.
    """

    SECURITY_FIX = "security_fix"   # the changelog says so in as many words
    NEW_PLUGIN = "new_plugin"       # code nobody has read yet
    RELEASE = "release"             # a version change with no security wording


class Match(BaseModel):
    """One security-flavoured phrase found in a changelog, with its context.

    Keeping the surrounding line matters: "fixed a security issue in the export
    endpoint" tells a reader which file to open, while the bare keyword tells
    them nothing.
    """

    keyword: str
    line: str


class Release(BaseModel):
    """A plugin as wp.org describes it right now."""

    slug: str
    name: str = ""
    version: str
    last_updated: str = ""
    # wp.org publishes active_installs ROUNDED DOWN to a bucket (20000 means
    # "20,000+"), so it is a floor, not a measurement. `downloaded` is the exact
    # cumulative figure. Keeping both lets the UI say which is which instead of
    # presenting a bucket as if it were counted.
    active_installs: int = 0
    downloaded: int = 0
    changelog_head: str = ""


class Event(BaseModel):
    """Something changed since the last run.

    `previous_version` is None for a plugin seen for the first time under
    --discover-new; for a tracked plugin it is always populated, because the
    very first observation only records a baseline and never reports.
    """

    slug: str
    name: str = ""
    signal: Signal
    previous_version: str | None = None
    current_version: str
    active_installs: int = 0
    downloaded: int = 0
    last_updated: str = ""
    changelog_head: str = ""
    matches: list[Match] = Field(default_factory=list)

    @property
    def sort_key(self) -> tuple:
        order = {Signal.SECURITY_FIX: 0, Signal.NEW_PLUGIN: 1, Signal.RELEASE: 2}
        return (order[self.signal], -self.active_installs, self.slug)


class WatchResult(BaseModel):
    """Everything one run produced. Serialised as report.json."""

    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    watched: int = 0
    unreachable: list[str] = Field(default_factory=list)
    events: list[Event] = Field(default_factory=list)

    @property
    def security_events(self) -> list[Event]:
        return [e for e in self.events if e.signal is Signal.SECURITY_FIX]
