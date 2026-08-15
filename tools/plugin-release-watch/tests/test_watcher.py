"""Tests for the parts that decide what gets reported.

The network layer is stubbed everywhere: a watcher whose tests need wp.org to be
up is a watcher whose tests get skipped.
"""

from __future__ import annotations

import json

import pytest

from watcher import runner
from watcher.detect import find_matches, is_security_release
from watcher.models import Release, Signal
from watcher.report import next_step, write_html, write_json
from watcher.runner import run_watch
from watcher.sources import SourceError, _plain_text
from watcher.state import StateStore


# ── detect ────────────────────────────────────────────────────────────────────

def test_security_wording_is_flagged_with_its_line():
    log = "3.1.4\nSecurity: Fixed access control bypass in widget AJAX handlers\nFixed: typo"
    matches = find_matches(log)
    assert len(matches) == 1
    assert "access control bypass" in matches[0].line


def test_cve_reference_alone_is_enough():
    assert is_security_release("Patched CVE-2026-4298 reported via Patchstack")


def test_ordinary_changelog_is_not_flagged():
    assert not is_security_release("Added a new shortcode\nFixed a layout glitch")


def test_link_to_a_security_policy_is_not_a_patch():
    # A plugin that merely advertises where to report bugs must not wake anyone.
    assert not is_security_release("See our security policy to report a vulnerability")


# ── state ─────────────────────────────────────────────────────────────────────

def test_first_sighting_records_but_does_not_report(tmp_path, monkeypatch):
    store = StateStore(tmp_path / "state.json")
    monkeypatch.setattr(runner, "fetch_release", lambda slug, **kw: Release(
        slug=slug, name=slug, version="1.0.0", active_installs=10_000,
        changelog_head="Security: fixed an authorisation bypass"))

    result = run_watch(["demo"], store, delay=0)

    assert result.events == []
    assert store.previous_version("demo") == "1.0.0"


def test_version_change_after_baseline_is_reported(tmp_path, monkeypatch):
    store = StateStore(tmp_path / "state.json")
    versions = iter(["1.0.0", "1.0.1"])
    monkeypatch.setattr(runner, "fetch_release", lambda slug, **kw: Release(
        slug=slug, name=slug, version=next(versions), active_installs=20_000,
        changelog_head="Security: fixed a missing capability check"))

    assert run_watch(["demo"], store, delay=0).events == []
    result = run_watch(["demo"], store, delay=0)

    assert len(result.events) == 1
    event = result.events[0]
    assert event.signal is Signal.SECURITY_FIX
    assert (event.previous_version, event.current_version) == ("1.0.0", "1.0.1")


def test_state_survives_a_reload(tmp_path):
    path = tmp_path / "state.json"
    store = StateStore(path)
    store.record(Release(slug="demo", name="demo", version="2.0"))
    store.save()

    assert StateStore(path).previous_version("demo") == "2.0"


# ── runner ────────────────────────────────────────────────────────────────────

def test_unreachable_plugin_is_listed_not_silently_skipped(tmp_path, monkeypatch):
    # Treating a network failure as "no change" is how a watcher goes quiet.
    store = StateStore(tmp_path / "state.json")

    def boom(slug, **kw):
        raise SourceError("network down")

    monkeypatch.setattr(runner, "fetch_release", boom)
    result = run_watch(["demo"], store, delay=0)

    assert result.unreachable == ["demo"]
    assert not store.known("demo")


def test_security_only_drops_plain_releases(tmp_path, monkeypatch):
    store = StateStore(tmp_path / "state.json")
    versions = iter(["1.0", "1.1"])
    monkeypatch.setattr(runner, "fetch_release", lambda slug, **kw: Release(
        slug=slug, name=slug, version=next(versions), active_installs=5_000,
        changelog_head="Added a new widget"))

    run_watch(["demo"], store, delay=0)
    assert run_watch(["demo"], store, security_only=True, delay=0).events == []


def test_min_installs_filters_small_plugins(tmp_path, monkeypatch):
    store = StateStore(tmp_path / "state.json")
    versions = iter(["1.0", "1.1"])
    monkeypatch.setattr(runner, "fetch_release", lambda slug, **kw: Release(
        slug=slug, name=slug, version=next(versions), active_installs=50,
        changelog_head="Security: fixed XSS"))

    run_watch(["demo"], store, delay=0)
    assert run_watch(["demo"], store, min_installs=1_000, delay=0).events == []


def test_security_events_sort_above_plain_releases(tmp_path, monkeypatch):
    store = StateStore(tmp_path / "state.json")
    state = {"a": iter(["1.0", "1.1"]), "b": iter(["1.0", "1.1"])}
    logs = {"a": "Added a setting", "b": "Security: fixed CSRF"}
    monkeypatch.setattr(runner, "fetch_release", lambda slug, **kw: Release(
        slug=slug, name=slug, version=next(state[slug]), active_installs=1_000,
        changelog_head=logs[slug]))

    run_watch(["a", "b"], store, delay=0)
    result = run_watch(["a", "b"], store, delay=0)

    assert [e.slug for e in result.events] == ["b", "a"]


# ── report ────────────────────────────────────────────────────────────────────

def test_next_step_points_at_the_incomplete_fix_hunt():
    from watcher.models import Event
    event = Event(slug="demo", signal=Signal.SECURITY_FIX,
                  previous_version="1.0", current_version="1.1")
    assert "incomplete_fix.py demo" in next_step(event)


def test_json_report_is_the_integration_contract(tmp_path, monkeypatch):
    store = StateStore(tmp_path / "state.json")
    versions = iter(["1.0", "1.1"])
    monkeypatch.setattr(runner, "fetch_release", lambda slug, **kw: Release(
        slug=slug, name=slug, version=next(versions), active_installs=30_000,
        changelog_head="Security: fixed a nonce check"))

    run_watch(["demo"], store, delay=0)
    result = run_watch(["demo"], store, delay=0)
    path = write_json(result, tmp_path / "report.json")

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["events"][0]["signal"] == "security_fix"
    assert payload["events"][0]["slug"] == "demo"
    assert "generated_at" in payload


def test_html_report_is_self_contained(tmp_path, monkeypatch):
    store = StateStore(tmp_path / "state.json")
    versions = iter(["1.0", "1.1"])
    monkeypatch.setattr(runner, "fetch_release", lambda slug, **kw: Release(
        slug=slug, name=slug, version=next(versions), active_installs=1_000,
        changelog_head="Security: fixed SSRF"))
    run_watch(["demo"], store, delay=0)
    result = run_watch(["demo"], store, delay=0)

    text = write_html(result, tmp_path / "report.html").read_text(encoding="utf-8")
    assert "<script" not in text and "http://" not in text.split("wordpress.org")[0]
    assert "demo" in text


# ── sources ───────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("raw,expected", [
    ("<h4>3.1</h4><ul><li>Security: fixed XSS</li></ul>", ["3.1", "Security: fixed XSS"]),
    ("plain text", ["plain text"]),
])
def test_changelog_html_becomes_lines(raw, expected):
    # detect.py works per line, so the line structure has to survive stripping.
    assert _plain_text(raw).splitlines() == expected


# ── section_for_version ───────────────────────────────────────────────────────
# Plugins do not agree on changelog ordering. Assuming newest-first is a silent
# correctness bug: it reads the wrong entry and never sees the security line.

def test_newest_first_changelog():
    from watcher.sources import section_for_version
    log = "3.1.4\nSecurity: fixed bypass\n3.1.3\nOlder entry"
    assert "Security: fixed bypass" in section_for_version(log, "3.1.4", 10)
    assert "Older entry" not in section_for_version(log, "3.1.4", 10)


def test_oldest_first_changelog_still_finds_the_current_entry():
    # DSGVO All in one starts at 1.0.0 and works forward.
    from watcher.sources import section_for_version
    log = "1.0.0\nreleased\n1.0.1\nsomething\n5.0\nSecurity Bugfix"
    section = section_for_version(log, "5.0", 10)
    assert "Security Bugfix" in section
    assert "released" not in section


def test_version_inside_a_combined_heading_is_found():
    from watcher.sources import section_for_version
    log = "notes\nwpForo Forum 3.1.3/3.1.4 | 23.07.2026\nSecurity: fixed XSS"
    assert "Security: fixed XSS" in section_for_version(log, "3.1.4", 10)


def test_unknown_version_falls_back_to_the_top():
    from watcher.sources import section_for_version
    log = "1.0\nfirst\n2.0\nsecond"
    assert section_for_version(log, "9.9", 2) == "1.0\nfirst"


def test_similar_version_number_is_not_mistaken_for_a_heading():
    from watcher.sources import section_for_version
    log = "15.01 build notes\n5.0\nSecurity Bugfix"
    assert section_for_version(log, "5.0", 10).startswith("5.0")


# ── repository-wide watching ────────────────────────────────────────────────

def _listed(slug: str, version: str) -> Release:
    """A Release as the listing endpoint returns it: no changelog."""
    return Release(slug=slug, name=slug, version=version, active_installs=1000)


def test_repo_wide_first_run_only_baselines(tmp_path, monkeypatch):
    """The first repository-wide run must be silent.

    wp.org lists the 100 most recently updated plugins. On install day every one
    of them is unknown, and reporting them all would open the feed with a hundred
    releases that shipped before the tool existed.
    """
    monkeypatch.setattr(runner, "fetch_recently_updated",
                        lambda **kw: [_listed("alpha", "1.0"), _listed("beta", "2.0")])
    store = StateStore(tmp_path / "state.json")

    result = run_watch([], store, repo_wide=True)

    assert result.events == []
    assert store.previous_version("alpha") == "1.0"


def test_repo_wide_reports_a_version_change_with_its_changelog(tmp_path, monkeypatch):
    """A moved version is reported, and the changelog decides the signal.

    The listing carries no changelog, so a security release can only be told
    apart from an ordinary one by the second fetch — this pins that it happens.
    """
    monkeypatch.setattr(runner, "fetch_recently_updated",
                        lambda **kw: [_listed("alpha", "1.1")])
    monkeypatch.setattr(runner, "fetch_release", lambda slug, **kw: Release(
        slug=slug, name="Alpha", version="1.1", active_installs=90000,
        changelog_head="= 1.1 =\nSecurity: fixed an authenticated SQL injection.",
    ))
    store = StateStore(tmp_path / "state.json")
    store.record(_listed("alpha", "1.0"))

    result = run_watch([], store, repo_wide=True)

    assert len(result.events) == 1
    event = result.events[0]
    assert event.signal is Signal.SECURITY_FIX
    assert event.previous_version == "1.0"
    assert event.current_version == "1.1"
    assert event.matches, "the changelog line that justified the flag must be kept"


def test_repo_wide_does_not_refetch_unchanged_plugins(tmp_path, monkeypatch):
    """The listing is the cheap filter; the detail call must be the exception.

    100 changelog fetches per cycle to find the two that changed would be both
    slow and rude to a free public API.
    """
    monkeypatch.setattr(runner, "fetch_recently_updated",
                        lambda **kw: [_listed("alpha", "1.0"), _listed("beta", "2.0")])
    calls: list[str] = []

    def _fetch(slug, **kw):
        calls.append(slug)
        return Release(slug=slug, name=slug, version="9.9")

    monkeypatch.setattr(runner, "fetch_release", _fetch)
    store = StateStore(tmp_path / "state.json")
    store.record(_listed("alpha", "1.0"))   # unchanged
    store.record(_listed("beta", "1.0"))    # moved to 2.0

    run_watch([], store, repo_wide=True)

    assert calls == ["beta"]


def test_new_plugin_discovery_baselines_before_it_reports(tmp_path, monkeypatch):
    """Same day-one rule for the newest-plugin list."""
    monkeypatch.setattr(runner, "fetch_new_plugins",
                        lambda **kw: [_listed("brand-new", "1.0")])
    store = StateStore(tmp_path / "state.json")

    first = run_watch([], store, repo_wide=False, discover_new=True)
    assert first.events == [], "install day must not flood the feed"

    monkeypatch.setattr(runner, "fetch_new_plugins",
                        lambda **kw: [_listed("brand-new", "1.0"), _listed("later", "1.0")])
    second = run_watch([], store, repo_wide=False, discover_new=True)
    assert [e.slug for e in second.events] == ["later"]


def test_rolling_report_keeps_recent_events_across_runs(tmp_path):
    """A backend read that lands between two runs must not miss anything.

    The tool and the backend are on independent clocks; if each run overwrote the
    file with only its own delta, every event produced between two reads would be
    gone for good.
    """
    from watcher.models import Event, WatchResult

    path = tmp_path / "report.json"
    first = WatchResult(watched=1, events=[Event(
        slug="alpha", signal=Signal.SECURITY_FIX, current_version="1.1",
        previous_version="1.0")])
    write_json(first, path)

    second = WatchResult(watched=1, events=[Event(
        slug="beta", signal=Signal.RELEASE, current_version="2.0",
        previous_version="1.9")])
    write_json(second, path)

    stored = json.loads(path.read_text(encoding="utf-8"))
    slugs = {e["slug"] for e in stored["events"]}
    assert slugs == {"alpha", "beta"}, "the earlier run's event was dropped"


def test_rolling_report_does_not_duplicate_a_repeated_event(tmp_path):
    from watcher.models import Event, WatchResult

    path = tmp_path / "report.json"
    event = Event(slug="alpha", signal=Signal.RELEASE, current_version="1.1",
                  previous_version="1.0")
    write_json(WatchResult(watched=1, events=[event]), path)
    write_json(WatchResult(watched=1, events=[event]), path)

    stored = json.loads(path.read_text(encoding="utf-8"))
    assert len(stored["events"]) == 1


def test_state_prune_bounds_the_file(tmp_path):
    """Repository-wide watching records ~400 plugins a day; unbounded is a leak."""
    store = StateStore(tmp_path / "state.json")
    for i in range(10):
        store.record(Release(slug=f"p{i:02d}", name="p", version="1.0",
                             last_updated=f"2020-01-{i + 1:02d}"))

    dropped = store.prune(max_plugins=4)

    assert dropped == 6
    assert not store.known("p00"), "the stalest entry should go first"
    assert store.known("p09"), "the most recently updated must survive"


def test_plugin_names_are_html_decoded(monkeypatch):
    """wp.org returns names HTML-encoded; a raw "&#8211;" in a headline is a bug
    the reader sees on every card."""
    from watcher import sources

    monkeypatch.setattr(sources, "_get", lambda url, timeout: {
        "name": "Gamification &#8211; myCred", "version": "3.2.5",
        "active_installs": 10000, "downloaded": 1447162, "sections": {},
    })
    release = sources.fetch_release("mycred")

    assert release.name == "Gamification – myCred"
    assert release.downloaded == 1447162, "the exact download count must survive"
