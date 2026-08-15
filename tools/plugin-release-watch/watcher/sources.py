"""The wordpress.org plugin API, and nothing else.

Only public endpoints are used and only metadata is requested - version,
timestamps, install count and the changelog the vendor publishes. Nothing here
touches a live site.

Two endpoints matter:

  plugin_information   one plugin, including `sections.changelog`. The changelog
                       is the whole point: it is the vendor saying what they
                       fixed.
  query_plugins        used with browse=new to find plugins that have just
                       appeared - code nobody has read yet.
"""

from __future__ import annotations

import html as html_mod
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request

from .models import Release

# Both calls go to info/1.2. The older info/1.0 endpoint takes the slug in the
# PATH (.../1.0/<slug>.json) and answers 400 to the query-string form used here.
INFO_API = "https://api.wordpress.org/plugins/info/1.2/"
QUERY_API = "https://api.wordpress.org/plugins/info/1.2/"
USER_AGENT = "AnalysisHub plugin-release-watch (security research)"

_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"[ \t]+")


class SourceError(RuntimeError):
    """The API could not be reached or answered with something unusable."""


def _get(url: str, timeout: int) -> dict | list:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = response.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise SourceError(str(exc)) from exc
    try:
        return json.loads(payload)
    except json.JSONDecodeError as exc:
        raise SourceError("khong phai JSON hop le") from exc


def _plain_text(html: str) -> str:
    """Changelogs are HTML. Keep the line structure, drop the markup.

    Line structure is load-bearing: detect.py works per line so it can show the
    reader the sentence that triggered a flag.
    """
    text = _TAG_RE.sub("\n", html or "")
    text = text.replace("&#8211;", "-").replace("&#8217;", "'").replace("&amp;", "&")
    lines = [_WS_RE.sub(" ", ln).strip() for ln in text.splitlines()]
    return "\n".join(ln for ln in lines if ln)


def section_for_version(changelog: str, version: str, max_lines: int) -> str:
    """The changelog entry for `version`, not merely the top of the file.

    Plugins do not agree on ordering. wpForo puts the newest release first;
    DSGVO All in one starts at 1.0.0 and works forward, so taking the first few
    lines returns an entry from years ago and a real "Security: ..." line in the
    current release is never seen.

    So find the heading that names the version and read forward until the next
    heading. Falls back to the top of the changelog when the version cannot be
    located, which is better than returning nothing.
    """
    lines = changelog.splitlines()
    if not lines:
        return ""

    # A heading is a short line that contains the version and little else -
    # "5.0", "= 5.0 =", "v5.0 - 2026-04-11". Requiring it to be short avoids
    # matching a sentence that merely mentions the number.
    escaped = re.escape(version)
    heading = re.compile(rf"(?:^|[^\d.]){escaped}(?:$|[^\d.])")
    start = None
    for index, line in enumerate(lines):
        if len(line) <= 60 and heading.search(line):
            start = index
            break
    if start is None:
        return "\n".join(lines[:max_lines])

    collected = [lines[start]]
    for line in lines[start + 1:]:
        # Stop at the next version heading so one entry does not bleed into the
        # release before it.
        if len(line) <= 60 and re.match(r"^[=\sv]*\d+\.\d+", line):
            break
        collected.append(line)
        if len(collected) >= max_lines:
            break
    return "\n".join(collected)


def fetch_release(slug: str, *, timeout: int = 45, changelog_lines: int = 20) -> Release:
    """Current metadata for one plugin.

    Raises SourceError so the caller can record the slug as unreachable rather
    than mistaking a network blip for "nothing changed" - silently treating a
    failed fetch as no-change is how a watcher goes quiet without anyone
    noticing.
    """
    params = {"action": "plugin_information", "request[slug]": slug}
    for field in ("version", "last_updated", "active_installs", "downloaded",
                  "sections", "name"):
        params[f"request[fields][{field}]"] = "1"

    data = _get(INFO_API + "?" + urllib.parse.urlencode(params), timeout)
    if not isinstance(data, dict) or not data.get("version"):
        raise SourceError(f"khong tim thay plugin '{slug}'")

    changelog = _plain_text((data.get("sections") or {}).get("changelog", ""))
    head = section_for_version(changelog, str(data["version"]), changelog_lines)

    return Release(
        slug=slug,
        name=html_mod.unescape(str(data.get("name") or slug)),
        version=str(data["version"]),
        last_updated=str(data.get("last_updated") or ""),
        active_installs=int(data.get("active_installs") or 0),
        downloaded=int(data.get("downloaded") or 0),
        changelog_head=head,
    )


def _browse(browse: str, *, pages: int, timeout: int, delay: float) -> list[Release]:
    """One page-walk of query_plugins for a browse mode.

    query_plugins does NOT return `sections`, so the Release objects it yields
    carry no changelog. That is deliberate: asking for 100 changelogs to find the
    two that changed would be 100 wasted requests. The caller fetches the full
    record only for the slugs whose version actually moved.
    """
    found: list[Release] = []
    for page in range(1, pages + 1):
        params = {
            "action": "query_plugins",
            "request[browse]": browse,
            "request[per_page]": "100",
            "request[page]": str(page),
        }
        try:
            data = _get(QUERY_API + "?" + urllib.parse.urlencode(params), timeout)
        except SourceError:
            break
        if not isinstance(data, dict):
            break
        items = data.get("plugins") or []
        if not items:
            break
        for item in items:
            slug = item.get("slug")
            if not slug:
                continue
            found.append(Release(
                slug=str(slug),
                name=html_mod.unescape(str(item.get("name") or slug)),
                version=str(item.get("version") or ""),
                last_updated=str(item.get("last_updated") or ""),
                active_installs=int(item.get("active_installs") or 0),
                downloaded=int(item.get("downloaded") or 0),
                changelog_head=_plain_text(str(item.get("short_description") or ""))[:300],
            ))
        if delay:
            time.sleep(delay)
    return found


def fetch_new_plugins(*, pages: int = 2, timeout: int = 45,
                      delay: float = 0.4) -> list[Release]:
    """Plugins wp.org currently lists as newest."""
    return _browse("new", pages=pages, timeout=timeout, delay=delay)


def fetch_recently_updated(*, pages: int = 1, timeout: int = 45,
                           delay: float = 0.4) -> list[Release]:
    """Every plugin in the repository that was just updated, newest first.

    This is what makes the watcher repository-wide instead of watchlist-wide. A
    watchlist can only ever report on plugins someone already thought to add;
    the interesting release is usually in a plugin nobody was watching yet.

    Sizing: the repository publishes roughly 15-20 updates an hour, so one page
    of 100 covers about six hours. Polling every few minutes therefore has a
    very large margin - even a multi-hour outage of this tool is caught up on
    the next successful run, with nothing missed.
    """
    return _browse("updated", pages=pages, timeout=timeout, delay=delay)
