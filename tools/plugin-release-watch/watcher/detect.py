"""Decide whether a changelog entry is announcing a security fix.

This is the only judgement the tool makes, and it is deliberately a shallow
one. The tool does not read code and does not claim anything is vulnerable - it
ranks what a human should open first. Over-matching costs a minute of reading;
under-matching means a patched-and-still-broken plugin sails past unnoticed, so
the list below leans inclusive.

The high-value case this exists for: a vendor patches the one function named in
a disclosure and leaves its siblings untouched. The changelog line is the vendor
telling you which file to open.
"""

from __future__ import annotations

import re

from .models import Match

# Ordered roughly by how often each word has actually sat on top of a real
# missing-authorisation bug rather than a cosmetic change.
KEYWORDS: tuple[str, ...] = (
    r"CVE-\d{4}-\d{4,7}",
    r"securit\w*",
    r"vulnerab\w*",
    r"unauthoriz\w*",
    r"authoriz\w*",
    r"authentic\w*",
    r"privilege\w*",
    r"permission\w*",
    r"capabilit\w*",
    r"nonce",
    r"bypass",
    r"XSS",
    r"CSRF",
    r"SSRF",
    r"RCE",
    r"LFI",
    r"IDOR",
    r"SQL\s*inject\w*",
    r"inject\w*",
    r"sanitiz\w*",
    r"escap\w*",
    r"disclos\w*",
    r"exploit\w*",
    r"hardening",
    r"patchstack",
    r"wordfence",
    r"wpscan",
)

_PATTERN = re.compile(r"\b(?:" + "|".join(KEYWORDS) + r")\b", re.I)

# Lines that contain a keyword but say nothing about a fix. "escaped" and
# "sanitize" show up constantly in ordinary refactors, and a changelog that
# merely links to a security policy is not announcing a patch.
_NOISE = re.compile(
    r"security\s+policy|report\s+a\s+vulnerabilit|responsible\s+disclosure|"
    r"security\.txt|see\s+our\s+security",
    re.I,
)


def find_matches(changelog_head: str) -> list[Match]:
    """Every security-flavoured line in the top of a changelog, with context.

    Works line by line rather than over the whole blob so the caller can show a
    reader the sentence that triggered the flag - which is the part that decides
    whether the release is worth opening.
    """
    matches: list[Match] = []
    for raw in (changelog_head or "").splitlines():
        line = raw.strip()
        if not line or _NOISE.search(line):
            continue
        found = _PATTERN.search(line)
        if found:
            matches.append(Match(keyword=found.group(0), line=line[:200]))
    return matches


def is_security_release(changelog_head: str) -> bool:
    return bool(find_matches(changelog_head))
