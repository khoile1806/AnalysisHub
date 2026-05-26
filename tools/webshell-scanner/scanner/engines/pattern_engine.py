from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path

from scanner.engines.base import EngineHit
from scanner.paths import rules_dir

log = logging.getLogger(__name__)

_LANG_BY_EXT: dict[str, str] = {
    ".php": "php", ".phtml": "php", ".php3": "php", ".php4": "php",
    ".php5": "php", ".php7": "php", ".phar": "php",
    ".asp": "asp", ".aspx": "asp", ".ashx": "asp", ".asmx": "asp",
    ".jsp": "jsp", ".jspx": "jsp", ".jspf": "jsp",
    ".py": "python", ".pyc": "python",
    ".pl": "perl", ".pm": "perl", ".cgi": "perl",
    ".sh": "shell", ".bash": "shell",
    ".cfm": "cf", ".cfc": "cf",
    ".rb": "ruby",
    ".js": "js", ".mjs": "js",
    ".htaccess": "htaccess",
}


@dataclass
class _Rule:
    id: str
    score: int
    lang: str
    pattern: re.Pattern[bytes]


class PatternEngine:
    name = "pattern"

    def __init__(self, config_path: Path | None = None) -> None:
        cfg = config_path or (rules_dir() / "patterns" / "webshell.json")
        self._rules: list[_Rule] = []
        if not cfg.exists():
            log.warning("Pattern config not found at %s", cfg)
            return
        try:
            data = json.loads(cfg.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            log.error("Failed to load pattern config %s: %s", cfg, exc)
            return
        for item in data:
            try:
                self._rules.append(_Rule(
                    id=item["id"],
                    score=int(item["score"]),
                    lang=item.get("lang", "any"),
                    pattern=re.compile(item["regex"].encode("utf-8"), re.IGNORECASE | re.DOTALL),
                ))
            except (KeyError, re.error) as exc:
                log.warning("Skipping invalid pattern rule %s: %s", item, exc)

    def scan(self, path: Path, content: bytes) -> EngineHit | None:
        if not self._rules:
            return None
        ext = _ext(path)
        lang = _LANG_BY_EXT.get(ext, "any")

        best_score = 0
        reasons: list[str] = []
        snippet: str | None = None
        for rule in self._rules:
            if rule.lang not in ("any", lang):
                continue
            m = rule.pattern.search(content)
            if not m:
                continue
            best_score = max(best_score, rule.score)
            reasons.append(f"pattern:{rule.id}")
            if snippet is None:
                snippet = _make_snippet(content, m.start(), m.end())
        if best_score == 0:
            return None
        return EngineHit(engine=self.name, score=best_score, reasons=reasons, snippet=snippet)


def _ext(path: Path) -> str:
    name = path.name.lower()
    if name in {".htaccess", "htaccess"}:
        return ".htaccess"
    return path.suffix.lower()


def _make_snippet(content: bytes, start: int, end: int, *, ctx: int = 80, max_len: int = 500) -> str:
    a = max(0, start - ctx)
    b = min(len(content), end + ctx)
    chunk = content[a:b]
    text = chunk.decode("utf-8", errors="replace")
    if len(text) > max_len:
        text = text[:max_len] + "..."
    return text
