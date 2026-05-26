from __future__ import annotations

import logging
from pathlib import Path

from scanner.engines.base import EngineHit
from scanner.paths import rules_dir

log = logging.getLogger(__name__)

_SEVERITY_SCORE = {
    "critical": 95,
    "high": 75,
    "medium": 55,
    "low": 35,
}


class YaraEngine:
    name = "yara"

    def __init__(self, rules_path: Path | None = None) -> None:
        try:
            import yara  # type: ignore[import-not-found]
        except ImportError:
            log.warning("yara-python not installed; YaraEngine disabled")
            self._rules = None
            return

        rules_root = rules_path or (rules_dir() / "yara")
        files = sorted(rules_root.glob("*.yar")) + sorted(rules_root.glob("*.yara"))
        if not files:
            log.warning("No YARA rules found in %s; engine disabled", rules_root)
            self._rules = None
            return

        filepaths = {f.stem: str(f) for f in files}
        try:
            self._rules = yara.compile(filepaths=filepaths)
        except Exception as exc:  # noqa: BLE001
            log.error("Failed to compile YARA rules: %s", exc)
            self._rules = None

    def scan(self, path: Path, content: bytes) -> EngineHit | None:
        if self._rules is None:
            return None
        try:
            matches = self._rules.match(data=content)
        except Exception as exc:  # noqa: BLE001
            log.debug("YARA match error on %s: %s", path, exc)
            return None
        if not matches:
            return None

        best_score = 0
        reasons: list[str] = []
        snippet: str | None = None
        for m in matches:
            severity = _meta_get(m.meta, "severity", "medium").lower()
            score = _SEVERITY_SCORE.get(severity, 50)
            best_score = max(best_score, score)
            reasons.append(f"yara:{m.rule}")
            if snippet is None:
                snippet = _extract_snippet(content, m)
        return EngineHit(engine=self.name, score=best_score, reasons=reasons, snippet=snippet)


def _meta_get(meta: dict | list, key: str, default: str) -> str:
    if isinstance(meta, dict):
        return str(meta.get(key, default))
    for k, v in meta or []:
        if k == key:
            return str(v)
    return default


def _extract_snippet(content: bytes, match) -> str | None:
    """Extract a context snippet around the first matching string in a YARA match.

    Handles both yara-python >= 4.3 (StringMatch objects with .instances)
    and older tuple-based API ((offset, identifier, data)).
    """
    try:
        strings = match.strings
        if not strings:
            return None
        first = strings[0]
        if hasattr(first, "instances") and first.instances:
            inst = first.instances[0]
            off = inst.offset
            end = off + inst.matched_length
        else:
            # Older yara-python: (offset, identifier, data) tuple
            off, _name, data = first
            end = off + len(data)
        ctx = 120
        a = max(0, off - ctx)
        b = min(len(content), end + ctx)
        text = content[a:b].decode("utf-8", errors="replace")
        return text[:600]
    except Exception:  # noqa: BLE001
        return None
