from __future__ import annotations

import logging
import re
from pathlib import Path

from scanner.engines.base import EngineHit
from scanner.paths import rules_dir, scenarios_dir

log = logging.getLogger(__name__)

# Scenario ids are used to build a filename, so restrict to a safe charset to
# prevent path traversal (e.g. "../../etc/passwd").
_SCENARIO_RE = re.compile(r"^[a-z0-9_]{1,40}$")

_SEVERITY_SCORE = {
    "critical": 95,
    "high": 75,
    "medium": 55,
    "low": 35,
}


class YaraEngine:
    name = "yara"

    def __init__(
        self,
        custom_rules_path: Path | None = None,
        base64_rules: str | None = None,
        scenario: str | None = None,
    ) -> None:
        try:
            import yara  # type: ignore[import-not-found]
        except ImportError:
            log.warning("yara-python not installed; YaraEngine disabled")
            self._rules = None
            return

        filepaths = {}
        sources = {}

        # 1. Built-in base rules (always loaded — general webshell/malware coverage)
        rules_root = rules_dir() / "yara"
        files = sorted(rules_root.glob("*.yar")) + sorted(rules_root.glob("*.yara"))
        for f in files:
            filepaths[f.stem] = str(f)

        # 1b. Scenario rule sets (opt-in via --scenario). "all" loads every
        # scenario; otherwise the single matching <scenario>.yar is added on top
        # of the base rules. Unknown/invalid scenarios are ignored (base only).
        if scenario:
            scen = scenario.strip().lower()
            scen_root = scenarios_dir()
            if scen == "all":
                for f in sorted(scen_root.glob("*.yar")) + sorted(scen_root.glob("*.yara")):
                    filepaths[f"scenario_{f.stem}"] = str(f)
            elif _SCENARIO_RE.match(scen):
                for ext in (".yar", ".yara"):
                    p = scen_root / f"{scen}{ext}"
                    if p.exists():
                        filepaths[f"scenario_{scen}"] = str(p)
                        break
                else:
                    log.warning("scenario %r has no rule file; using base rules only", scen)
            else:
                log.warning("invalid scenario id %r ignored; using base rules only", scenario)

        # 2. Custom rules from directory or file
        if custom_rules_path and custom_rules_path.exists():
            if custom_rules_path.is_dir():
                custom_files = sorted(custom_rules_path.glob("*.yar")) + sorted(custom_rules_path.glob("*.yara"))
                for f in custom_files:
                    filepaths[f"custom_{f.stem}"] = str(f)
            else:
                filepaths[f"custom_{custom_rules_path.stem}"] = str(custom_rules_path)

        # 3. Base64 rules
        if base64_rules:
            import base64
            try:
                decoded = base64.b64decode(base64_rules).decode('utf-8')
                sources["custom_base64"] = decoded
            except Exception as exc:
                log.error("Failed to decode base64 YARA rule: %s", exc)

        if not filepaths and not sources:
            log.warning("No YARA rules found; engine disabled")
            self._rules = None
            return

        try:
            if sources:
                # yara.compile does not accept both filepaths and sources.
                # So we must read all filepaths into sources.
                for ns, path in filepaths.items():
                    with open(path, "r", encoding="utf-8") as f:
                        sources[ns] = f.read()
                self._rules = yara.compile(sources=sources)
            else:
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
