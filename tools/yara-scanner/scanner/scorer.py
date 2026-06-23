from __future__ import annotations

from scanner.engines.base import EngineHit
from scanner.models import Severity


def aggregate(hits: list[EngineHit]) -> tuple[int, Severity, list[str], list[str], str | None]:
    if not hits:
        return 0, "clean", [], [], None
    base = max(h.score for h in hits)
    bonus = 5 * (len(hits) - 1)
    score = min(100, base + bonus)
    reasons: list[str] = []
    engines: list[str] = []
    snippet: str | None = None
    for h in hits:
        reasons.extend(h.reasons)
        if h.engine not in engines:
            engines.append(h.engine)
        if snippet is None and h.snippet:
            snippet = h.snippet
    return score, classify(score), reasons, engines, snippet


def classify(score: int) -> Severity:
    if score >= 95:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "clean"
