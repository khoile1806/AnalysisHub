from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol


@dataclass
class EngineHit:
    engine: str
    score: int
    reasons: list[str] = field(default_factory=list)
    snippet: str | None = None


class Engine(Protocol):
    name: str

    def scan(self, path: Path, content: bytes) -> EngineHit | None: ...
