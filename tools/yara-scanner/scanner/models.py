from __future__ import annotations

import base64
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field, field_serializer

Severity = Literal["critical", "high", "medium", "low", "clean"]


class Finding(BaseModel):
    path: str
    sha256: str
    size_bytes: int
    severity: Severity
    score: int = Field(ge=0, le=100)
    reasons: list[str] = Field(default_factory=list)
    engines: list[str] = Field(default_factory=list)
    snippet: str | None = None

    @field_serializer("snippet", when_used="json")
    def _encode_snippet(self, value: str | None) -> str | None:
        # Snippets carry raw webshell strings; serialize as base64 so that AV
        # signature scanners (Windows Defender, ClamAV, …) do not quarantine
        # report.json. Consumers must base64-decode `snippet` before display.
        if value is None:
            return None
        return base64.b64encode(value.encode("utf-8")).decode("ascii")


class ScanStats(BaseModel):
    total_files: int = 0
    scanned: int = 0
    matched: int = 0
    errors: int = 0
    skipped: int = 0


class ScanReport(BaseModel):
    scanner_version: str
    rules_version: str
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    hostname: str
    targets: list[str]
    snippet_encoding: Literal["base64"] = "base64"
    stats: ScanStats = Field(default_factory=ScanStats)
    findings: list[Finding] = Field(default_factory=list)
