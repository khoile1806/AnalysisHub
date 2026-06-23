# YARA Scanner

Multi-engine webshell scanner — Phase 1 MVP của
[`yara-scanner-plan.md`](../yara-scanner-plan.md).

Engine: **YARA** + **Pattern (regex)**. Output: `report.json` + `report.html`
(self-contained, mở offline). Đóng gói thành single binary qua PyInstaller để
deploy lên ForensicHub agents (xem ROADMAP.md mục #2 — Multi-Agent Scanning).

## Cài đặt (dev)

```bash
cd yara-scanner
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

pip install -e .[dev]
```

## Chạy

```bash
python -m scanner.cli scan tests/samples/malicious --out ./out
# → out/report.json + out/report.html

python -m scanner.cli scan /var/www --out ./out --format json --min-severity medium
python -m scanner.cli scan ./site --out ./out --progress json --exclude "*/cache/*"
```

Exit codes: `0` = không có finding ≥ medium, `1` = có actionable finding, `2` = lỗi tham số.

## Test

```bash
pytest -v
```

Yêu cầu accuracy MVP: detection ≥ 80%, FP ≤ 5% trên fixture corpus.

## Build single binary (PyInstaller)

```bash
pip install pyinstaller
pyinstaller build.spec
# Output:
#   dist/yara-scanner.exe   (Windows)
#   dist/yara-scanner       (Linux)
```

Binary đã bundle `rules/` + `templates/`, không cần Python trên máy đích.

## Cấu trúc

```
scanner/
├── cli.py              typer entry
├── runner.py           pipeline điều phối engines + reporter
├── enumerator.py       file walker + filter (ext, size, exclude)
├── engines/
│   ├── yara_engine.py  YARA (severity meta -> score)
│   └── pattern_engine.py  regex JSON (rules/patterns/webshell.json)
├── scorer.py           weighted aggregate -> severity
├── reporter/
│   ├── json_reporter.py
│   └── html_reporter.py  Jinja2 + Tailwind CDN + Alpine.js
└── models.py           pydantic Finding / ScanReport
```

## Progress stream (cho integration ForensicHub)

`--progress json` phát JSONL lên stdout, dùng cho agent stream về backend qua WS:

```json
{"event":"start","total":12345}
{"event":"progress","scanned":42,"total":12345}
{"event":"finding","path":"/var/www/x.php","severity":"critical","score":98}
{"event":"done","matched":7}
```

## Output schema

`report.json` field:

```jsonc
{
  "scanner_version": "0.1.0",
  "rules_version": "abc123def456",
  "scanned_at": "2026-04-28T...",
  "hostname": "host01",
  "targets": ["/var/www"],
  "stats": {"total_files": 1234, "scanned": 1234, "matched": 5, "errors": 0, "skipped": 0},
  "findings": [
    {
      "path": "/var/www/upload/backdoor.php",
      "sha256": "...",
      "size_bytes": 412,
      "severity": "critical",
      "score": 95,
      "reasons": ["yara:WS_PHP_DirectExecSuperglobal", "pattern:php_eval_post"],
      "engines": ["yara", "pattern"],
      "snippet": "..."
    }
  ]
}
```

## Roadmap

Phase này (MVP) chỉ làm YARA + pattern. Các phase tiếp theo theo
`yara-scanner-plan.md`: entropy, AST PHP (`phply`), recursive deobfuscator,
taint analysis, differential scanning, ML layer, platform integration.

Tích hợp ForensicHub: scanner sẽ được upload như **ZIP tool** với
`executable_path = yara-scanner.exe`. Tab YARA Scanner mới sẽ chọn nhiều
agent, dispatch job, agent upload `report.json` + `report.html` qua artifact
endpoint hiện có. Chi tiết blueprint: plan riêng.
