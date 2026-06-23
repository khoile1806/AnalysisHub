"""Unit tests for the regex-based PatternEngine."""

from __future__ import annotations

import json
from pathlib import Path

from scanner.engines.pattern_engine import PatternEngine


def _make_config(tmp_path: Path, rules: list[dict]) -> Path:
    cfg = tmp_path / "patterns.json"
    cfg.write_text(json.dumps(rules), encoding="utf-8")
    return cfg


def test_missing_config_disables_engine_gracefully(tmp_path: Path):
    eng = PatternEngine(config_path=tmp_path / "ghost.json")
    assert eng._rules == []
    assert eng.scan(tmp_path / "any.php", b"<?php ?>") is None


def test_invalid_regex_is_skipped(tmp_path: Path):
    cfg = _make_config(tmp_path, [
        {"id": "broken", "regex": "(unclosed", "score": 50, "lang": "php"},
        {"id": "valid", "regex": "eval", "score": 60, "lang": "php"},
    ])
    eng = PatternEngine(config_path=cfg)
    ids = [r.id for r in eng._rules]
    assert ids == ["valid"]


def test_lang_routing_matches_extension(tmp_path: Path):
    cfg = _make_config(tmp_path, [
        {"id": "php_only", "regex": "MARKER", "score": 80, "lang": "php"},
    ])
    eng = PatternEngine(config_path=cfg)
    payload = b"some MARKER here"
    assert eng.scan(tmp_path / "x.py", payload) is None
    hit = eng.scan(tmp_path / "x.php", payload)
    assert hit is not None
    assert hit.score == 80
    assert hit.reasons == ["pattern:php_only"]


def test_lang_any_applies_everywhere(tmp_path: Path):
    cfg = _make_config(tmp_path, [
        {"id": "universal", "regex": "TOKEN", "score": 30, "lang": "any"},
    ])
    eng = PatternEngine(config_path=cfg)
    for ext in (".php", ".py", ".jsp", ".aspx"):
        hit = eng.scan(tmp_path / f"f{ext}", b"line TOKEN line")
        assert hit is not None, f"any-lang rule should fire on {ext}"


def test_picks_highest_score_among_matches(tmp_path: Path):
    cfg = _make_config(tmp_path, [
        {"id": "weak", "regex": "alpha", "score": 30, "lang": "php"},
        {"id": "strong", "regex": "beta", "score": 90, "lang": "php"},
    ])
    eng = PatternEngine(config_path=cfg)
    hit = eng.scan(tmp_path / "x.php", b"alpha and beta")
    assert hit is not None
    assert hit.score == 90
    assert sorted(hit.reasons) == ["pattern:strong", "pattern:weak"]


def test_no_match_returns_none(tmp_path: Path):
    cfg = _make_config(tmp_path, [
        {"id": "needle", "regex": "ZZZNEEDLEZZZ", "score": 90, "lang": "php"},
    ])
    eng = PatternEngine(config_path=cfg)
    assert eng.scan(tmp_path / "x.php", b"haystack only") is None


def test_snippet_includes_match_context(tmp_path: Path):
    cfg = _make_config(tmp_path, [
        {"id": "tag", "regex": "DANGEROUS", "score": 80, "lang": "php"},
    ])
    eng = PatternEngine(config_path=cfg)
    content = (b"a" * 200) + b" DANGEROUS " + (b"b" * 200)
    hit = eng.scan(tmp_path / "x.php", content)
    assert hit is not None
    assert hit.snippet is not None
    assert "DANGEROUS" in hit.snippet


def test_snippet_truncated_to_max_len(tmp_path: Path):
    cfg = _make_config(tmp_path, [
        {"id": "tag", "regex": "X", "score": 50, "lang": "any"},
    ])
    eng = PatternEngine(config_path=cfg)
    content = b"A" * 5000 + b"X" + b"B" * 5000
    hit = eng.scan(tmp_path / "x.php", content)
    assert hit is not None
    assert hit.snippet is not None
    assert len(hit.snippet) <= 600  # 500 + ellipsis allowance


def test_case_insensitive_and_multiline(tmp_path: Path):
    cfg = _make_config(tmp_path, [
        {"id": "evalcase", "regex": "EVAL\\s*\\(", "score": 70, "lang": "php"},
    ])
    eng = PatternEngine(config_path=cfg)
    hit = eng.scan(tmp_path / "x.php", b"some\neval(\n$x)\n;")
    assert hit is not None
    assert hit.score == 70


def test_htaccess_routes_to_htaccess_lang(tmp_path: Path):
    cfg = _make_config(tmp_path, [
        {"id": "ht_addtype", "regex": "AddType", "score": 60, "lang": "htaccess"},
    ])
    eng = PatternEngine(config_path=cfg)
    hit = eng.scan(tmp_path / ".htaccess", b"AddType application/x-httpd-php .jpg")
    assert hit is not None
    assert hit.reasons == ["pattern:ht_addtype"]
