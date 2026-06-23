"""Unit tests for the YaraEngine — severity meta -> score mapping,
graceful degradation when YARA is unavailable or rules folder is empty."""

from __future__ import annotations

from pathlib import Path

import pytest

yara = pytest.importorskip("yara")

from scanner.engines.yara_engine import YaraEngine


def _write_rules(rules_dir: Path, rules: dict[str, str]) -> None:
    (rules_dir / "yara").mkdir(parents=True, exist_ok=True)
    for name, body in rules.items():
        (rules_dir / "yara" / f"{name}.yar").write_text(body, encoding="utf-8")


def test_empty_rules_dir_disables_engine(tmp_path: Path):
    (tmp_path / "yara").mkdir()
    eng = YaraEngine(rules_path=tmp_path / "yara")
    assert eng._rules is None
    assert eng.scan(tmp_path / "any.php", b"<?php ?>") is None


def test_missing_rules_dir_disables_engine(tmp_path: Path):
    eng = YaraEngine(rules_path=tmp_path / "ghost")
    assert eng._rules is None


def test_severity_critical_maps_to_95(tmp_path: Path):
    _write_rules(tmp_path, {
        "crit": '''rule R_crit {
            meta:
                severity = "critical"
            strings:
                $a = "MARK_CRIT"
            condition:
                $a
        }'''
    })
    eng = YaraEngine(rules_path=tmp_path / "yara")
    hit = eng.scan(tmp_path / "x.php", b"... MARK_CRIT ...")
    assert hit is not None
    assert hit.score == 95
    assert hit.reasons == ["yara:R_crit"]


def test_severity_high_and_medium_and_low(tmp_path: Path):
    _write_rules(tmp_path, {
        "h": 'rule R_h { meta: severity = "high" strings: $a = "AAA" condition: $a }',
        "m": 'rule R_m { meta: severity = "medium" strings: $a = "BBB" condition: $a }',
        "l": 'rule R_l { meta: severity = "low" strings: $a = "CCC" condition: $a }',
    })
    eng = YaraEngine(rules_path=tmp_path / "yara")
    assert eng.scan(tmp_path / "x.php", b"AAA").score == 75
    assert eng.scan(tmp_path / "x.php", b"BBB").score == 55
    assert eng.scan(tmp_path / "x.php", b"CCC").score == 35


def test_missing_severity_meta_defaults_to_medium(tmp_path: Path):
    """When meta.severity is absent, the engine falls back to 'medium' (55).
    This anchors the contract — if the default ever changes, the test must move
    with it intentionally."""
    _write_rules(tmp_path, {
        "nometa": 'rule R_nometa { strings: $a = "MISSING" condition: $a }',
    })
    eng = YaraEngine(rules_path=tmp_path / "yara")
    hit = eng.scan(tmp_path / "x.php", b"data MISSING data")
    assert hit is not None
    assert hit.score == 55


def test_unknown_severity_meta_defaults_to_medium(tmp_path: Path):
    _write_rules(tmp_path, {
        "weird": 'rule R_weird { meta: severity = "spicy" strings: $a = "ZZZ" condition: $a }',
    })
    eng = YaraEngine(rules_path=tmp_path / "yara")
    hit = eng.scan(tmp_path / "x.php", b"foo ZZZ bar")
    assert hit is not None
    assert hit.score == 50  # _SEVERITY_SCORE.get fallback for unknown labels


def test_multiple_matches_keeps_highest_severity(tmp_path: Path):
    _write_rules(tmp_path, {
        "low": 'rule R_low { meta: severity = "low" strings: $a = "LO" condition: $a }',
        "crit": 'rule R_crit { meta: severity = "critical" strings: $a = "HI" condition: $a }',
    })
    eng = YaraEngine(rules_path=tmp_path / "yara")
    hit = eng.scan(tmp_path / "x.php", b"LO and HI present")
    assert hit is not None
    assert hit.score == 95
    assert "yara:R_crit" in hit.reasons
    assert "yara:R_low" in hit.reasons


def test_no_match_returns_none(tmp_path: Path):
    _write_rules(tmp_path, {
        "x": 'rule R { meta: severity = "high" strings: $a = "NEEDLE" condition: $a }',
    })
    eng = YaraEngine(rules_path=tmp_path / "yara")
    assert eng.scan(tmp_path / "x.php", b"haystack content") is None


def test_invalid_rule_disables_engine(tmp_path: Path):
    """Bad syntax in any rule file fails compile() — entire engine should
    fall back to disabled rather than raising."""
    _write_rules(tmp_path, {
        "broken": "rule busted { condition: this_is_not_valid_yara }",
    })
    eng = YaraEngine(rules_path=tmp_path / "yara")
    assert eng._rules is None
    assert eng.scan(tmp_path / "x.php", b"anything") is None


def test_default_engine_loads_bundled_rules():
    """Smoke test: the engine constructed with no path picks up rules/yara/*.yar
    bundled with the package, and at least one of them compiles."""
    eng = YaraEngine()
    assert eng._rules is not None, "Bundled YARA rules failed to compile"
