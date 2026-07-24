"""Unit tests for the YaraEngine — severity meta -> score mapping,
graceful degradation when YARA is unavailable or rules folder is empty."""

from __future__ import annotations

from pathlib import Path

import pytest

yara = pytest.importorskip("yara")

from scanner.engines import yara_engine as yara_engine_mod
from scanner.engines.yara_engine import YaraEngine


@pytest.fixture
def rules_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Relocate the engine's bundled-rules root to a temp directory.

    The engine always loads its built-in rules and treats ``custom_rules_path``
    as an *addition*, so a test cannot observe an empty or deliberately broken
    ruleset by passing a path — it has to move the root itself.
    """
    monkeypatch.setattr(yara_engine_mod, "rules_dir", lambda: tmp_path)
    monkeypatch.setattr(yara_engine_mod, "scenarios_dir", lambda: tmp_path / "yara" / "scenarios")
    return tmp_path


def _write_rules(rules_dir: Path, rules: dict[str, str]) -> None:
    (rules_dir / "yara").mkdir(parents=True, exist_ok=True)
    for name, body in rules.items():
        (rules_dir / "yara" / f"{name}.yar").write_text(body, encoding="utf-8")


def test_empty_rules_dir_disables_engine(rules_root: Path):
    (rules_root / "yara").mkdir()
    eng = YaraEngine()
    assert eng._rules is None
    assert eng.scan(rules_root / "any.php", b"<?php ?>") is None


def test_missing_rules_dir_disables_engine(rules_root: Path):
    eng = YaraEngine()
    assert eng._rules is None


def test_severity_critical_maps_to_95(rules_root: Path):
    _write_rules(rules_root, {
        "crit": '''rule R_crit {
            meta:
                severity = "critical"
            strings:
                $a = "MARK_CRIT"
            condition:
                $a
        }'''
    })
    eng = YaraEngine()
    hit = eng.scan(rules_root / "x.php", b"... MARK_CRIT ...")
    assert hit is not None
    assert hit.score == 95
    assert hit.reasons == ["yara:R_crit"]


def test_severity_high_and_medium_and_low(rules_root: Path):
    _write_rules(rules_root, {
        "h": 'rule R_h { meta: severity = "high" strings: $a = "AAA" condition: $a }',
        "m": 'rule R_m { meta: severity = "medium" strings: $a = "BBB" condition: $a }',
        "l": 'rule R_l { meta: severity = "low" strings: $a = "CCC" condition: $a }',
    })
    eng = YaraEngine()
    assert eng.scan(rules_root / "x.php", b"AAA").score == 75
    assert eng.scan(rules_root / "x.php", b"BBB").score == 55
    assert eng.scan(rules_root / "x.php", b"CCC").score == 35


def test_missing_severity_meta_defaults_to_medium(rules_root: Path):
    """When meta.severity is absent, the engine falls back to 'medium' (55).
    This anchors the contract — if the default ever changes, the test must move
    with it intentionally."""
    _write_rules(rules_root, {
        "nometa": 'rule R_nometa { strings: $a = "MISSING" condition: $a }',
    })
    eng = YaraEngine()
    hit = eng.scan(rules_root / "x.php", b"data MISSING data")
    assert hit is not None
    assert hit.score == 55


def test_unknown_severity_meta_defaults_to_medium(rules_root: Path):
    _write_rules(rules_root, {
        "weird": 'rule R_weird { meta: severity = "spicy" strings: $a = "ZZZ" condition: $a }',
    })
    eng = YaraEngine()
    hit = eng.scan(rules_root / "x.php", b"foo ZZZ bar")
    assert hit is not None
    assert hit.score == 50  # _SEVERITY_SCORE.get fallback for unknown labels


def test_multiple_matches_keeps_highest_severity(rules_root: Path):
    _write_rules(rules_root, {
        "low": 'rule R_low { meta: severity = "low" strings: $a = "LO" condition: $a }',
        "crit": 'rule R_crit { meta: severity = "critical" strings: $a = "HI" condition: $a }',
    })
    eng = YaraEngine()
    hit = eng.scan(rules_root / "x.php", b"LO and HI present")
    assert hit is not None
    assert hit.score == 95
    assert "yara:R_crit" in hit.reasons
    assert "yara:R_low" in hit.reasons


def test_no_match_returns_none(rules_root: Path):
    _write_rules(rules_root, {
        "x": 'rule R { meta: severity = "high" strings: $a = "NEEDLE" condition: $a }',
    })
    eng = YaraEngine()
    assert eng.scan(rules_root / "x.php", b"haystack content") is None


def test_invalid_rule_disables_engine(rules_root: Path):
    """Bad syntax in any rule file fails compile() — entire engine should
    fall back to disabled rather than raising."""
    _write_rules(rules_root, {
        "broken": "rule busted { condition: this_is_not_valid_yara }",
    })
    eng = YaraEngine()
    assert eng._rules is None
    assert eng.scan(rules_root / "x.php", b"anything") is None


def test_custom_rules_are_added_on_top_of_bundled(rules_root: Path, tmp_path: Path):
    """custom_rules_path supplements the built-in set rather than replacing it —
    both must be able to fire."""
    _write_rules(rules_root, {
        "builtin": 'rule R_builtin { meta: severity = "low" strings: $a = "BUILTIN" condition: $a }',
    })
    custom = tmp_path / "custom"
    custom.mkdir()
    (custom / "extra.yar").write_text(
        'rule R_custom { meta: severity = "critical" strings: $a = "CUSTOM" condition: $a }',
        encoding="utf-8",
    )
    eng = YaraEngine(custom_rules_path=custom)
    assert eng.scan(rules_root / "x.php", b"BUILTIN") is not None
    hit = eng.scan(rules_root / "x.php", b"CUSTOM")
    assert hit is not None and hit.score == 95


def test_default_engine_loads_bundled_rules():
    """Smoke test: the engine constructed with no path picks up rules/yara/*.yar
    bundled with the package, and at least one of them compiles."""
    eng = YaraEngine()
    assert eng._rules is not None, "Bundled YARA rules failed to compile"
