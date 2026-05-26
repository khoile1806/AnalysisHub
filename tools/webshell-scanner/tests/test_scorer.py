"""Unit tests for the scoring layer."""

from __future__ import annotations

from scanner.engines.base import EngineHit
from scanner.scorer import aggregate, classify


def test_classify_boundaries():
    assert classify(95) == "critical"
    assert classify(94) == "high"
    assert classify(70) == "high"
    assert classify(69) == "medium"
    assert classify(40) == "medium"
    assert classify(39) == "low"
    assert classify(20) == "low"
    assert classify(19) == "clean"
    assert classify(0) == "clean"


def test_classify_extreme_values():
    assert classify(-5) == "clean"
    assert classify(150) == "critical"


def test_aggregate_empty_returns_clean():
    score, severity, reasons, engines, snippet = aggregate([])
    assert score == 0
    assert severity == "clean"
    assert reasons == []
    assert engines == []
    assert snippet is None


def test_aggregate_single_hit_keeps_score():
    hit = EngineHit(engine="yara", score=80, reasons=["yara:rule_a"])
    score, severity, reasons, engines, _ = aggregate([hit])
    assert score == 80
    assert severity == "high"
    assert reasons == ["yara:rule_a"]
    assert engines == ["yara"]


def test_aggregate_multiple_hits_apply_corroboration_bonus():
    """Each additional engine that fires adds 5 points (capped at 100)."""
    h1 = EngineHit(engine="yara", score=80, reasons=["yara:a"])
    h2 = EngineHit(engine="pattern", score=60, reasons=["pattern:b"])
    score, severity, reasons, engines, _ = aggregate([h1, h2])
    assert score == 85
    assert severity == "high"
    assert engines == ["yara", "pattern"]
    assert reasons == ["yara:a", "pattern:b"]


def test_aggregate_score_capped_at_100():
    h1 = EngineHit(engine="a", score=98, reasons=[])
    h2 = EngineHit(engine="b", score=50, reasons=[])
    h3 = EngineHit(engine="c", score=30, reasons=[])
    score, _, _, _, _ = aggregate([h1, h2, h3])
    assert score == 100


def test_aggregate_picks_first_snippet():
    h1 = EngineHit(engine="yara", score=80, reasons=["yara:a"], snippet=None)
    h2 = EngineHit(engine="pattern", score=60, reasons=["pattern:b"], snippet="hello world")
    h3 = EngineHit(engine="entropy", score=40, reasons=["entropy:c"], snippet="other")
    _, _, _, _, snippet = aggregate([h1, h2, h3])
    assert snippet == "hello world"


def test_aggregate_dedupes_engine_names():
    h1 = EngineHit(engine="pattern", score=40, reasons=["pattern:a"])
    h2 = EngineHit(engine="pattern", score=50, reasons=["pattern:b"])
    _, _, reasons, engines, _ = aggregate([h1, h2])
    assert engines == ["pattern"]
    assert reasons == ["pattern:a", "pattern:b"]


def test_aggregate_critical_threshold_reachable_via_corroboration():
    h1 = EngineHit(engine="yara", score=90, reasons=["yara:r1"])
    h2 = EngineHit(engine="pattern", score=70, reasons=["pattern:r2"])
    score, severity, _, _, _ = aggregate([h1, h2])
    assert score == 95
    assert severity == "critical"
