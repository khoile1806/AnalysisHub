"""Engine accuracy tests.

These exercise both engines on the bundled fixture corpus. The MVP target is
detection rate >= 80% on malicious samples, false-positive rate <= 5% on clean.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scanner.engines import PatternEngine, YaraEngine
from scanner.engines.base import EngineHit
from scanner.scorer import aggregate, classify

SAMPLES = Path(__file__).parent / "samples"
MALICIOUS_DIR = SAMPLES / "malicious"
CLEAN_DIR = SAMPLES / "clean"


@pytest.fixture(scope="module")
def engines():
    return [YaraEngine(), PatternEngine()]


def _scan_file(engines, path: Path) -> tuple[int, str]:
    content = path.read_bytes()
    hits: list[EngineHit] = []
    for e in engines:
        h = e.scan(path, content)
        if h:
            hits.append(h)
    score, severity, *_ = aggregate(hits)
    return score, severity


def test_pattern_engine_loads_rules():
    eng = PatternEngine()
    assert eng._rules, "Pattern rules must load from rules/patterns/webshell.json"


def test_classify_thresholds():
    assert classify(99) == "critical"
    assert classify(80) == "high"
    assert classify(50) == "medium"
    assert classify(25) == "low"
    assert classify(10) == "clean"


@pytest.mark.parametrize("sample", sorted(MALICIOUS_DIR.glob("*")))
def test_each_malicious_sample_flagged(engines, sample):
    score, severity = _scan_file(engines, sample)
    assert severity in {"medium", "high", "critical"}, (
        f"{sample.name}: expected medium+, got {severity} (score={score})"
    )


@pytest.mark.parametrize("sample", sorted(CLEAN_DIR.glob("*")))
def test_clean_samples_not_flagged_high(engines, sample):
    score, severity = _scan_file(engines, sample)
    assert severity in {"clean", "low"}, (
        f"{sample.name}: clean file flagged {severity} (score={score})"
    )


def test_corpus_detection_rate(engines):
    samples = sorted(MALICIOUS_DIR.glob("*"))
    detected = sum(1 for s in samples if _scan_file(engines, s)[1] in {"medium", "high", "critical"})
    rate = detected / len(samples)
    assert rate >= 0.8, f"Detection rate {rate:.0%} below 80%"


def test_corpus_false_positive_rate(engines):
    samples = sorted(CLEAN_DIR.glob("*"))
    flagged = sum(1 for s in samples if _scan_file(engines, s)[1] in {"medium", "high", "critical"})
    fp_rate = flagged / len(samples)
    assert fp_rate <= 0.05, f"FP rate {fp_rate:.0%} above 5%"
