import pytest
from pathlib import Path
from src.rule_parser.parser import parse_sigma_rule, extract_mitre_tags, SigmaRule


def test_parse_sigma_rule_basic(tmp_path: Path):
    rule_content = """
title: Test Rule
id: test-123
description: A test Sigma rule
level: high
tags:
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: powershell.exe
  condition: selection
"""
    rule_file = tmp_path / "test_rule.yml"
    rule_file.write_text(rule_content)

    rule = parse_sigma_rule(rule_file)
    assert rule is not None
    assert rule.id == "test-123"
    assert rule.title == "Test Rule"
    assert rule.level == "high"
    assert "attack.t1059.001" in rule.tags


def test_parse_invalid_yaml(tmp_path: Path):
    rule_file = tmp_path / "bad.yml"
    rule_file.write_text(":: invalid yaml {{{")

    rule = parse_sigma_rule(rule_file)
    assert rule is None


def test_extract_mitre_tags():
    rule = SigmaRule(
        id="test",
        title="Test",
        description="",
        level="medium",
        tags=["attack.t1059.001", "detection.threat_hunting", "attack.t1003.001"],
    )

    mitre_tags = extract_mitre_tags(rule)
    assert len(mitre_tags) == 2
    assert "attack.t1059.001" in mitre_tags
    assert "attack.t1003.001" in mitre_tags
