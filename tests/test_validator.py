import pytest
from pathlib import Path
from src.reporter.coverage import generate_coverage_report
from src.reporter.mitre_map import map_rules_to_mitre
from src.rule_parser.parser import SigmaRule


def test_generate_coverage_report(tmp_path: Path):
    report = {
        "rules_tested": 3,
        "rules_fired": 2,
        "rules_failed": 1,
        "results": [
            {"rule_id": "r1", "title": "Rule 1", "level": "high", "expected": True, "fired": True, "status": "PASS"},
            {"rule_id": "r2", "title": "Rule 2", "level": "medium", "expected": True, "fired": False, "status": "FAIL"},
            {"rule_id": "r3", "title": "Rule 3", "level": "low", "expected": False, "fired": True, "status": "FIRED"},
        ],
    }

    generate_coverage_report(report, tmp_path)

    summary_path = tmp_path / "summary.md"
    assert summary_path.exists()

    content = summary_path.read_text()
    assert "Rules tested: 3" in content
    assert "PASS" in content
    assert "FAIL" in content


def test_map_rules_to_mitre():
    rules = [
        SigmaRule(id="r1", title="PS Exec", description="", level="high",
                  tags=["attack.t1059.001"]),
        SigmaRule(id="r2", title="Mimikatz", description="", level="critical",
                  tags=["attack.t1003.001"]),
    ]
    results = [
        {"rule_id": "r1", "title": "PS Exec", "status": "PASS"},
        {"rule_id": "r2", "title": "Mimikatz", "status": "FAIL"},
    ]

    mitre_report = map_rules_to_mitre(rules, results)
    assert mitre_report["total_techniques"] >= 1
