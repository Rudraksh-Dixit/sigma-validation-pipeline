import json
import logging
from pathlib import Path

from src.rule_parser.parser import SigmaRule, extract_mitre_tags

logger = logging.getLogger(__name__)

MITRE_MAPPING_FILE = Path(__file__).parent.parent.parent / "config" / "mitre_mapping.json"


def load_mitre_mapping(mapping_file: Path | None = None) -> dict:
    mapping_file = mapping_file or MITRE_MAPPING_FILE
    if not mapping_file.exists():
        logger.warning("MITRE mapping file not found: %s", mapping_file)
        return {}

    with open(mapping_file) as f:
        return json.load(f)


def map_rules_to_mitre(rules: list[SigmaRule], results: list[dict]) -> dict:
    mapping = load_mitre_mapping()

    techniques: dict[str, dict] = {}
    for rule, result in zip(rules, results):
        tags = extract_mitre_tags(rule)
        for tag in tags:
            tag_lower = tag.lower()
            technique_info = mapping.get(tag_lower, {
                "technique": tag.replace("attack.", "").upper(),
                "name": "Unknown",
                "tactic": "Unknown",
            })

            technique_id = technique_info["technique"]
            if technique_id not in techniques:
                techniques[technique_id] = {
                    "technique_id": technique_id,
                    "name": technique_info["name"],
                    "tactic": technique_info["tactic"],
                    "rules": [],
                    "coverage": 0,
                }

            techniques[technique_id]["rules"].append({
                "rule_id": rule.id,
                "title": rule.title,
                "status": result["status"],
            })

    for tech in techniques.values():
        total = len(tech["rules"])
        passing = sum(1 for r in tech["rules"] if r["status"] in ("PASS", "FIRED"))
        tech["coverage"] = round(passing / total * 100, 1) if total > 0 else 0

    return {
        "total_techniques": len(techniques),
        "techniques": techniques,
    }
