import yaml
import logging
from pathlib import Path
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class SigmaRule:
    id: str
    title: str
    description: str
    level: str
    tags: list[str] = field(default_factory=list)
    logsource: dict = field(default_factory=dict)
    detection: dict = field(default_factory=dict)
    raw_yaml: str = ""


def parse_sigma_rule(rule_path: Path) -> SigmaRule | None:
    try:
        with open(rule_path) as f:
            data = yaml.safe_load(f)

        if not data:
            return None

        return SigmaRule(
            id=data.get("id", rule_path.stem),
            title=data.get("title", ""),
            description=data.get("description", ""),
            level=data.get("level", "medium"),
            tags=data.get("tags", []),
            logsource=data.get("logsource", {}),
            detection=data.get("detection", {}),
            raw_yaml=rule_path.read_text(),
        )
    except yaml.YAMLError as e:
        logger.error("Failed to parse Sigma rule %s: %s", rule_path, e)
        return None


def load_sigma_rules(rules_dir: Path) -> list[SigmaRule]:
    rules: list[SigmaRule] = []

    if not rules_dir.exists():
        logger.warning("Rules directory not found: %s", rules_dir)
        return rules

    for rule_file in sorted(rules_dir.rglob("*.yml")):
        rule = parse_sigma_rule(rule_file)
        if rule:
            rules.append(rule)

    for rule_file in sorted(rules_dir.rglob("*.yaml")):
        rule = parse_sigma_rule(rule_file)
        if rule:
            rules.append(rule)

    logger.info("Loaded %d Sigma rules from %s", len(rules), rules_dir)
    return rules


def extract_mitre_tags(rule: SigmaRule) -> list[str]:
    return [tag for tag in rule.tags if tag.startswith("attack.")]
