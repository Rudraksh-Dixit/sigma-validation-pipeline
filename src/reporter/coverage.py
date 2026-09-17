import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def generate_coverage_report(report: dict, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    total = report["rules_tested"]
    fired = report["rules_fired"]
    failed = report["rules_failed"]
    pass_rate = (fired / total * 100) if total > 0 else 0

    md_lines = [
        "# Sigma Rule Validation Report\n",
        f"**Rules tested:** {total}  ",
        f"**Rules fired:** {fired}  ",
        f"**Rules failed:** {failed}  ",
        f"**Pass rate:** {pass_rate:.1f}%\n",
        "## Results\n",
        "| Rule ID | Title | Level | Expected | Fired | Status |",
        "|---|---|---|---|---|---|",
    ]

    for result in report.get("results", []):
        expected = "Yes" if result["expected"] else "No"
        fired = "Yes" if result["fired"] else "No"
        md_lines.append(
            f"| `{result['rule_id']}` | {result['title']} | {result['level']} "
            f"| {expected} | {fired} | {result['status']} |"
        )

    summary_path = output_dir / "summary.md"
    with open(summary_path, "w") as f:
        f.write("\n".join(md_lines) + "\n")

    logger.info("Coverage report written to %s", summary_path)
