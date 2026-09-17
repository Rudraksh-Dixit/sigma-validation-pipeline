import argparse
import json
import logging
import time
from pathlib import Path

from src.rule_parser.parser import load_sigma_rules, extract_mitre_tags
from src.log_simulator.generator import load_sample_logs, inject_log_docker_exec, inject_log_via_syslog
from src.reporter.coverage import generate_coverage_report
from src.reporter.mitre_map import map_rules_to_mitre

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger(__name__)

WAZUH_API_DEFAULT = "https://localhost:55000"
ALERT_POLL_INTERVAL = 5
ALERT_POLL_TIMEOUT = 30


def fetch_wazuh_alerts(wazuh_api_url: str, wazuh_user: str, wazuh_password: str) -> list[dict]:
    import requests

    try:
        auth_resp = requests.post(
            f"{wazuh_api_url}/security/user/authenticate",
            auth=(wazuh_user, wazuh_password),
            verify=False,
            timeout=10,
        )
        if auth_resp.status_code != 200:
            logger.error("Wazuh API auth failed: %s", auth_resp.text[:200])
            return []

        token = auth_resp.json()["data"]["token"]
        headers = {"Authorization": f"Bearer {token}"}

        response = requests.get(
            f"{wazuh_api_url}/alerts",
            headers=headers,
            params={"limit": 500, "sort": "-timestamp"},
            verify=False,
            timeout=15,
        )
        if response.status_code == 200:
            return response.json().get("data", {}).get("affected_items", [])
    except requests.RequestException as e:
        logger.error("Failed to fetch Wazuh alerts: %s", e)
    return []


def run_validation(
    rules_dir: Path,
    sample_dir: Path | None = None,
    wazuh_api_url: str = WAZUH_API_DEFAULT,
    wazuh_user: str = "wazuh-wui",
    wazuh_password: str = "wazuh-wui",
    output_dir: Path = Path("reports"),
    include_mitre: bool = False,
) -> dict:
    logger.info("Starting validation pipeline")

    sigma_rules = load_sigma_rules(rules_dir)
    if not sigma_rules:
        logger.warning("No Sigma rules found in %s", rules_dir)
        return {"rules_tested": 0, "results": []}

    sample_logs = load_sample_logs(sample_dir)
    if not sample_logs:
        logger.warning("No sample logs found")
        return {"rules_tested": len(sigma_rules), "results": []}

    rule_map = {rule.id: rule for rule in sigma_rules}

    for log in sample_logs:
        success = inject_log_via_syslog(log, host="localhost", port=514, protocol="udp")
        if not success:
            success = inject_log_docker_exec(log)
        if success:
            logger.info("Injected log from %s (technique: %s)", log.source, log.technique_id)
        else:
            logger.warning("Failed to inject log from %s", log.source)

    logger.info("Waiting %d seconds for alert processing...", ALERT_POLL_TIMEOUT)
    time.sleep(ALERT_POLL_TIMEOUT)

    alerts = fetch_wazuh_alerts(wazuh_api_url, wazuh_user, wazuh_password)
    logger.info("Fetched %d alerts from Wazuh", len(alerts))

    alert_full_text = " ".join(
        alert.get("full_log", "") + " " + str(alert.get("rule", {}).get("description", ""))
        for alert in alerts
    ).lower()

    results = []
    for rule in sigma_rules:
        expected = rule.id in {r for log in sample_logs for r in log.expected_rules}
        fired = False

        detection = rule.detection
        selection = detection.get("selection", {})
        if isinstance(selection, dict):
            for key, val in selection.items():
                search_vals = val if isinstance(val, list) else [val]
                for sv in search_vals:
                    if isinstance(sv, str):
                        search_str = sv.replace("\\", "/").replace(".*", "").lower()
                        search_str = search_str.replace("*", "").replace("|endswith", "").replace("|contains", "")
                        if len(search_str) > 3 and search_str in alert_full_text:
                            fired = True
                            break
                if fired:
                    break

        if expected:
            status = "PASS" if fired else "FAIL"
        else:
            status = "FIRED" if fired else "NO_DATA"

        results.append({
            "rule_id": rule.id,
            "title": rule.title,
            "level": rule.level,
            "expected": expected,
            "fired": fired,
            "status": status,
            "mitre_tags": extract_mitre_tags(rule),
        })

    fired_count = sum(1 for r in results if r["status"] in ("PASS", "FIRED"))
    report = {
        "rules_tested": len(sigma_rules),
        "rules_fired": fired_count,
        "rules_failed": sum(1 for r in results if r["status"] == "FAIL"),
        "results": results,
    }

    output_dir.mkdir(parents=True, exist_ok=True)

    with open(output_dir / "report.json", "w") as f:
        json.dump(report, f, indent=2, default=str)

    generate_coverage_report(report, output_dir)

    if include_mitre:
        mitre_report = map_rules_to_mitre(sigma_rules, results)
        with open(output_dir / "mitre_coverage.json", "w") as f:
            json.dump(mitre_report, f, indent=2)

    logger.info("Validation complete: %d tested, %d fired, %d failed",
                report["rules_tested"], report["rules_fired"], report["rules_failed"])

    return report


def main():
    parser = argparse.ArgumentParser(description="Sigma Rule Validation Pipeline")
    parser.add_argument("--rules", type=Path, required=True, help="Path to Sigma rules directory")
    parser.add_argument("--samples", type=Path, default=None, help="Path to sample attack logs")
    parser.add_argument("--wazuh-url", type=str, default=WAZUH_API_DEFAULT, help="Wazuh API URL")
    parser.add_argument("--wazuh-user", type=str, default="wazuh-wui")
    parser.add_argument("--wazuh-password", type=str, default="wazuh-wui")
    parser.add_argument("--output", type=Path, default=Path("reports"), help="Output directory")
    parser.add_argument("--mitre", action="store_true", help="Include MITRE ATT&CK mapping")
    args = parser.parse_args()

    import os
    wazuh_url = os.environ.get("WAZUH_API_URL", args.wazuh_url)
    wazuh_user = os.environ.get("WAZUH_API_USER", args.wazuh_user)
    wazuh_password = os.environ.get("WAZUH_API_PASSWORD", args.wazuh_password)
    output_dir = Path(os.environ.get("REPORT_OUTPUT_DIR", str(args.output)))

    run_validation(
        rules_dir=args.rules,
        sample_dir=args.samples,
        wazuh_api_url=wazuh_url,
        wazuh_user=wazuh_user,
        wazuh_password=wazuh_password,
        output_dir=output_dir,
        include_mitre=args.mitre,
    )


if __name__ == "__main__":
    main()
