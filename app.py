import json
import threading
from pathlib import Path
from datetime import datetime

from flask import Flask, render_template, jsonify, request

from src.rule_parser.parser import load_sigma_rules, extract_mitre_tags
from src.validator.engine import run_validation
from src.reporter.mitre_map import map_rules_to_mitre

app = Flask(__name__)
REPORTS_DIR = Path(__file__).parent / "reports"
RULES_DIR_DEFAULT = Path(__file__).parent.parent / "sigma-rules"

run_status = {"running": False, "last_result": None, "history": []}


def load_latest_report():
    report_path = REPORTS_DIR / "report.json"
    if report_path.exists():
        with open(report_path) as f:
            return json.load(f)
    return None


def load_mitre_report():
    mitre_path = REPORTS_DIR / "mitre_coverage.json"
    if mitre_path.exists():
        with open(mitre_path) as f:
            return json.load(f)
    return None


@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/report")
def api_report():
    report = load_latest_report()
    if not report:
        return jsonify({"error": "No report found. Run a validation first."}), 404
    return jsonify(report)


@app.route("/api/mitre")
def api_mitre():
    mitre = load_mitre_report()
    if not mitre:
        return jsonify({"error": "No MITRE coverage data. Run validation with --mitre."}), 404
    return jsonify(mitre)


@app.route("/api/run", methods=["POST"])
def api_run():
    if run_status["running"]:
        return jsonify({"status": "already_running"}), 409

    config = request.get_json(silent=True) or {}
    rules_dir = Path(config.get("rules_dir", str(RULES_DIR_DEFAULT)))
    wazuh_url = config.get("wazuh_url", "https://localhost:55000")
    wazuh_user = config.get("wazuh_user", "wazuh-wui")
    wazuh_password = config.get("wazuh_password", "wazuh-wui")

    run_status["running"] = True

    def _run():
        try:
            result = run_validation(
                rules_dir=rules_dir,
                wazuh_api_url=wazuh_url,
                wazuh_user=wazuh_user,
                wazuh_password=wazuh_password,
                output_dir=REPORTS_DIR,
                include_mitre=True,
            )
            run_status["last_result"] = result
            run_status["history"].append({
                "timestamp": datetime.now().isoformat(),
                "rules_tested": result["rules_tested"],
                "rules_fired": result["rules_fired"],
                "rules_failed": result["rules_failed"],
            })
            if len(run_status["history"]) > 50:
                run_status["history"] = run_status["history"][-50:]
        finally:
            run_status["running"] = False

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()

    return jsonify({"status": "started"})


@app.route("/api/status")
def api_status():
    return jsonify({
        "running": run_status["running"],
        "history": run_status["history"][-10:],
    })


@app.route("/api/rules")
def api_rules():
    rules_dir_str = request.args.get("dir", str(RULES_DIR_DEFAULT))
    rules = load_sigma_rules(Path(rules_dir_str))
    return jsonify([
        {
            "id": r.id,
            "title": r.title,
            "level": r.level,
            "tags": r.tags,
            "mitre_tags": extract_mitre_tags(r),
            "logsource": r.logsource,
        }
        for r in rules
    ])


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
