import json
import logging
from pathlib import Path
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

SAMPLE_LOGS_DIR = Path(__file__).parent / "atomic_samples"


@dataclass
class SimulatedLog:
    raw: str
    source: str
    technique_id: str = ""
    expected_rules: list[str] = field(default_factory=list)


def load_sample_logs(sample_dir: Path | None = None) -> list[SimulatedLog]:
    sample_dir = sample_dir or SAMPLE_LOGS_DIR
    logs: list[SimulatedLog] = []

    if not sample_dir.exists():
        logger.warning("Sample log directory not found: %s", sample_dir)
        return logs

    for log_file in sorted(sample_dir.glob("*.json")):
        with open(log_file) as f:
            data = json.load(f)

        if isinstance(data, list):
            for entry in data:
                logs.append(SimulatedLog(
                    raw=entry.get("raw", ""),
                    source=entry.get("source", log_file.stem),
                    technique_id=entry.get("technique_id", ""),
                    expected_rules=entry.get("expected_rules", []),
                ))
        else:
            logs.append(SimulatedLog(
                raw=data.get("raw", ""),
                source=data.get("source", log_file.stem),
                technique_id=data.get("technique_id", ""),
                expected_rules=data.get("expected_rules", []),
            ))

    logger.info("Loaded %d sample logs from %s", len(logs), sample_dir)
    return logs


def inject_log(wazuh_api_url: str, log: SimulatedLog) -> bool:
    import requests

    try:
        response = requests.post(
            f"{wazuh_api_url}/logs",
            json={"log": log.raw, "source": log.source},
            verify=False,
            timeout=10,
        )
        return response.status_code == 200
    except requests.RequestException as e:
        logger.error("Failed to inject log: %s", e)
        return False
