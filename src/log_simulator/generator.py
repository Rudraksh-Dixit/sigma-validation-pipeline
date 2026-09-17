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


def inject_log_via_syslog(log: SimulatedLog, host: str = "localhost", port: int = 514, protocol: str = "udp") -> bool:
    import socket

    try:
        message = log.raw
        if not message.endswith("\n"):
            message += "\n"
        encoded = message.encode("utf-8")

        if protocol == "udp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            sock.sendto(encoded, (host, port))
            sock.close()
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            sock.sendall(encoded)
            sock.close()

        logger.info("Injected log via syslog %s:%d (%s) - technique: %s", host, port, protocol, log.technique_id)
        return True
    except OSError as e:
        logger.error("Failed to inject log via syslog: %s", e)
        return False


def inject_log_via_api(wazuh_api_url: str, log: SimulatedLog, api_user: str = "wazuh-wui", api_password: str = "wazuh-wui") -> bool:
    import requests

    try:
        auth_resp = requests.post(
            f"{wazuh_api_url}/security/user/authenticate",
            auth=(api_user, api_password),
            verify=False,
            timeout=10,
        )
        if auth_resp.status_code != 200:
            logger.error("Failed to authenticate with Wazuh API: %s", auth_resp.text[:100])
            return False

        token = auth_resp.json()["data"]["token"]
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        active_responses = requests.get(
            f"{wazuh_api_url}/active-response",
            headers=headers,
            params={"agent_id": "000"},
            verify=False,
            timeout=10,
        )

        command_payload = {
            "command": f"echo '{log.raw}' >> /var/ossec/logs/active-responses.log",
            "custom": True,
            "arguments": [log.raw],
        }

        response = requests.post(
            f"{wazuh_api_url}/active-response",
            json=command_payload,
            headers=headers,
            verify=False,
            timeout=10,
        )
        return response.status_code == 200
    except requests.RequestException as e:
        logger.error("Failed to inject log via API: %s", e)
        return False


def inject_log_docker_exec(log: SimulatedLog, container_name: str = "single-node-wazuh.manager-1") -> bool:
    import subprocess

    try:
        escaped_raw = log.raw.replace("'", "'\\''")
        cmd = [
            "docker", "exec", container_name,
            "bash", "-c",
            f"echo '{escaped_raw}' >> /var/ossec/logs/active-responses.log",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            logger.info("Injected log via docker exec - technique: %s", log.technique_id)
            return True
        else:
            logger.error("docker exec failed: %s", result.stderr[:100])
            return False
    except Exception as e:
        logger.error("Failed to inject log via docker exec: %s", e)
        return False
