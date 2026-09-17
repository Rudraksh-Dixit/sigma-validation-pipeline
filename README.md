# sigma-validation-pipeline

CI/CD pipeline that automatically tests Sigma detection rules against a live Wazuh SIEM instance — simulating attack logs, validating which rules fire, and reporting coverage with MITRE ATT&CK mapping.

## Why this exists

Untested detection rules are dead weight. SOCs routinely deploy Sigma rules that never fire, fire on the wrong things, or silently break after log format changes. This pipeline makes detection-as-code real: every rule change gets validated automatically, just like application code.

Connects three existing projects into one system:
- **[sigma-soc-rules](https://github.com/Rudraksh-Dixit/sigma-soc-rules)** → source of rules to validate
- **[cloud-siem-lab](https://github.com/Rudraksh-Dixit/cloud-siem-lab)** → Wazuh instance to test against
- **[apt-hunter-ai](https://github.com/Rudraksh-Dixit/apt-hunter-ai)** → future: AI-assisted rule gap analysis

---

## Architecture

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  sigma-soc-rules │────▶│   Rule Parser    │────▶│  Wazuh (Docker)  │
│  (Sigma YAML)    │     │  (Sigma→Wazuh)   │     │  Custom rules    │
└──────────────────┘     └──────────────────┘     └────────┬─────────┘
                                                          │
                                                          ▼
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  Report Generator│◀────│    Validator     │◀────│  Log Simulator   │
│  (MD/JSON/HTML)  │     │  (Expected vs    │     │  (Attack samples │
│  + MITRE mapping │     │   Actual alerts) │     │   / Atomic Red)  │
└──────────────────┘     └──────────────────┘     └──────────────────┘
```

### Pipeline flow

1. **Pull** Sigma rules from `sigma-soc-rules`
2. **Convert** Sigma YAML → Wazuh custom rule format via `sigma-cli`
3. **Spin up** Wazuh lab via Docker Compose (reuses `cloud-siem-lab`)
4. **Inject** simulated attack logs (sample datasets / Atomic Red Team outputs)
5. **Collect** alerts from Wazuh API
6. **Compare** expected alerts vs actual alerts per rule
7. **Generate** coverage report with MITRE ATT&CK technique mapping
8. **Output** as Markdown summary + JSON artifact (GitHub Actions compatible)

---

## Project structure

```
sigma-validation-pipeline/
├── .github/
│   └── workflows/
│       └── validate-rules.yml      # CI/CD pipeline
├── src/
│   ├── log_simulator/              # Attack log generation & ingestion
│   │   ├── __init__.py
│   │   ├── generator.py            # Synthetic log generator
│   │   └── atomic_samples/         # Atomic Red Team log samples
│   ├── rule_parser/                # Sigma → Wazuh rule conversion
│   │   ├── __init__.py
│   │   └── parser.py
│   ├── validator/                  # Rule validation engine
│   │   ├── __init__.py
│   │   └── engine.py
│   └── reporter/                   # Report generation
│       ├── __init__.py
│       ├── coverage.py             # Rule coverage analysis
│       └── mitre_map.py            # MITRE ATT&CK mapping
├── config/
│   ├── wazuh/
│   │   └── ossec.conf              # Wazuh agent/manager config
│   └── mitre_mapping.json          # Sigma tag → MITRE technique map
├── tests/
│   ├── test_parser.py
│   ├── test_validator.py
│   └── test_sample_logs/           # Test fixtures
├── reports/                        # Generated validation reports
├── docker-compose.yml              # Wazuh lab (references cloud-siem-lab)
├── requirements.txt
└── pyproject.toml
```

---

## Quick start

```bash
# Clone
git clone https://github.com/Rudraksh-Dixit/sigma-validation-pipeline.git
cd sigma-validation-pipeline

# Install dependencies
pip install -r requirements.txt

# Spin up Wazuh lab
docker-compose up -d

# Run validation against local Sigma rules
python -m src.validator.engine --rules /path/to/sigma-soc-rules --output reports/

# Run with MITRE mapping
python -m src.validator.engine --rules /path/to/sigma-soc-rules --mitre --output reports/
```

---

## GitHub Actions (CI/CD)

The pipeline runs automatically on:
- **Push** to `main` (any rule or config change)
- **Pull requests** (validates before merging)
- **Schedule** (weekly cron to catch drift from log format changes)

### Example workflow output

| Rule ID | Technique | Expected | Fired | Status |
|---|---|---|---|---|
| `sysmon_susp_proc_creation` | T1059.001 | ✅ | ✅ | PASS |
| `win_mimikatz_detection` | T1003.001 | ✅ | ❌ | FAIL |
| `linux_priv_esc_sudo` | T1548.003 | ✅ | ✅ | PASS |

The `FAIL` row means the rule didn't fire when it should have — either the rule is broken, or the simulated log doesn't match the detection logic.

---

## Configuration

### `config/mitre_mapping.json`

Maps Sigma rule tags to MITRE ATT&CK technique IDs for coverage reporting:

```json
{
  "attack.t1059.001": {"technique": "T1059.001", "name": "PowerShell", "tactic": "Execution"},
  "attack.t1003.001": {"technique": "T1003.001", "name": "LSASS Memory", "tactic": "Credential Access"}
}
```

### Environment variables

| Variable | Description | Default |
|---|---|---|
| `WAZUH_API_URL` | Wazuh manager API endpoint | `https://localhost:55000` |
| `WAZUH_API_USER` | API username | `wazuh-wui` |
| `WAZUH_API_PASSWORD` | API password | `wazuh-wui` |
| `SIGMA_RULES_PATH` | Path to Sigma rules directory | `./sigma-rules` |
| `REPORT_OUTPUT_DIR` | Where to write reports | `./reports` |

---

## Tech stack

`Python` `Docker` `Wazuh` `Sigma` `GitHub Actions` `MITRE ATT&CK`

---

## Roadmap

- [ ] Core Sigma → Wazuh rule conversion
- [ ] Log simulator with Atomic Red Team samples
- [ ] Validation engine (expected vs actual)
- [ ] MITRE ATT&CK coverage report
- [ ] GitHub Actions workflow
- [ ] Markdown + JSON report output
- [ ] Historical trend tracking (rule coverage over time)
- [ ] Integration with `apt-hunter-ai` for AI-assisted gap analysis
- [ ] Web dashboard for report visualization

---

## Related projects

- [sigma-soc-rules](https://github.com/Rudraksh-Dixit/sigma-soc-rules) — Sigma detection rules for SOC use
- [cloud-siem-lab](https://github.com/Rudraksh-Dixit/cloud-siem-lab) — Cloud SIEM SOC lab with Wazuh on Docker
- [apt-hunter-ai](https://github.com/Rudraksh-Dixit/apt-hunter-ai) — AI-assisted APT hunting

## License

MIT
