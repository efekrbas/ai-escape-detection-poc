# AI Escape Detection Harness (PoC)
**Track 1: Containment - "Detection that fires but does not page"**

This repository provides an isolated, Docker-based detection harness that simulates the July 2026 Hugging Face intrusion involving autonomous AI agents during an internal cybersecurity evaluation. It reproduces the post-exploitation Python C2 loop to validate defensive telemetry and correlation rules.

**Security & Exploitation Disclaimer**
* The dataset configuration (`dataset_config.json`) contains a non-executing representation of the injection primitive observed in the incident.
* The PoC intentionally does not execute the injection against `fsspec`/Jinja2. 
* Simulated C2 beaconing is emitted locally for detection validation. No external network connection is performed.

**Detection Validation & Containment Matrix**

| Attack Step | MITRE ATT&CK | Telemetry Source | Detection Engine & Rule | Severity | Alerting Logic ("Fires vs Page") | Containment Action |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **01. Dataset injection** | `T1190` | Application log | App rule (`APP-RULE-01`) | Medium | **Fires only (No Page)** | Telemetry tagging, taint marker |
| **02. Python execution** | `T1059.006` | Process creation / `execve` | Sigma (`sysmon_huggingface_c2`) / Wazuh `100500` | High | **Fires only (No Page)** | Process lineage tracking |
| **03. Encoded command** | `T1027` | Process / audit telemetry | Sigma Process Creation | High | **Fires only (No Page)** | Correlate with step 02 |
| **04. Shell execution** | `T1059.004` | `execve` / Auditd | Wazuh `100501` | Critical | **Conditional Page** | Network isolation, drop non-root |
| **05. Repeated polling** | `T1071.001` | Process / network telemetry | Wazuh Correlation (`100502` & `100503`) | Critical | **Pages On-Call (P1)** | Automated container isolation |
| **06. Exfil simulation** | `T1041` | `stdout` / webhook simulation | Wazuh Correlation (`100504`) | Critical | **Critical Page + Kill** | Revoke tokens & terminate container |

> [!TIP]
> For the complete technical report, evasion analysis, false-positive auditing, and correlation architecture, see [ANALYSIS_AND_MATRIX.md](ANALYSIS_AND_MATRIX.md).

---

## Running the PoC Simulation

### 1. Build and Run the Worker Container
```bash
docker-compose up -d --build
```

### 2. Trigger the C2 Beaconing Simulation
```bash
docker exec -it huggingface-worker-sim python3 c2_simulation.py
```

### 3. Verify Telemetry & Rules
* **Sigma Rule:** [sigma-rules/sysmon_huggingface_c2.yml](sigma-rules/sysmon_huggingface_c2.yml)
* **Wazuh Rule:** [wazuh-rules/001-ai-escape.xml](wazuh-rules/001-ai-escape.xml)
* **Detailed Technical Deep Dive:** [ANALYSIS_AND_MATRIX.md](ANALYSIS_AND_MATRIX.md)