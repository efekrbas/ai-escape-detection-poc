# AI Escape Detection Harness (PoC)
**Track 1: Containment - "Detection that fires but does not page"**

This repository provides an isolated, Docker-based detection harness that simulates the July 2026 Hugging Face intrusion involving autonomous AI agents during an internal cybersecurity evaluation. It reproduces the post-exploitation Python C2 loop to validate defensive telemetry and correlation rules.

**Security & Exploitation Disclaimer**
* The dataset configuration (`dataset_config.json`) contains a non-executing representation of the injection primitive observed in the incident.
* The PoC intentionally does not execute the injection against `fsspec`/Jinja2. 
* Simulated C2 beaconing is emitted locally for detection validation. No external network connection is performed.

**Detection Validation Matrix**

| Attack Step | Telemetry Source | Detection Engine | Expected Severity |
| :--- | :--- | :--- | :--- |
| Dataset injection | Application log | App rule | Medium |
| Python execution | Process creation | Sigma | High |
| Encoded command | Process/audit telemetry | Wazuh | High |
| Shell execution | `execve` | Wazuh | Critical |
| Repeated polling | Process/network telemetry | Correlation | Critical |
| Exfil simulation | `stdout` / webhook simulation | Correlation | Critical |