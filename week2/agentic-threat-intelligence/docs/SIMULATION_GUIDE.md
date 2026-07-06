# Real Attack Simulation Guide

This guide explains how to run realistic attack simulations against the MedFlow threat intelligence system.

## Overview

The simulation system tests the complete threat intelligence workflow:
1. **Event Ingestion** - Raw security events from various sources
2. **Threat Analysis** - ATT&CK mapping, IOC enrichment, campaign correlation
3. **Response Actions** - Automated or manual response recommendations

## Prerequisites

1. **Start the Flask API**
   ```bash
   cd /home/rania/Documents/MedFlow_AI_Cybersecurity/week2/agentic-threat-intelligence
   source .venv/bin/activate
   python app.py
   ```

2. **Verify API is running**
   ```bash
   curl http://127.0.0.1:5000/
   # Should return: {"status": "running"}
   ```

## Available Simulation Scenarios

### 1. Credential Dumping Incident (`credential_dumping_incident.json`)
**Attack Chain:** Macro-enabled document → PowerShell → C2 beacon → Credential dumping → Lateral movement

**Expected Detection:**
- Techniques: T1566 (Phishing), T1059.001 (PowerShell), T1071 (C2), T1003 (Credential Dumping), T1021.002 (SMB)
- IOCs: Malicious IP (194.61.55.18), suspicious PowerShell commands
- Campaign: Multi-stage attack with lateral movement
- Actions: Block malicious IP, isolate compromised host

### 2. LOLBIN Test (`lolbin_test.json`)
**Attack Chain:** Living-off-the-land binaries abuse

**Expected Detection:**
- Techniques: T1218 (Signed Binary Proxy Execution)
- IOCs: Suspicious LOLBIN usage
- Campaign: Isolated suspicious activity
- Actions: Notify analyst (low confidence)

### 3. Ransomware Simulation (`ransomware_simulation.json`)
**Attack Chain:** PowerShell script → Malware download → File encryption → Lateral spread

**Expected Detection:**
- Techniques: T1059.001 (PowerShell), T1105 (Ingress Tool Transfer), T1486 (Data Encrypted)
- IOCs: Malicious IP (185.233.100.44), suspicious executable
- Campaign: Ransomware attack in progress
- Actions: Block malicious IP, isolate host, quarantine file

### 4. Sample Events (`sample_events.json`)
**Attack Chain:** Basic suspicious activity

**Expected Detection:**
- Techniques: Basic ATT&CK mapping
- IOCs: Suspicious PowerShell, C2 beacon
- Campaign: Isolated event
- Actions: Notify analyst

## Running Simulations

### Run All Scenarios
```bash
source .venv/bin/activate
python simulation_runner.py --all
```

### Run Specific Scenario
```bash
python simulation_runner.py --scenario credential_dumping_incident.json
```

### Custom API URL
```bash
python simulation_runner.py --all --api-url http://your-server:5000
```

## Expected Output

The simulation runner will output:

```
============================================================
Running scenario: credential_dumping_incident
Events: 10
============================================================
Loaded 10 events from ./data/sample_events/credential_dumping_incident.json
✓ Scenario completed in 3.45s
Campaign: credential_dumping_lateral_movement (ID: camp-2024-001)
Techniques detected: 5
  - T1566: Spearphishing Attachment (confidence: 0.92)
  - T1059.001: PowerShell (confidence: 0.95)
  - T1071: Application Layer Protocol (confidence: 0.88)
  - T1003: OS Credential Dumping (confidence: 0.94)
  - T1021.002: SMB/Windows Admin Shares (confidence: 0.89)
IOCs found: 3
  - ip: 194.61.55.18
  - ip: 10.0.8.41
  - domain: DC-FILESRV01
Actions taken: 3
  - block_ip -> 194.61.55.18: pending_approval
    (DRY RUN - no real action executed)
  - isolate_host -> FIN-LAPTOP-12: pending_approval
    (DRY RUN - no real action executed)
  - notify_analyst -> : pending_approval
    (DRY RUN - no real action executed)
============================================================
SIMULATION SUMMARY
============================================================
Total scenarios: 4
Successful: 4
Failed: 0
Average duration: 3.12s
============================================================
```

## Simulation Modes

### Dry-Run Mode (Default)
- Actions are logged but not executed
- Safe for testing without real infrastructure
- Set via `DRY_RUN=true` in `.env`

### Live Mode
- Real API calls to security tools
- Requires configured connectors
- Set via `DRY_RUN=false` in `.env`
- **CAUTION:** Only use with test infrastructure

### Auto-Response Mode
- Actions execute automatically based on confidence
- Set via `AUTO_RESPONSE_ENABLED=true` in `.env`
- **CAUTION:** Requires thorough testing first

## Creating Custom Scenarios

Create a new JSON file in `data/sample_events/`:

```json
[
  {
    "source": "sysmon",
    "event_id": 1,
    "timestamp": "2026-07-03T10:00:00Z",
    "host": "WORKSTATION-01",
    "process": "powershell.exe",
    "command_line": "suspicious command",
    "user": "user",
    "src_ip": null,
    "dest_ip": null,
    "raw": {
      "EventID": 1,
      "UtcTime": "2026-07-03T10:00:00Z",
      "Computer": "WORKSTATION-01",
      "Image": "powershell.exe",
      "CommandLine": "suspicious command",
      "User": "user"
    }
  }
]
```

Run your custom scenario:
```bash
python simulation_runner.py --scenario your_scenario.json
```

## Event Sources Supported

- **Sysmon** - Windows system monitoring
- **Wazuh** - EDR/SIEM alerts
- **Suricata** - Network IDS
- **Custom** - Any JSON with required fields

## Key Metrics to Monitor

1. **Detection Accuracy**
   - Are ATT&CK techniques correctly mapped?
   - Are IOCs properly extracted?

2. **Campaign Correlation**
   - Are related events grouped correctly?
   - Is the attack timeline accurate?

3. **Response Quality**
   - Are recommended actions appropriate?
   - Are confidence scores reasonable?

4. **Performance**
   - Investigation duration
   - API response times

## Troubleshooting

### API Not Responding
```bash
# Check if app is running
curl http://127.0.0.1:5000/

# Restart app
python app.py
```

### Scenario File Not Found
```bash
# List available scenarios
ls data/sample_events/

# Check file path is correct
```

### ChromaDB Errors
```bash
# Re-ingest ATT&CK data
python -m rag.ingest_attack
```

### Connector Errors
```bash
# Test connectors in dry-run
python test_connectors.py

# Check credentials in .env
```

## Next Steps

1. **Run all scenarios** in dry-run mode
2. **Review detection accuracy** and adjust prompts if needed
3. **Configure real connectors** for your security tools
4. **Test in live mode** with human approval
5. **Enable auto-response** for low-risk actions
6. **Monitor and iterate** based on real-world performance
