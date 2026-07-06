# Action-Response Mechanism - Complete Technical Guide

## Architecture Overview

The action-response mechanism is a multi-layered system that automatically generates, evaluates, and executes security response actions based on threat intelligence analysis. It operates at the final stage of the investigation workflow.

## System Components

### 1. **Response Agent** (`agents/response_agent.py`)

**Purpose**: Orchestrates the entire action-response workflow.

**Key Functions**:
- `run(campaign, techniques, iocs)`: Main entry point that coordinates action generation
- `_execute(action, decision)`: Executes approved actions via connectors
- `_generate_fallback_actions(iocs, campaign)`: Fallback mechanism when LLM fails

**Workflow**:
1. Receives campaign intelligence, ATT&CK techniques, and IOCs
2. Sends data to LLM with system prompt for action generation
3. Parses LLM response into structured action proposals
4. Evaluates each action against security policy
5. Executes approved actions via appropriate connectors
6. Logs all actions to audit trail

### 2. **Policy Engine** (`actions/policy.py`)

**Purpose**: Enforces security policies and prevents unauthorized actions.

**Key Functions**:
- `evaluate(action: ProposedAction) -> str`: Returns execution decision
- `_rate_limit_exceeded(target: str) -> bool`: Prevents action spam

**Policy Rules**:
- **Kill Switch**: `AUTO_RESPONSE_ENABLED=false` → all actions require approval
- **Protected Targets**: Critical systems (domain controllers, admin accounts) → denied
- **Severity Threshold**: HIGH severity → always requires approval
- **Confidence Threshold**: Below 0.70 → requires approval
- **Rate Limiting**: Max 3 actions per target per hour

**Decision Outcomes**:
- `auto_execute`: Action runs immediately
- `pending_approval`: Action logged for human review
- `denied`: Action blocked (policy violation)

### 3. **Action Connectors** (`actions/connectors.py`)

**Purpose**: Interface with external security tools to execute actions.

**Connector Functions**:

#### `block_ip(ip_address: str) -> str`
- **Purpose**: Block IP addresses/domains via firewall API
- **Supported Firewalls**: Generic API, Palo Alto, Fortinet, AWS Security Groups
- **Configuration**: `FIREWALL_API_URL`, `FIREWALL_API_TOKEN`
- **Dry Run**: Logs intended action without API call

#### `isolate_host(hostname: str) -> str`
- **Purpose**: Isolate compromised endpoints via Wazuh Active Response
- **Configuration**: `WAZUH_API_URL`, `WAZUH_USERNAME`, `WAZUH_PASSWORD`
- **Process**: 
  1. Query Wazuh API for agent ID by hostname
  2. Send `isolate-host` active response command
  3. Return execution status

#### `disable_account(username: str) -> str`
- **Purpose**: Disable compromised user accounts via IAM
- **Supported Platforms**: Azure AD/Entra ID, Okta
- **Configuration**: 
  - Azure: `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`
  - Okta: `OKTA_DOMAIN`, `OKTA_API_TOKEN`
- **Process**:
  1. Authenticate with OAuth2 (Azure) or API token (Okta)
  2. Query user by username/email
  3. Disable account via API

#### `kill_process(process_ref: str) -> str`
- **Purpose**: Terminate malicious processes via Wazuh Active Response
- **Configuration**: `WAZUH_API_URL`, `WAZUH_USERNAME`, `WAZUH_PASSWORD`
- **Process**: Send `kill-process` command with PID or process name

#### `quarantine_file(file_hash: str) -> str`
- **Purpose**: Quarantine malicious files via EDR
- **Supported Platforms**: CrowdStrike, SentinelOne, Wazuh
- **Configuration**:
  - CrowdStrike: `CROWDSTRIKE_API_URL`, `CROWDSTRIKE_CLIENT_ID`, `CROWDSTRIKE_CLIENT_SECRET`
  - SentinelOne: `SENTINELONE_API_URL`, `SENTINELONE_API_TOKEN`
  - Wazuh: `WAZUH_API_URL` (requires custom active response script)
- **Process**: Send quarantine command with file hash (MD5/SHA1/SHA256)

#### `notify_analyst(message: str) -> str`
- **Purpose**: Send alerts to security team via Slack
- **Configuration**: `SLACK_WEBHOOK_URL`
- **Process**: POST message to Slack webhook URL

**Helper Functions**:
- `_log_action(action_type, target, detail)`: Logs actions with dry-run prefix
- `_post_with_retry(url, **kwargs)`: HTTP client with retry logic

### 4. **Action Models** (`actions/action_models.py`)

**Purpose**: Define structured data models for actions.

**Data Models**:

#### `ActionType` (Enum)
- `BLOCK_IP`: Block IP address/domain
- `ISOLATE_HOST`: Isolate endpoint
- `DISABLE_ACCOUNT`: Disable user account
- `KILL_PROCESS`: Terminate process
- `QUARANTINE_FILE`: Quarantine file
- `NOTIFY_ANALYST`: Send notification

#### `ActionSeverity` (Enum)
- `LOW`: Minimal impact
- `MEDIUM`: Moderate impact
- `HIGH`: High impact/disruptive

#### `ActionStatus` (Enum)
- `EXECUTED`: Action completed successfully
- `PENDING_APPROVAL`: Awaiting human review
- `DENIED`: Blocked by policy
- `FAILED`: Execution error

#### `ProposedAction` (Pydantic Model)
```python
{
    "action_type": ActionType,
    "target": str,           # IP, hostname, username, process, hash
    "severity": ActionSeverity,
    "confidence": float,     # 0.0-1.0
    "rationale": str,        # 5-500 chars
    "technique_id": Optional[str]  # ATT&CK technique ID
}
```

#### `ActionResult` (Pydantic Model)
```python
{
    "action": ProposedAction,
    "status": ActionStatus,
    "detail": str,           # Execution details
    "dry_run": bool          # Whether dry-run mode
}
```

### 5. **Audit Logging** (`actions/audit_log.py`)

**Purpose**: Maintain immutable audit trail of all actions.

**Key Functions**:
- `record(result, campaign_id)`: Log action to audit file
- Audit log location: `actions/audit_log.json`

**Log Entry Structure**:
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

### 6. **Configuration** (`config.py`)

**Purpose**: Centralize configuration and environment variables.

**Key Settings**:
- `AUTO_RESPONSE_ENABLED`: Global kill switch for auto-execution
- `DRY_RUN`: Execute in simulation mode (no real API calls)
- `API_TIMEOUT`: HTTP request timeout (default: 10s)
- `API_RETRY`: HTTP retry attempts (default: 3)

**Connector Configuration**:
- `FIREWALL_API_URL`, `FIREWALL_API_TOKEN`
- `WAZUH_API_URL`, `WAZUH_USERNAME`, `WAZUH_PASSWORD`
- `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`
- `OKTA_DOMAIN`, `OKTA_API_TOKEN`
- `CROWDSTRIKE_API_URL`, `CROWDSTRIKE_CLIENT_ID`, `CROWDSTRIKE_CLIENT_SECRET`
- `SENTINELONE_API_URL`, `SENTINELONE_API_TOKEN`
- `SLACK_WEBHOOK_URL`

## Complete Workflow

### Step 1: Investigation Completion
```
Investigation Workflow → Response Agent
```
The investigation workflow completes threat analysis and passes results to the Response Agent.

### Step 2: Action Generation
```
Response Agent.run(campaign, techniques, iocs)
  ↓
LLM Call with System Prompt
  ↓
JSON Response: [ProposedAction, ...]
```
The LLM generates 2-3 appropriate actions based on the threat intelligence.

### Step 3: Policy Evaluation
```
For each ProposedAction:
  ↓
policy.evaluate(action)
  ↓
Decision: auto_execute | pending_approval | denied
```
Each action is evaluated against security policies.

### Step 4: Action Execution
```
If auto_execute:
  ↓
ACTION_DISPATCH[action_type](target)
  ↓
Connector Function → External API
  ↓
ActionResult returned
```
Approved actions are executed via appropriate connectors.

### Step 5: Audit Logging
```
audit_log.record(result, campaign_id)
  ↓
actions/audit_log.json
```
All actions are logged to the audit trail.

## LLM Integration

### System Prompt
The response agent uses a sophisticated system prompt that:
- Defines available action types with descriptions
- Sets confidence thresholds for different action categories
- Requires 2-3 actions per incident
- Demands exact target values from IOCs
- Specifies severity and rationale requirements

### Fallback Mechanism
If LLM fails or returns invalid JSON:
- System automatically generates fallback actions
- Analyzes IOCs to determine appropriate responses
- Blocks malicious IPs/domains
- Isolates compromised hosts
- Always includes notify_analyst

## Security Considerations

### Defense in Depth
1. **Kill Switch**: Global disable for auto-execution
2. **Protected Targets**: Critical systems cannot be auto-actioned
3. **Severity Thresholds**: High-impact actions require approval
4. **Confidence Thresholds**: Low-confidence actions require approval
5. **Rate Limiting**: Prevents action spam
6. **Audit Trail**: Immutable log of all actions

### Dry Run Mode
- Default mode: `DRY_RUN=true`
- Connectors log intended actions without API calls
- Safe for testing without real infrastructure
- Audit logs still generated

### Configuration Validation
- Required environment variables validated on startup
- Missing credentials prevent auto-execution
- Graceful degradation when connectors not configured

## File Structure

```
actions/
├── action_models.py      # Data models for actions
├── connectors.py         # External API integrations
├── policy.py             # Security policy engine
└── audit_log.py          # Audit trail management

agents/
└── response_agent.py     # Action orchestration

config.py                 # Configuration management
```

## Integration Points

### LangGraph Workflow
```python
# graph/nodes.py
def response_node(state: InvestigationState):
    agent = ResponseAgent()
    actions = agent.run(
        campaign=state["campaign"],
        techniques=state["techniques"],
        iocs=state["iocs"]
    )
    return {"actions_taken": actions}
```

### Flask API
```python
# app.py
@app.route("/investigate", methods=["POST"])
def investigate():
    result = run_investigation(events)
    return jsonify(result)  # includes actions_taken
```

## Monitoring and Debugging

### Logging Levels
- `INFO`: Normal operation, action execution
- `WARNING`: Policy decisions, connector issues
- `ERROR`: Execution failures, LLM errors

### Key Log Messages
- `Running Response Agent`: Agent started
- `LLM response received`: LLM call completed
- `Parsed X action proposals`: Actions generated
- `Evaluating action -> target`: Policy evaluation
- `Policy decision = X`: Policy decision made
- `Executing X on Y`: Action execution started
- `Audit log saved`: Action logged

### Debug Commands
```bash
# View audit log
cat actions/audit_log.json | jq

# Check connector configuration
python -c "from config import config; print(config.FIREWALL_API_URL)"

# Test response agent directly
python test_response_agent.py
```

## Performance Considerations

### LLM Latency
- Average: 3-5 seconds per action generation
- Retry logic for rate limiting (429 errors)
- Timeout: 60 seconds total

### Connector Latency
- HTTP timeout: 10 seconds per request
- Retry: 3 attempts with exponential backoff
- Total: Up to 30 seconds per action

### Total Workflow Time
- Typical: 60-90 seconds for full investigation
- Action response: 10-20 seconds additional
