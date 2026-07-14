# Agent Test Verification Guide

This guide explains how to run tests for each agent and verify they work successfully.

## Prerequisites

Before running tests, ensure:

1. **Python environment is activated:**
   ```bash
   source venv/bin/activate  # or .venv/bin/activate
   ```

2. **Dependencies are installed:**
   ```bash
   pip install -r requirements.txt
   pip install pytest pytest-mock
   ```

3. **Environment variables are set:**
   ```bash
   # Copy .env.example to .env and configure
   cp .env.example .env
   # Edit .env with your API keys
   ```

## Running All Tests

Run all agent tests with pytest:
```bash
pytest tests/ -v
```

Run specific agent tests:
```bash
pytest tests/test_collection.py -v
pytest tests/test_enrichment.py -v
pytest tests/test_vulnerability.py -v
pytest tests/test_attack_mapping.py -v
pytest tests/test_correlation.py -v
pytest tests/test_prediction.py -v
pytest tests/test_reporting.py -v
pytest tests/test_response_agent.py -v
```

## Individual Agent Verification

### 1. CollectionAgent

**Purpose:** Normalizes raw security events into structured format.

**Test File:** `tests/test_collection.py`

**Verification Steps:**
```bash
# Run tests
pytest tests/test_collection.py -v

# Expected output:
# test_collection_agent_handles_empty_input PASSED
# test_collection_agent_normalizes_events PASSED
# test_collection_agent_batches_large_inputs PASSED
# test_collection_agent_fallback_on_parse_error PASSED
```

**Success Criteria:**
- Empty input returns empty list
- Events are normalized with event_id
- Large inputs are batched (20 events per batch)
- Parse errors fall back to raw passthrough

**Manual Verification:**
```python
from agents.collection_agent import CollectionAgent

agent = CollectionAgent()
raw_events = [
    {"raw": "powershell.exe -Command Invoke-WebRequest"},
    {"raw": "cmd.exe /c whoami"}
]

result = agent.run(raw_events)
print(f"Normalized events: {len(result)}")
print(f"Has event_id: {all('event_id' in e for e in result)}")
# Expected: 2 events, all with event_id
```

---

### 2. EnrichmentAgent

**Purpose:** Enriches IOCs with threat intelligence and verdicts.

**Test File:** `tests/test_enrichment.py`

**Verification Steps:**
```bash
# Run tests
pytest tests/test_enrichment.py -v

# Expected output:
# test_enrichment_agent_handles_empty_events PASSED
# test_enrichment_agent_handles_no_iocs PASSED
# test_enrichment_agent_enriches_iocs PASSED
# test_enrichment_agent_fallback_on_parse_error PASSED
# test_enrichment_agent_calls_llm_with_iocs PASSED
```

**Success Criteria:**
- Empty events return empty list
- No IOCs return empty list
- IOCs are enriched with LLM
- Parse errors fall back to unenriched IOCs with verdict="unknown"

**Manual Verification:**
```python
from agents.enrichment_agent import EnrichmentAgent

agent = EnrichmentAgent()
events = [{"event_id": "e1", "src_ip": "192.168.1.1", "dest_ip": "evil.com"}]

result = agent.run(events)
print(f"Enriched IOCs: {len(result)}")
print(f"Has verdict: {all('verdict' in i for i in result)}")
# Expected: IOCs enriched with verdict field
```

---

### 3. VulnerabilityAgent

**Purpose:** Identifies relevant CVEs from events and IOCs.

**Test File:** `tests/test_vulnerability.py`

**Verification Steps:**
```bash
# Run tests
pytest tests/test_vulnerability.py -v

# Expected output:
# test_vulnerability_agent_handles_empty_input PASSED
# test_vulnerability_agent_handles_no_software_context PASSED
# test_vulnerability_agent_identifies_software_from_events PASSED
# test_vulnerability_agent_handles_no_cves_retrieved PASSED
# test_vulnerability_agent_analyzes_cves_with_llm PASSED
# test_vulnerability_agent_fallback_on_parse_error PASSED
# test_vulnerability_agent_extracts_from_command_line PASSED
# test_vulnerability_agent_extracts_from_iocs PASSED
```

**Success Criteria:**
- Empty input returns empty list
- Software is extracted from events (product, version, process, command_line)
- CVEs are retrieved via RAG
- LLM analyzes and filters relevant CVEs
- Parse errors use fallback analysis

**Manual Verification:**
```python
from agents.vulnerability_agent import VulnerabilityAgent

agent = VulnerabilityAgent()
events = [{"event_id": "e1", "product": "Apache Log4j", "version": "2.14.1"}]
iocs = []

result = agent.run(events, iocs)
print(f"Vulnerabilities: {len(result)}")
print(f"Has CVE ID: {all('cve_id' in v for v in result)}")
# Expected: CVEs related to Log4j
```

---

### 4. AttackMappingAgent

**Purpose:** Maps security events to MITRE ATT&CK techniques.

**Test File:** `tests/test_attack_mapping.py`

**Verification Steps:**
```bash
# Run tests
pytest tests/test_attack_mapping.py -v

# Expected output:
# test_attack_mapping_agent_handles_empty_events PASSED
# test_attack_mapping_agent_maps_event_to_technique PASSED
# test_attack_mapping_agent_skips_on_parse_error PASSED
# test_attack_mapping_agent_maps_multiple_events PASSED
# test_attack_mapping_agent_event_to_text_conversion PASSED
# test_attack_mapping_agent_handles_missing_fields PASSED
```

**Success Criteria:**
- Empty events return empty list
- Events are mapped to ATT&CK techniques
- RAG provides ATT&CK context
- Parse errors skip the event
- Evidence event_id is preserved

**Manual Verification:**
```python
from agents.attack_mapping_agent import AttackMappingAgent

agent = AttackMappingAgent()
events = [
    {"event_id": "e1", "process": "powershell.exe", "command_line": "Invoke-WebRequest"}
]

result = agent.run(events)
print(f"Techniques: {len(result)}")
print(f"Has technique_id: {all('technique_id' in t for t in result)}")
print(f"Has evidence_event_id: {all('evidence_event_id' in t for t in result)}")
# Expected: Technique mapped with T1059.001 or similar
```

---

### 5. CorrelationAgent

**Purpose:** Correlates events into campaigns and persists to knowledge graph.

**Test File:** `tests/test_correlation.py`

**Verification Steps:**
```bash
# Run tests
pytest tests/test_correlation.py -v

# Expected output:
# test_correlation_agent_handles_empty_events PASSED
# test_correlation_agent_creates_campaign PASSED
# test_correlation_agent_fallback_on_parse_error PASSED
# test_correlation_agent_persists_to_graph PASSED
# test_correlation_agent_handles_persistence_error PASSED
# test_correlation_agent_generates_campaign_id PASSED
# test_correlation_agent_includes_all_context_in_prompt PASSED
```

**Success Criteria:**
- Empty events return empty dict
- Events are correlated into campaigns
- Campaign has campaign_id, name, timeline, related_techniques
- Campaign is persisted to Neo4j
- Persistence errors don't break the pipeline
- Parse errors use fallback campaign

**Manual Verification:**
```python
from agents.correlation_agent import CorrelationAgent

agent = CorrelationAgent()
events = [{"event_id": "e1", "process": "powershell.exe"}]
iocs = [{"value": "192.168.1.1", "ioc_type": "ip"}]
techniques = [{"technique_id": "T1059.001", "name": "PowerShell"}]

result = agent.run(events, iocs, techniques)
print(f"Campaign ID: {result.get('campaign_id')}")
print(f"Campaign Name: {result.get('name')}")
print(f"Has timeline: {'timeline' in result}")
# Expected: Campaign with UUID, name, and timeline
```

---

### 6. PredictionAgent

**Purpose:** Predicts likely next attacker techniques.

**Test File:** `tests/test_prediction.py`

**Verification Steps:**
```bash
# Run tests
pytest tests/test_prediction.py -v

# Expected output:
# test_prediction_agent_handles_empty_techniques PASSED
# test_prediction_agent_retrieves_attack_chain PASSED
# test_prediction_agent_fallback_on_parse_error PASSED
# test_prediction_agent_includes_campaign_context PASSED
# test_prediction_agent_handles_missing_technique_names PASSED
# test_prediction_agent_includes_rag_context PASSED
```

**Success Criteria:**
- Empty techniques return default response
- Attack chain is retrieved via RAG
- LLM predicts next techniques
- Campaign context is included
- Parse errors use fallback response

**Manual Verification:**
```python
from agents.prediction_agent import PredictionAgent

agent = PredictionAgent()
techniques = [{"name": "PowerShell", "technique_id": "T1059.001"}]
campaign = {"name": "Test Campaign"}

result = agent.run(techniques, campaign)
print(f"Next techniques: {result.get('likely_next_techniques')}")
print(f"Rationale: {result.get('rationale')}")
# Expected: List of next techniques with rationale
```

---

### 7. ReportingAgent

**Purpose:** Generates markdown intelligence reports.

**Test File:** `tests/test_reporting.py`

**Verification Steps:**
```bash
# Run tests
pytest tests/test_reporting.py -v

# Expected output:
# test_reporting_agent_generates_report PASSED
# test_reporting_agent_includes_all_state_in_prompt PASSED
# test_reporting_agent_saves_report_with_campaign PASSED
# test_reporting_agent_handles_empty_state PASSED
# test_reporting_agent_handles_missing_campaign PASSED
```

**Success Criteria:**
- Report is generated from state
- All state components are included (events, IOCs, vulnerabilities, techniques, campaign, prediction)
- Report is saved to file with campaign info
- Empty state is handled

**Manual Verification:**
```python
from agents.reporting_agent import ReportingAgent

agent = ReportingAgent()
state = {
    "events": [{"event_id": "e1"}],
    "iocs": [{"value": "192.168.1.1"}],
    "vulnerabilities": [],
    "techniques": [{"technique_id": "T1059.001"}],
    "campaign": {"campaign_id": "test-123", "name": "Test Campaign"},
    "prediction": {"likely_next_techniques": []}
}

result = agent.run(state)
print(f"Report length: {len(result)}")
print(f"Has markdown: {'#' in result}")
# Expected: Markdown report with headers
```

---

### 8. ResponseAgent

**Purpose:** Generates and executes response actions.

**Test File:** `tests/test_response_agent.py`

**Verification Steps:**
```bash
# Run tests
pytest tests/test_response_agent.py -v

# Expected output:
# test_response_agent_generates_actions PASSED
# test_response_agent_executes_auto_approved_actions PASSED
# test_response_agent_handles_denied_actions PASSED
# test_response_agent_handles_parse_error PASSED
# test_response_agent_includes_context_in_prompt PASSED
# test_response_agent_handles_empty_input PASSED
# test_response_agent_records_all_actions PASSED
```

**Success Criteria:**
- Actions are generated from campaign, techniques, IOCs
- Auto-approved actions are executed via connectors
- Denied actions are not executed
- All actions are recorded in audit log
- Parse errors are handled gracefully
- Protected targets are denied

**Manual Verification:**
```python
from agents.response_agent import ResponseAgent

agent = ResponseAgent()
campaign = {"campaign_id": "test-123", "name": "Test Campaign"}
techniques = [{"technique_id": "T1059.001", "name": "PowerShell"}]
iocs = [{"value": "192.168.1.1", "ioc_type": "ip", "verdict": "malicious"}]

results = agent.run(campaign, techniques, iocs)
print(f"Actions: {len(results)}")
for r in results:
    print(f"  {r.action.action_type} -> {r.action.target} ({r.status})")
# Expected: Actions with status (executed, pending_approval, or denied)
```

---

## Integration Testing

To test the full workflow:

```bash
# Run the full investigation
python main.py --events data/sample_events/single_event_test.json

# Or use the API
python app.py
# Then POST events to /investigate endpoint
```

**Success Criteria:**
- All agents execute in sequence
- State is passed between agents
- Final state contains all analysis results
- Report is generated
- Actions are evaluated (if enabled)

---

## Troubleshooting

### Test Failures

**LLM API Errors:**
- Check GROQ_API_KEY in .env
- Verify API key is valid
- Check network connectivity

**ChromaDB Errors:**
- Ensure ChromaDB is initialized: `python -c "from rag.ingest_attack import main; main()"`
- Check CHROMA_PERSIST_DIR exists

**Neo4j Errors:**
- Check NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD in .env
- Verify Neo4j is running: `neo4j status`
- Test connection: `python -c "from databases.neo4j_manager import neo4j_manager; print(neo4j_manager.verify_connectivity())"`

**Import Errors:**
- Ensure virtual environment is activated
- Reinstall dependencies: `pip install -r requirements.txt`

### Mock vs Real Tests

The provided tests use mocks to avoid external dependencies. To test with real LLM calls:

1. Remove `@patch` decorators
2. Set real API keys in .env
3. Run tests: `pytest tests/ -v --no-mock`

**Warning:** Real tests will consume API quota and take longer.

---

## Continuous Integration

Add to CI/CD pipeline:

```yaml
# .github/workflows/test.yml
name: Test Agents
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2
        with:
          python-version: '3.13'
      - run: pip install -r requirements.txt
      - run: pip install pytest pytest-mock
      - run: pytest tests/ -v
```

---

## Test Coverage

Generate coverage report:

```bash
pip install pytest-cov
pytest tests/ --cov=agents --cov-report=html
```

Open `htmlcov/index.html` to view coverage.

**Target Coverage:** 80%+ for all agents
