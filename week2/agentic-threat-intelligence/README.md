# Agentic Threat Intelligence Platform

LangGraph + Groq + RAG (ChromaDB) + Neo4j — turns raw security telemetry
(Sysmon, Suricata, Zeek, Wazuh) into correlated, predictive threat
intelligence reports, using six specialized AI agents instead of static
SIEM rules.

```
Security Tools Collect Data  →  AI Agents Analyze Data
```

## Quick Links

- **Full architecture:** [`docs/architecture.md`](docs/architecture.md)
- **Pipeline / workflow detail:** [`docs/workflow.md`](docs/workflow.md)
- **Database schema (Neo4j + ChromaDB):** [`docs/database_schema.md`](docs/database_schema.md)
- **Step-by-step install guide:** [`INSTALLATION_GUIDE.md`](INSTALLATION_GUIDE.md)

## Quick Start

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # add your GROQ_API_KEY (https://console.groq.com/keys)
docker run -d --name neo4j-threat-intel -p 7474:7474 -p 7687:7687 -e NEO4J_AUTH=neo4j/changeme neo4j:5.23
curl -L -o data/attack_data/enterprise_attack.json https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
python -m rag.ingest_attack
python main.py
```

See `INSTALLATION_GUIDE.md` for the full walkthrough, troubleshooting, and
optional real telemetry source setup (Sysmon/Suricata/Zeek/Wazuh).

## The Six Agents

| # | Agent | Job |
|---|---|---|
| 1 | Collection | Normalize raw telemetry into one event schema |
| 2 | IOC Enrichment | Extract & score IPs/hashes/domains/URLs |
| 3 | ATT&CK Mapping (RAG) | Map behavior to MITRE technique IDs |
| 4 | Campaign Correlation | Group isolated events into one attack narrative |
| 5 | Threat Prediction | Forecast the attacker's likely next move |
| 6 | Reporting | Generate the final markdown intelligence report |

## Project Layout

```
agentic-threat-intelligence/
├── main.py / config.py / requirements.txt
├── graph/          orchestration (LangGraph state + workflow)
├── agents/         the six agents above
├── rag/            ATT&CK ingestion + ChromaDB retrieval
├── llm/            Groq client, prompts, output parsing
├── telemetry/      Sysmon / Suricata / Zeek / Wazuh parsers
├── intelligence/   IOC extraction, ATT&CK lookups, risk scoring
├── databases/      Neo4j + Chroma connection managers, models
├── knowledge_graph/ Neo4j schema, graph writes, analyst queries
├── memory/         cross-run investigation/campaign memory
├── reports/        markdown report templates + generator
├── data/           ATT&CK data, sample events, raw log inputs
├── tests/          pytest unit tests
└── docs/           architecture, workflow, db schema docs
```
