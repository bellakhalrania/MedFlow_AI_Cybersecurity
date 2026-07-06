# Agentic Threat Intelligence Platform

LangGraph + Groq + RAG (ChromaDB) + Neo4j — turns raw security telemetry
(Sysmon, Suricata, Zeek, Wazuh) into correlated, predictive threat
intelligence reports, using six specialized AI agents instead of static
SIEM rules.

```
Security Tools Collect Data  →  AI Agents Analyze Data
```

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
