# Architecture — Agentic Threat Intelligence Platform

## 1. Design Principle

Traditional SIEMs collect data and raise alerts; analysts do the thinking.
This platform inverts the cost curve:

```
Security Tools  →  Collect Data        (Sysmon, Suricata, Zeek, Wazuh)
AI Agents       →  Analyze Data        (LangGraph + Groq + RAG)
```

Six specialized agents run as nodes in a single LangGraph pipeline, each
reading and writing a shared `InvestigationState` object, so every agent has
full context from everything upstream of it.

## 2. End-to-End Pipeline

```
┌────────────────────┐
│  Security Telemetry │  Sysmon · Suricata · Zeek · Wazuh
└──────────┬──────────┘
           ▼
┌────────────────────┐
│  Collection Agent    │  raw logs → normalized event schema
└──────────┬──────────┘
           ▼
┌────────────────────┐
│  IOC Enrichment      │  extract IPs/hashes/domains/URLs → verdict + context
└──────────┬──────────┘
           ▼
┌────────────────────┐
│  ATT&CK Mapping (RAG)│  event → retrieved ATT&CK technique → technique_id
└──────────┬──────────┘
           ▼
┌────────────────────┐
│  Campaign Correlation│  events+IOCs+techniques → one attack narrative
└──────────┬──────────┘
           ▼
┌────────────────────┐
│  Threat Prediction   │  observed techniques → likely next technique(s)
└──────────┬──────────┘
           ▼
┌────────────────────┐
│  Reporting Agent     │  full state → markdown intelligence report
└──────────┬──────────┘
           ▼
   Intelligence Report (.md, saved + printed)
```

## 3. Component Map

| Layer | Folder | Responsibility |
|---|---|---|
| Orchestration | `graph/` | LangGraph `StateGraph`: shared state, node wrappers, compiled workflow |
| Reasoning agents | `agents/` | One class per pipeline stage; each owns a single responsibility |
| RAG | `rag/` | ATT&CK ingestion, chunking, embeddings, ChromaDB store/retrieval |
| LLM | `llm/` | Single Groq client, centralized prompts, defensive JSON parsing |
| Telemetry | `telemetry/` | Parsers that turn vendor-specific log formats into plain dicts |
| Domain logic | `intelligence/` | IOC regex extraction, ATT&CK lookups, campaign storylines, risk scoring |
| Persistence | `databases/` | Neo4j driver manager, Chroma convenience wrapper, Pydantic models |
| Graph DB | `knowledge_graph/` | Schema/constraints, graph writes, analyst Cypher queries |
| Memory | `memory/` | Cross-run investigation history, campaign continuity matching |
| Output | `reports/` | Jinja2 template + file writer for the final markdown report |

## 4. Data Flow Through `InvestigationState`

```python
InvestigationState = {
    "raw_events": [...],     # input
    "events": [...],         # ← Collection Agent
    "iocs": [...],           # ← Enrichment Agent
    "techniques": [...],     # ← ATT&CK Mapping Agent
    "campaign": {...},       # ← Correlation Agent
    "prediction": {...},     # ← Prediction Agent
    "report": "...",         # ← Reporting Agent
}
```

Every node in `graph/workflow.py` takes this dict in, computes its slice, and
returns a partial update — LangGraph merges it back into state automatically.

## 5. Why Two Databases

| Database | Question it answers | Why this DB |
|---|---|---|
| **ChromaDB** | "Which ATT&CK technique does this behavior most resemble?" | Semantic similarity search over technique *descriptions* — exactly what vector search is for |
| **Neo4j** | "Which hosts used T1059? What's the full timeline of campaign X?" | Multi-hop relationship traversal (Host → Event → Technique → Campaign) is native to graph DBs, painful in SQL/vector stores |

## 6. RAG Flow (ATT&CK Mapping)

```
MITRE ATT&CK STIX bundle (enterprise-attack.json)
        │  rag/ingest_attack.py
        ▼
Chunked technique descriptions (rag/chunking.py)
        │  rag/embeddings.py (sentence-transformers)
        ▼
ChromaDB persistent collection (rag/vector_store.py)
        │  query at runtime
        ▼
rag/retriever.py → top-N relevant technique snippets
        │
        ▼
attack_mapping_agent.py → Groq LLM picks technique_id + confidence
```

## 7. Extending the Platform

- **New telemetry source** → add a parser in `telemetry/`, output the same
  raw-event dict shape, feed it into `raw_events`.
- **New agent / pipeline stage** → add a class in `agents/`, a node wrapper in
  `graph/nodes.py`, and an edge in `graph/workflow.py`.
- **Swap the LLM provider** → only `llm/groq_client.py` needs to change;
  every agent calls `invoke_llm()`, never the provider SDK directly.
- **Swap the vector DB** → only `rag/vector_store.py` needs to change.
