# Database Schema

## ChromaDB — `attack_techniques` collection

| Field | Type | Description |
|---|---|---|
| `id` | string | `<technique_id>-<chunk_index>` |
| `embedding` | float[] | sentence-transformers embedding (384-dim for `all-MiniLM-L6-v2`) |
| `document` | string | chunked ATT&CK technique description text |
| `metadata.technique_id` | string | e.g. `T1059.001` |
| `metadata.name` | string | e.g. `PowerShell` |
| `metadata.tactic` | string | e.g. `execution` |

Populated by `rag/ingest_attack.py`, queried by `rag/retriever.py` and
`rag/attack_chain_retriever.py`.

## Neo4j — Graph Schema

**Node labels:**

| Label | Key property | Other properties |
|---|---|---|
| `Host` | `name` | — |
| `Event` | `event_id` | `event_type`, `timestamp` |
| `Technique` | `technique_id` | `name` |
| `Campaign` | `campaign_id` | `name` |
| `IOC` *(optional, extend graph_builder.py to add)* | `value` | `ioc_type`, `verdict` |

**Relationships:**

```
(Host)      -[:GENERATED]->   (Event)
(Event)     -[:MAPPED_TO]->   (Technique)
(Event)     -[:PART_OF]->     (Campaign)
(Technique) -[:PART_OF]->     (Campaign)
(Event)     -[:INVOLVED]->    (IOC)        # optional extension
```

**Constraints** (`knowledge_graph/graph_schema.py`):

```cypher
CREATE CONSTRAINT host_id      IF NOT EXISTS FOR (h:Host) REQUIRE h.name IS UNIQUE;
CREATE CONSTRAINT event_id     IF NOT EXISTS FOR (e:Event) REQUIRE e.event_id IS UNIQUE;
CREATE CONSTRAINT technique_id IF NOT EXISTS FOR (t:Technique) REQUIRE t.technique_id IS UNIQUE;
CREATE CONSTRAINT campaign_id  IF NOT EXISTS FOR (c:Campaign) REQUIRE c.campaign_id IS UNIQUE;
CREATE CONSTRAINT ioc_value    IF NOT EXISTS FOR (i:IOC) REQUIRE i.value IS UNIQUE;
```

**Example analyst queries** (`knowledge_graph/graph_queries.py`):

```cypher
-- All hosts that triggered a given technique
MATCH (h:Host)-[:GENERATED]->(:Event)-[:MAPPED_TO]->(t:Technique {technique_id: "T1059.001"})
RETURN DISTINCT h.name;

-- Full timeline of a campaign
MATCH (e:Event)-[:PART_OF]->(:Campaign {campaign_id: $id})
RETURN e.event_id, e.event_type, e.timestamp
ORDER BY e.timestamp;
```

## Local JSON file — Investigation Memory

`data/investigation_memory.json` (created automatically by
`memory/investigation_memory.py`): an append-only JSON array of full
`InvestigationState` snapshots from past runs, used for campaign-continuity
matching across separate executions of `main.py`.
