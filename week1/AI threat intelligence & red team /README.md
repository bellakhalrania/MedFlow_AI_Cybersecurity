# MITRE ATT&CK RAG / Red Team Intelligence Platform

A Retrieval-Augmented Generation platform that lets SOC analysts, threat
hunters, and red-team operators query the MITRE ATT&CK knowledge base
through four specialized AI agents, grounded by real ATT&CK data (not LLM
memory) and served by Groq-hosted Llama 3.3.

This implementation has been built and tested against the **real, live
MITRE ATT&CK Enterprise STIX bundle** (25,842 objects, pulled directly from
`github.com/mitre/cti`) — every parser function in this repo has been run
against actual production data, not synthetic samples.

---

## 1. Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│ Layer 1 — Data Source                                                │
│   MITRE CTI repo (github.com/mitre/cti) → enterprise-attack.json     │
│   STIX 2.1 bundle: 858 attack-patterns, 21k relationships,           │
│   729 malware, 189 intrusion-sets, 95 tools, 268 mitigations,        │
│   1758 analytics, 699 detection strategies                           │
└───────────────────────────────┬────────────────────────────────────-┘
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Layer 2 — Data Processing (parser/stix_parser.py)                    │
│   Loads bundle → builds id-lookup table → filters revoked/deprecated │
│   → emits 4 datasets:                                                │
│     • techniques      (attack-pattern)            → attack_db       │
│     • procedures      (relationship type="uses")  → redteam_db      │
│     • actors_tools    (intrusion-set/malware/tool) → actor_db        │
│     • detections      (course-of-action/analytic/  → detection_db    │
│                         detection-strategy)                          │
└───────────────────────────────┬────────────────────────────────────-┘
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Layer 3 — Embedding Pipeline (embeddings/embedding_pipeline.py)      │
│   BAAI/bge-base-en-v1.5 (768-dim, retrieval-optimized)                │
│   Documents embedded as-is; queries get the bge retrieval prefix     │
└───────────────────────────────┬────────────────────────────────────-┘
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Layer 4 — Vector DB (vectordb/chroma_manager.py)                     │
│   ChromaDB PersistentClient, 4 cosine-similarity collections,        │
│   local disk storage at storage/chroma_db/, no external DB needed    │
└───────────────────────────────┬────────────────────────────────────-┘
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Layer 5 — Agent Layer (agents/, orchestrator.py)                     │
│   Red Team Agent   → attack_db + redteam_db                          │
│   CTI Analyst Agent → attack_db + detection_db (healthcare framing)  │
│   Attribution Agent → actor_db (confidence-scored, never invents)    │
│   Detection Agent  → detection_db + attack_db                        │
│   Orchestrator routes free-text queries to the right agent           │
└─────────────────────────────────────────────────────────────────────┘
```

**RAG workflow per query:** user query → ID-validation guardrail → embed
query (bge prefix) → vector search across the agent's collections → merge
+ rank by cosine distance → build context block → Groq Llama 3.3 with a
grounding-rules system prompt → answer + cited sources returned to caller.

**Hallucination prevention (`validation/id_validator.py`):** every MITRE-ID-
shaped token in the user's query (regex: `T1003`, `T1003.001`, `TA0001`,
`S0154`, `G0016`, `M1015`) is checked against an **exact metadata match**
in ChromaDB before the query ever reaches the LLM. If an ID doesn't exist
in the ingested dataset, the agent returns a refusal — the LLM is never
given a chance to "explain" a fake technique. This was tested against the
real dataset: `T1047` (real) → valid, `T9999` (fake) → correctly rejected.

---

## 2. Project layout

```
mitre_rag_platform/
├── config.py                  # all paths, model names, tunables
├── requirements.txt
├── ingest.py                  # one-shot: download → parse → embed → store
├── app.py                     # CLI chat interface
├── web_app.py                 # Streamlit web interface 
├── orchestrator.py            # query routing across the 4 agents
├── data/
│   ├── download_mitre.py      # pulls enterprise-attack.json from GitHub
│   └── parsed/                # generated: 4 JSON datasets (after ingest)
├── parser/
│   └── stix_parser.py         # STIX → 4 structured datasets
├── embeddings/
│   └── embedding_pipeline.py  # BAAI/bge-base-en-v1.5 wrapper
├── vectordb/
│   └── chroma_manager.py      # ChromaDB collections, ingest + query
├── validation/
│   └── id_validator.py        # hallucination-prevention guardrail
├── llm/
│   └── groq_client.py         # Groq API call + grounding system prompt
├── agents/
│   ├── base_agent.py          # shared RAG pipeline (retrieve + answer)
│   ├── redteam_agent.py
│   ├── cti_agent.py
│   ├── attribution_agent.py   # adds confidence scoring
│   └── detection_agent.py
└── storage/chroma_db/         # persistent vector DB (created on first run)
```

---

## 3. Setup

```bash
cd mitre_rag_platform
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

export GROQ_API_KEY=   # https://console.groq.com/keys
```

### Build the knowledge base (one-time, ~5-10 min on CPU)

```bash
python ingest.py
```

This downloads the live MITRE bundle, parses it into the 4 datasets,
embeds every document with `BAAI/bge-base-en-v1.5`, and stores everything
in `storage/chroma_db/`. Re-run this whenever MITRE publishes a new ATT&CK
release (a few times per year) to keep the knowledge base current.

For a fast dev loop, ingest a small slice first:
```bash
python ingest.py --limit 50
```

### Run the CLI chat interface

```bash
python app.py
```

```
============================================================
  MITRE ATT&CK RAG / Red Team Intelligence Platform
  Agents: [redteam] [cti] [attribution] [detection] [auto]
============================================================
(auto)> How does Ryuk gain persistence?
[Red Team Agent]
...grounded answer citing specific T-IDs from retrieved context...

(auto)> /agent attribution
(attribution)> Which actors use Mimikatz and PsExec together?
[Attribution Agent]
1. <actor> – <confidence> confidence ...
```

### Run the web interface (recommended)

```bash
streamlit run web_app.py
```

Opens in your browser at `http://localhost:8501`

**Features:**
- **Multi-agent chat** — select agents manually or use auto-routing
- **Persistent chat history** — all queries and responses stored in session
- **Retrieved sources display** — view all chunks retrieved, with:
  - Cosine distance scores
  - Confidence levels (for attribution agent)
  - Collection metadata
- **Database statistics** — real-time view of ingested collections
- **Agent selection sidebar** — pin to specific agent or enable auto-routing
- **Responsive design** — works on desktop and tablet

**Example queries:**
```
"How does Ryuk gain persistence?" → Red Team Agent (auto-routed)
"Detect Mimikatz usage in logs" → Detection Agent
"Which APT groups target healthcare?" → CTI Analyst Agent  
"Identify actors using T1003 and T1055" → Attribution Agent
```

---

## 4. A note on this sandbox vs. your machine

Everything in this repo was built and validated against **real MITRE
data** inside this development sandbox:

- `parser/stix_parser.py` ran against the actual 46 MB `enterprise-attack.json`
  (697 techniques, 16,903 procedures, 995 actors/tools, 2,499 detection
  records extracted, sample records spot-checked for quality).
- `vectordb/chroma_manager.py` was exercised end-to-end: ingestion, exact-ID
  metadata lookup, and cosine vector search all confirmed working.
- `validation/id_validator.py` was tested against the real dataset:
  real IDs (`T1047`, `S0140`, `G0016`, `M1021`) validate `True`; a fake ID
  (`T9999`) correctly validates `False` and produces the refusal message
  *before* any LLM call is made.


