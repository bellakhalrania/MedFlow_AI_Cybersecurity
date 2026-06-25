# Installation Guide — Agentic Threat Intelligence Platform

This guide walks through installing every tool the platform depends on, in
the order you need them. Estimated total setup time: 20–30 minutes.

---

## 0. Prerequisites

| Tool | Minimum version | Check with |
|---|---|---|
| Python | 3.10+ | `python3 --version` |
| pip | latest | `pip --version` |
| Docker (for Neo4j) | 20.10+ | `docker --version` |
| Git | any recent | `git --version` |

If Python is missing:
```bash
# Ubuntu/Debian
sudo apt update && sudo apt install python3 python3-pip python3-venv -y

# macOS (Homebrew)
brew install python

# Windows: download from https://www.python.org/downloads/
```

If Docker is missing, install Docker Desktop (Windows/macOS) or Docker
Engine (Linux) from https://docs.docker.com/get-docker/.

---

## 1. Get the Project and Create a Virtual Environment

```bash
git clone <your-repo-url> agentic-threat-intelligence
cd agentic-threat-intelligence

python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
```

---

## 2. Install Python Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

This installs: `langgraph`, `langchain`, `langchain-groq`, `chromadb`,
`sentence-transformers`, `neo4j`, `pydantic`, `python-dotenv`, `pandas`,
`jinja2`, `markdown2`, `pytest`, plus optional telemetry parsing libs
(`python-evtx`, `scapy`).

> **Note (Windows):** `sentence-transformers` pulls in PyTorch. If the
> install is slow or fails, install the CPU-only wheel first:
> `pip install torch --index-url https://download.pytorch.org/whl/cpu`

---

## 3. Set Up Environment Variables

```bash
cp .env.example .env
```

Open `.env` and fill in:

```ini
GROQ_API_KEY=your_groq_api_key_here
```

(Other values have sensible defaults and don't need to change for local
development.)

---

## 4. Get a Groq API Key (LLM reasoning engine)

1. Go to **https://console.groq.com/keys**
2. Sign up / log in (free tier available).
3. Click **Create API Key**, copy it.
4. Paste it into `.env` as `GROQ_API_KEY`.
5. Verify it works:

```bash
python -c "
from llm.groq_client import invoke_llm
print(invoke_llm('You are a helpful assistant.', 'Say hello in 5 words.'))
"
```

If you see a short greeting printed, the LLM layer is working. Default
model is `llama-3.3-70b-versatile` — change `GROQ_MODEL` in `.env` if you
want a different Groq-hosted model.

---

## 5. Set Up ChromaDB (Vector Intelligence — no server needed)

ChromaDB runs embedded/local by default — there's nothing extra to install
beyond the `chromadb` pip package already in `requirements.txt`. It will
create its on-disk store at `./data/chroma_store` automatically the first
time you run the app.

Verify it works:

```bash
python -c "
from rag.vector_store import get_attack_collection
print(get_attack_collection().count(), 'documents in collection (expect 0 before ingestion)')
"
```

---

## 6. Set Up Neo4j (Relationship Intelligence)

The simplest path is Docker:

```bash
docker run -d \
  --name neo4j-threat-intel \
  -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/changeme \
  -v neo4j_data:/data \
  neo4j:5.23
```

- Bolt protocol (used by the Python driver): `bolt://localhost:7687`
- Browser UI for manual querying: **http://localhost:7474** (login
  `neo4j` / `changeme`)

Make sure `.env` matches the password you used:

```ini
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=changeme
```

Apply the schema constraints once:

```bash
python -c "
from knowledge_graph.graph_schema import apply_constraints
apply_constraints()
print('Neo4j constraints applied.')
"
```

Verify connectivity:

```bash
python -c "
from databases.neo4j_manager import neo4j_manager
print('Connected:', neo4j_manager.verify_connectivity())
"
```

> **No Docker?** Download Neo4j Desktop from
> https://neo4j.com/download/ and create a local DBMS instead — just update
> `NEO4J_URI`/`NEO4J_USER`/`NEO4J_PASSWORD` in `.env` to match.

---

## 7. Download and Ingest MITRE ATT&CK Data

Download the Enterprise ATT&CK STIX bundle:

```bash
curl -L -o data/attack_data/enterprise_attack.json \
  https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
```

Run the ingestion script (embeds every technique into ChromaDB — first run
takes a few minutes and downloads the `all-MiniLM-L6-v2` embedding model,
~80MB):

```bash
python -m rag.ingest_attack
```

Expected output:
```
Loaded 800+ ATT&CK techniques from STIX bundle.
  ingested 50/800 techniques...
  ...
ATT&CK ingestion complete.
```

---

## 8. (Optional) Set Up Telemetry Sources

You don't need real Sysmon/Suricata/Zeek/Wazuh deployments to try the
platform — `data/sample_events/sample_events.json` already provides sample
normalized-ish events. Install these only if you want to feed in real
telemetry:

| Tool | Purpose | Install guide |
|---|---|---|
| **Sysmon** | Windows process/network telemetry | https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon |
| **Suricata** | Network IDS/IPS alerts | https://docs.suricata.io/en/latest/install.html |
| **Zeek** | Network traffic logs (conn/dns/http) | https://docs.zeek.org/en/master/install.html |
| **Wazuh** | Host-based SIEM/alerting | https://documentation.wazuh.com/current/installation-guide/index.html |

Once installed, export their logs as JSON (most support this natively, or
via Filebeat/Logstash) and point the parsers in `telemetry/` at the export
files, e.g.:

```python
from telemetry.sysmon_parser import parse_sysmon_json
events = parse_sysmon_json("data/raw_logs/sysmon_export.json")
```

---

## 9. Run the Platform End-to-End

```bash
python main.py --events data/sample_events/sample_events.json
```

This runs the full LangGraph pipeline (Collection → Enrichment → Mapping →
Correlation → Prediction → Reporting) and:
- prints the markdown intelligence report to the console
- saves it to `reports/generated_reports/report_<campaign_id>.md`
- writes the campaign/events/techniques into Neo4j
- appends the run to `data/investigation_memory.json`

---

## 10. Run the Test Suite

```bash
pytest tests/ -v
```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `EnvironmentError: Missing GROQ_API_KEY` | `.env` not filled in | Re-check step 3–4 |
| `chromadb` install fails on Apple Silicon | onnxruntime wheel mismatch | `pip install --upgrade chromadb` or use Python 3.11 |
| Neo4j `ServiceUnavailable` | container not running / wrong port | `docker ps`, confirm port `7687` is mapped |
| `sentence-transformers` very slow first run | downloading model weights | normal — only happens once, cached afterward |
| LLM JSON parsing errors in agent output | model returned prose instead of JSON | check `GROQ_MODEL`; larger models follow the JSON-only instruction more reliably |

---

## Summary: Minimum Viable Setup (just to see it run)

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # then add your GROQ_API_KEY
docker run -d --name neo4j-threat-intel -p 7474:7474 -p 7687:7687 -e NEO4J_AUTH=neo4j/changeme neo4j:5.23
curl -L -o data/attack_data/enterprise_attack.json https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
python -m rag.ingest_attack
python main.py
```
