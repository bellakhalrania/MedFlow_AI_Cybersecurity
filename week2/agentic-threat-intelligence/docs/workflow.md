# Workflow — LangGraph Pipeline Detail

## Graph Definition (`graph/workflow.py`)

```
START → collection → enrichment → mapping → correlation → prediction → reporting → END
```

This is currently a **linear** graph (no branches/loops), which keeps it easy
to reason about and debug. Each box below is a LangGraph node.

| Node | Reads from state | Writes to state | Agent class |
|---|---|---|---|
| `collection` | `raw_events` | `events` | `CollectionAgent` |
| `enrichment` | `events` | `iocs` | `EnrichmentAgent` |
| `mapping` | `events` | `techniques` | `AttackMappingAgent` |
| `correlation` | `events`, `iocs`, `techniques` | `campaign` | `CorrelationAgent` |
| `prediction` | `techniques`, `campaign` | `prediction` | `PredictionAgent` |
| `reporting` | entire state | `report` | `ReportingAgent` |

## Example Run

**Input** (`data/sample_events/sample_events.json`): a PowerShell encoded
command, a Suricata C2-beacon alert, and a Wazuh "new scheduled task" alert
on the same host within ~2 minutes.

**Expected progression:**

1. `collection` → normalizes the 3 heterogeneous logs into one event schema.
2. `enrichment` → flags `185.44.12.7` as a suspicious/malicious IP.
3. `mapping` → maps the PowerShell command to `T1059.001`, the scheduled task
   to `T1053.005` (Persistence).
4. `correlation` → groups all three into one campaign ("PowerShell-based
   intrusion with C2 beaconing and scheduled-task persistence").
5. `prediction` → given Execution + Persistence observed, predicts
   Credential Access (e.g. `T1003`) as the likely next step.
6. `reporting` → writes `reports/generated_reports/report_<campaign_id>.md`.

## Extending the Graph with Branches

LangGraph supports conditional edges if you later want, e.g., to skip
`prediction` for low-severity campaigns:

```python
def route_after_correlation(state):
    if state["campaign"].get("severity") == "Low":
        return "reporting"
    return "prediction"

graph.add_conditional_edges("correlation", route_after_correlation)
```

## Error Handling Philosophy

Every agent degrades gracefully instead of crashing the whole run:
- LLM JSON parse failures fall back to a sane default (e.g. passthrough
  events, "unknown" verdicts) rather than raising.
- Neo4j writes in `correlation_agent.py` are best-effort — a graph DB outage
  won't stop the report from being generated.
- `errors` field in `InvestigationState` is reserved for agents to log
  non-fatal issues for later review.
