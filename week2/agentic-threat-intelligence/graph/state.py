from typing import TypedDict, List, Dict, Any, Optional


class InvestigationState(TypedDict, total=False):
    # --- Input ---
    raw_events: List[Dict[str, Any]]          # raw telemetry as ingested

    # --- Collection Agent output ---
    events: List[Dict[str, Any]]              # normalized events

    # --- IOC Enrichment Agent output ---
    iocs: List[Dict[str, Any]]                # enriched indicators (ip/hash/domain/url + context)

    # --- ATT&CK Mapping Agent output ---
    techniques: List[Dict[str, Any]]          # [{technique_id, name, confidence, evidence_event_id}]

    # --- Correlation Agent output ---
    campaign: Dict[str, Any]                  # {campaign_id, name, timeline, related_techniques}

    # --- Prediction Agent output ---
    prediction: Dict[str, Any]                # {likely_next_techniques: [...], rationale: str}

    # --- Reporting Agent output ---
    report: str                               # final markdown intelligence report

    # --- Response Agent output ---
    actions_taken: List[Dict[str, Any]]       # results of proposed/executed/pending response actions

    # --- Bookkeeping ---
    errors: List[str]                         # any non-fatal errors collected along the way
    metadata: Dict[str, Any]                  # run id, timestamps, source system, etc.


def new_investigation_state(raw_events: Optional[List[Dict[str, Any]]] = None) -> InvestigationState:
    """Factory for a fresh, fully-initialized state object."""
    return InvestigationState(
        raw_events=raw_events or [],
        events=[],
        iocs=[],
        techniques=[],
        campaign={},
        prediction={},
        report="",
        actions_taken=[],
        errors=[],
        metadata={},
    )
