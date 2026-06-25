"""
graph/nodes.py
Thin wrapper functions that adapt each Agent class into a LangGraph node
(a callable that takes the state dict and returns a partial state update).
"""

from graph.state import InvestigationState
from agents.collection_agent import CollectionAgent
from agents.enrichment_agent import EnrichmentAgent
from agents.attack_mapping_agent import AttackMappingAgent
from agents.correlation_agent import CorrelationAgent
from agents.prediction_agent import PredictionAgent
from agents.reporting_agent import ReportingAgent

collection_agent = CollectionAgent()
enrichment_agent = EnrichmentAgent()
mapping_agent = AttackMappingAgent()
correlation_agent = CorrelationAgent()
prediction_agent = PredictionAgent()
reporting_agent = ReportingAgent()


def collection_node(state: InvestigationState) -> dict:
    events = collection_agent.run(state.get("raw_events", []))
    return {"events": events}


def enrichment_node(state: InvestigationState) -> dict:
    iocs = enrichment_agent.run(state.get("events", []))
    return {"iocs": iocs}


def mapping_node(state: InvestigationState) -> dict:
    techniques = mapping_agent.run(state.get("events", []))
    return {"techniques": techniques}


def correlation_node(state: InvestigationState) -> dict:
    campaign = correlation_agent.run(
        events=state.get("events", []),
        iocs=state.get("iocs", []),
        techniques=state.get("techniques", []),
    )
    return {"campaign": campaign}


def prediction_node(state: InvestigationState) -> dict:
    prediction = prediction_agent.run(
        techniques=state.get("techniques", []),
        campaign=state.get("campaign", {}),
    )
    return {"prediction": prediction}


def reporting_node(state: InvestigationState) -> dict:
    report = reporting_agent.run(state)
    return {"report": report}
