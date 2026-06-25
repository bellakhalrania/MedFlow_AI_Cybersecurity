"""
graph/workflow.py
Wires the six agents into a single linear LangGraph pipeline:

START -> Collection -> Enrichment -> Mapping -> Correlation -> Prediction -> Reporting -> END
"""

from langgraph.graph import StateGraph, START, END
from graph.state import InvestigationState
from graph.nodes import (
    collection_node,
    enrichment_node,
    mapping_node,
    correlation_node,
    prediction_node,
    reporting_node,
)


def build_workflow():
    graph = StateGraph(InvestigationState)

    graph.add_node("collection", collection_node)
    graph.add_node("enrichment", enrichment_node)
    graph.add_node("mapping", mapping_node)
    graph.add_node("correlation", correlation_node)
    graph.add_node("prediction", prediction_node)
    graph.add_node("reporting", reporting_node)

    graph.add_edge(START, "collection")
    graph.add_edge("collection", "enrichment")
    graph.add_edge("enrichment", "mapping")
    graph.add_edge("mapping", "correlation")
    graph.add_edge("correlation", "prediction")
    graph.add_edge("prediction", "reporting")
    graph.add_edge("reporting", END)

    return graph.compile()


# Singleton compiled graph used by main.py
threat_intel_workflow = build_workflow()
