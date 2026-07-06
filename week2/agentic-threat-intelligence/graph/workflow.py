from langgraph.graph import StateGraph, START, END
from graph.state import InvestigationState
from graph.nodes import (
    collection_node,
    enrichment_node,
    vulnerability_node,
    mapping_node,
    correlation_node,
    prediction_node,
    reporting_node,
    response_node,
)


def build_workflow():
    graph = StateGraph(InvestigationState)

    graph.add_node("collection", collection_node)
    graph.add_node("enrichment", enrichment_node)
    graph.add_node("vulnerability", vulnerability_node)
    graph.add_node("mapping", mapping_node)
    graph.add_node("correlation", correlation_node)
    graph.add_node("predict", prediction_node)
    graph.add_node("reporting", reporting_node)
    graph.add_node("response", response_node)

    graph.add_edge(START, "collection")
    graph.add_edge("collection", "enrichment")
    graph.add_edge("enrichment", "vulnerability")
    graph.add_edge("vulnerability", "mapping")
    graph.add_edge("mapping", "correlation")
    graph.add_edge("correlation", "predict")
    graph.add_edge("predict", "reporting")
    graph.add_edge("reporting", "response")
    graph.add_edge("response", END)

    return graph.compile()


# Singleton compiled graph used by main.py
threat_intel_workflow = build_workflow()

# Force recompilation to ensure changes are picked up
def get_workflow():
    return build_workflow()
