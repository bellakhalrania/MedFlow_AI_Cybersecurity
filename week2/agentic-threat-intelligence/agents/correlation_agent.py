"""
agents/correlation_agent.py
Connects isolated events/IOCs/techniques into a single coherent attack
campaign narrative, and persists the relationships into Neo4j via
knowledge_graph/graph_builder.py.
"""

import uuid
from typing import List, Dict
from llm.groq_client import invoke_llm
from llm.prompts import CORRELATION_SYSTEM_PROMPT
from llm.output_parsers import extract_json
from knowledge_graph.graph_builder import persist_campaign


class CorrelationAgent:
    def run(self, events: List[Dict], iocs: List[Dict], techniques: List[Dict]) -> Dict:
        if not events:
            return {}

        prompt = (
            f"Events:\n{events}\n\nIOCs:\n{iocs}\n\nMapped techniques:\n{techniques}"
        )
        response = invoke_llm(system_prompt=CORRELATION_SYSTEM_PROMPT, user_prompt=prompt)

        try:
            campaign = extract_json(response)
        except ValueError:
            campaign = {
                "campaign_id": str(uuid.uuid4()),
                "name": "Unclassified Activity",
                "timeline": events,
                "related_techniques": [t.get("technique_id") for t in techniques],
            }

        campaign.setdefault("campaign_id", str(uuid.uuid4()))

        try:
            persist_campaign(campaign, events, techniques)
        except Exception:
            pass  # graph persistence is best-effort; don't break the pipeline

        return campaign
