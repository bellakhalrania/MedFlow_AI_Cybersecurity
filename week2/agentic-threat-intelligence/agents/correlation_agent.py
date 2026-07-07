import logging
import uuid
from typing import List, Dict
from llm.groq_client import invoke_llm
from llm.prompts import CORRELATION_SYSTEM_PROMPT
from llm.output_parsers import extract_json
from knowledge_graph.graph_builder import persist_campaign

logger = logging.getLogger(__name__)


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

            # extract_json may return a list (e.g. LLM wraps a single
            # campaign object in a JSON array) or a dict. Normalize to dict.
            if isinstance(campaign, list):
                campaign = campaign[0] if campaign else {}

            if not isinstance(campaign, dict) or not campaign:
                raise ValueError("Unexpected campaign shape returned by LLM")

            # --- Hallucination guard ---
            # The LLM is meant to correlate/summarize data it was given, not
            # invent new techniques or events. Strip out anything that
            # doesn't trace back to the actual inputs.
            valid_technique_ids = {t.get("technique_id") for t in techniques}
            if "related_techniques" in campaign:
                original = campaign["related_techniques"]
                grounded = [
                    tid for tid in original if tid in valid_technique_ids
                ]
                dropped = set(original) - set(grounded)
                if dropped:
                    logger.warning(
                        f"Dropping ungrounded related_techniques not present in input: {dropped}"
                    )
                campaign["related_techniques"] = grounded

            valid_event_ids = {e.get("event_id") for e in events}
            if "timeline" in campaign:
                original_timeline = campaign["timeline"]
                grounded_timeline = [
                    e for e in original_timeline
                    if isinstance(e, dict) and e.get("event_id") in valid_event_ids
                ]
                dropped_count = len(original_timeline) - len(grounded_timeline)
                if dropped_count:
                    logger.warning(
                        f"Dropped {dropped_count} ungrounded timeline event(s) not present in input"
                    )
                campaign["timeline"] = grounded_timeline

        except ValueError as e:
            logger.error(f"Failed to parse LLM correlation response: {e}")
            campaign = {
                "campaign_id": str(uuid.uuid4()),
                "name": "Unclassified Activity",
                "timeline": events,
                "related_techniques": [t.get("technique_id") for t in techniques],
            }

        campaign.setdefault("campaign_id", str(uuid.uuid4()))

        try:
            persist_campaign(campaign, events, techniques)
        except Exception as e:
            logger.warning(f"Graph persistence failed (best-effort, continuing): {e}")

        return campaign