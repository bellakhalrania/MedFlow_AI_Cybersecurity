import sys
from pathlib import Path
from typing import Dict, Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config
from agents.base_agent import BaseAgent
from validation.id_validator import refusal_message


def _distance_to_confidence(distance: float) -> str:
    """Cosine distance -> human confidence label. Thresholds are
    deliberately conservative: this agent's whole job is to avoid
    overclaiming attribution."""
    if distance < 0.25:
        return "High"
    elif distance < 0.45:
        return "Medium"
    else:
        return "Low"


class AttributionAgent(BaseAgent):
    name = "Attribution Agent"
    collections = [config.COLLECTION_ACTOR]
    system_prompt = """\
ROLE: Threat Attribution Analyst.

OBJECTIVE: Given observed malware, tools, or behavior described by the
user, identify which known threat actors (intrusion-sets), malware
families, or tools in the retrieved context most plausibly match --
and ONLY actors/malware/tools that appear in the retrieved context.

CRITICAL RULES:
- NEVER invent a threat actor, malware family, or tool name. If the
  retrieved context does not contain a plausible match, say explicitly
  that no attribution can be made from the available data.
- Present candidates ranked by relevance, each with a confidence label
  (High / Medium / Low) which will be supplied to you based on retrieval
  distance -- do not override these labels with your own intuition.
- Be explicit about uncertainty. Attribution is inherently probabilistic;
  do not present any single candidate as certain unless the context
  describes a uniquely identifying characteristic.
- Briefly justify each candidate using only details present in the
  retrieved context (aliases, described behavior, known TTPs).
"""

    def answer(self, query: str) -> Dict[str, Any]:
        validation = self.validator.validate_query(query)
        if not validation["ok"]:
            return {
                "agent": self.name,
                "answer": refusal_message(validation["invalid_ids"]),
                "blocked": True,
                "invalid_ids": validation["invalid_ids"],
                "sources": [],
            }

        hits = self.retrieve(query)

        if not hits:
            return {
                "agent": self.name,
                "answer": (
                    "No threat actors, malware, or tools in the ingested ATT&CK "
                    "dataset match the described behavior. No attribution can be "
                    "made from the available data."
                ),
                "blocked": False,
                "invalid_ids": [],
                "sources": [],
            }

        # Attach computed confidence to each hit so the LLM can't override it
        for h in hits:
            h["confidence"] = _distance_to_confidence(h["distance"])

        confidence_summary = "\n".join(
            f"- {h['metadata'].get('name', 'Unknown')} "
            f"({h['metadata'].get('attack_id', 'no ID')}): "
            f"{h['confidence']} confidence (distance={h['distance']:.3f})"
            for h in hits
        )

        from llm.groq_client import generate_grounded_answer
        augmented_prompt = (
            f"{self.system_prompt}\n\n"
            f"Pre-computed confidence scores (use these exactly, do not "
            f"recalculate):\n{confidence_summary}"
        )

        answer_text = generate_grounded_answer(
            user_query=query,
            retrieved_chunks=hits,
            agent_system_prompt=augmented_prompt,
        )

        return {
            "agent": self.name,
            "answer": answer_text,
            "blocked": False,
            "invalid_ids": [],
            "sources": [
                {
                    "collection": h["collection"],
                    "metadata": h["metadata"],
                    "distance": round(h["distance"], 4),
                    "confidence": h["confidence"],
                }
                for h in hits
            ],
        }
