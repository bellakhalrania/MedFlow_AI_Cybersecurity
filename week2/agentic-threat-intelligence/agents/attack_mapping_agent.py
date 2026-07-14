import logging
from typing import List, Dict
from rag.retriever import retrieve_attack_context
from llm.groq_client import invoke_llm
from llm.prompts import ATTACK_MAPPING_SYSTEM_PROMPT
from llm.output_parsers import extract_json

logger = logging.getLogger(__name__)


class AttackMappingAgent:
    def run(self, events: List[Dict]) -> List[Dict]:
        techniques = []

        for event in events:
            description = self._event_to_text(event)
            context = retrieve_attack_context(description)

            prompt = f"Event:\n{description}\n\nRetrieved ATT&CK context:\n{context}"
            response = invoke_llm(
                system_prompt=ATTACK_MAPPING_SYSTEM_PROMPT, user_prompt=prompt
            )

            try:
                mapped = extract_json(response)

                # extract_json may return a list (e.g. LLM wraps a single
                # mapping in a JSON array) or a dict. Normalize to dict.
                if isinstance(mapped, list):
                    mapped = mapped[0] if mapped else {}

                if not isinstance(mapped, dict) or not mapped:
                    logger.warning(
                        f"Unexpected mapping shape for event {event.get('event_id')}; skipping"
                    )
                    continue

                # --- Hallucination guard ---
                # Only accept a technique if it's actually grounded in the
                # retrieved ATT&CK context. If the LLM invents a technique_id
                # that never showed up in `context`, drop it rather than
                # trusting it blindly.
                technique_id = mapped.get("technique_id")
                if technique_id and not self._is_grounded(technique_id, context):
                    logger.warning(
                        f"Dropping ungrounded technique '{technique_id}' for event "
                        f"{event.get('event_id')} — not present in retrieved ATT&CK context"
                    )
                    continue

                mapped["evidence_event_id"] = event.get("event_id")
                techniques.append(mapped)

            except (ValueError, TypeError, IndexError) as e:
                logger.warning(
                    f"Failed to map event {event.get('event_id')}: {e}"
                )
                continue  # skip events the LLM couldn't confidently map

        return techniques

    @staticmethod
    def _is_grounded(technique_id: str, context) -> bool:
        """
        Check whether a technique_id returned by the LLM is actually
        supported by the retrieved ATT&CK context, rather than trusting
        the LLM's output verbatim.

        Handles both:
        - context as a string (substring check), and
        - context as a list of dicts (e.g. [{"technique_id": ..., ...}]).
        """
        if context is None:
            return False

        if isinstance(context, str):
            return technique_id in context

        if isinstance(context, list):
            retrieved_ids = {
                c.get("technique_id") for c in context if isinstance(c, dict)
            }
            return technique_id in retrieved_ids

        return False

    @staticmethod
    def _event_to_text(event: Dict) -> str:
        parts = [
            f"event_type={event.get('event_type')}",
            f"process={event.get('process')}",
            f"command_line={event.get('command_line')}",
            f"user={event.get('user')}",
            f"src_ip={event.get('src_ip')}",
            f"dest_ip={event.get('dest_ip')}",
        ]
        return ", ".join(p for p in parts if "None" not in p)