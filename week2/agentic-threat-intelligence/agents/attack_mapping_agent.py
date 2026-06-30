from typing import List, Dict
from rag.retriever import retrieve_attack_context
from llm.groq_client import invoke_llm
from llm.prompts import ATTACK_MAPPING_SYSTEM_PROMPT
from llm.output_parsers import extract_json


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
                mapped["evidence_event_id"] = event.get("event_id")
                techniques.append(mapped)
            except ValueError:
                continue  # skip events the LLM couldn't confidently map

        return techniques

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
