from typing import List, Dict
from rag.attack_chain_retriever import retrieve_likely_next_techniques
from llm.groq_client import invoke_llm
from llm.prompts import PREDICTION_SYSTEM_PROMPT
from llm.output_parsers import extract_json


class PredictionAgent:
    def run(self, techniques: List[Dict], campaign: Dict) -> Dict:
        if not techniques:
            return {"likely_next_techniques": [], "rationale": "No techniques observed yet."}

        technique_names = [t.get("name", "") for t in techniques if t.get("name")]
        related_context = retrieve_likely_next_techniques(technique_names)

        prompt = (
            f"Observed techniques so far:\n{technique_names}\n\n"
            f"Campaign context:\n{campaign}\n\n"
            f"Related ATT&CK techniques (RAG):\n{related_context}"
        )
        response = invoke_llm(system_prompt=PREDICTION_SYSTEM_PROMPT, user_prompt=prompt)

        try:
            return extract_json(response)
        except ValueError:
            return {
                "likely_next_techniques": [],
                "rationale": "Prediction could not be parsed from model output.",
            }
