"""
agents/collection_agent.py
Converts raw, heterogeneous telemetry (Sysmon/Suricata/Zeek/Wazuh) into a
normalized event schema the rest of the pipeline can rely on.
"""

import uuid
from typing import List, Dict
from llm.groq_client import invoke_llm
from llm.prompts import COLLECTION_SYSTEM_PROMPT
from llm.output_parsers import extract_json


class CollectionAgent:
    def run(self, raw_events: List[Dict]) -> List[Dict]:
        if not raw_events:
            return []

        normalized = []
        # Batch in chunks to stay within context limits for large telemetry dumps
        batch_size = 20
        for i in range(0, len(raw_events), batch_size):
            batch = raw_events[i : i + batch_size]
            response = invoke_llm(
                system_prompt=COLLECTION_SYSTEM_PROMPT,
                user_prompt=str(batch),
            )
            try:
                parsed_batch = extract_json(response)
            except ValueError:
                parsed_batch = batch  # fall back to raw passthrough on parse failure

            for event in parsed_batch:
                event.setdefault("event_id", str(uuid.uuid4()))
                normalized.append(event)

        return normalized
