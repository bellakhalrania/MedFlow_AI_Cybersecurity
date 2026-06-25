"""
llm/output_parsers.py
LLMs occasionally wrap JSON in markdown fences or add stray prose. These
helpers defensively extract and parse JSON from raw model output.
"""

import json
import re
from typing import Any


def extract_json(text: str) -> Any:
    """Extract and parse the first JSON object or array found in `text`."""
    cleaned = text.strip()

    # Strip ```json ... ``` or ``` ... ``` fences
    fence_match = re.search(r"```(?:json)?\s*(.*?)```", cleaned, re.DOTALL)
    if fence_match:
        cleaned = fence_match.group(1).strip()

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    # Fall back to grabbing the first {...} or [...] block
    obj_match = re.search(r"(\{.*\}|\[.*\])", cleaned, re.DOTALL)
    if obj_match:
        try:
            return json.loads(obj_match.group(1))
        except json.JSONDecodeError:
            pass

    raise ValueError(f"Could not parse JSON from LLM output: {text[:300]}")
