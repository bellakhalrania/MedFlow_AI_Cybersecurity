"""
memory/investigation_memory.py
Simple in-process (and optionally file-persisted) memory of past
investigations, so agents can reference prior findings instead of treating
every run as a blank slate.
"""

import json
import os
from typing import Dict, List

MEMORY_FILE = "./data/investigation_memory.json"


class InvestigationMemory:
    def __init__(self, path: str = MEMORY_FILE):
        self.path = path
        self._records: List[Dict] = self._load()

    def _load(self) -> List[Dict]:
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as f:
                return json.load(f)
        return []

    def save(self, state_snapshot: Dict):
        self._records.append(state_snapshot)
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self._records, f, indent=2, default=str)

    def recent(self, n: int = 5) -> List[Dict]:
        return self._records[-n:]


investigation_memory = InvestigationMemory()
