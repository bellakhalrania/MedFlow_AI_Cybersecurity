"""
intelligence/technique_predictor.py
Non-LLM fallback predictor: a simple lookup table of common ATT&CK
tactic-to-tactic transitions, used as a sanity check / fallback alongside
the LLM-driven prediction_agent.py.
"""

from typing import List

# Simplified common next-tactic transitions (kill-chain heuristics)
NEXT_TACTIC_MAP = {
    "initial-access": ["execution", "persistence"],
    "execution": ["persistence", "privilege-escalation", "defense-evasion"],
    "persistence": ["privilege-escalation", "defense-evasion"],
    "privilege-escalation": ["credential-access", "defense-evasion"],
    "defense-evasion": ["credential-access", "discovery"],
    "credential-access": ["discovery", "lateral-movement"],
    "discovery": ["lateral-movement", "collection"],
    "lateral-movement": ["collection", "command-and-control"],
    "collection": ["exfiltration", "command-and-control"],
    "command-and-control": ["exfiltration", "impact"],
    "exfiltration": ["impact"],
}


def predict_next_tactics(observed_tactics: List[str]) -> List[str]:
    if not observed_tactics:
        return []
    last_tactic = observed_tactics[-1]
    return NEXT_TACTIC_MAP.get(last_tactic, [])
