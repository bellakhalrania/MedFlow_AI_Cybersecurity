from typing import List, Dict

# Canonical ATT&CK tactic ordering (kill-chain order), used to sort techniques
# into a coherent storyline even if events arrived out of order.
TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]


def build_storyline(techniques: List[Dict]) -> List[Dict]:
    from intelligence.mitre_mapper import get_tactic

    def sort_key(t):
        tactic = (get_tactic(t.get("technique_id", "")) or "").split(",")[0].strip()
        return TACTIC_ORDER.index(tactic) if tactic in TACTIC_ORDER else len(TACTIC_ORDER)

    return sorted(techniques, key=sort_key)
