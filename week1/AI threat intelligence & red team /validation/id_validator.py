import sys
from pathlib import Path
from typing import List, Set

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config
from vectordb.chroma_manager import ChromaManager


def extract_mitre_ids(text: str) -> List[str]:
  
    seen: Set[str] = set()
    ids = []
    for match in config.MITRE_ID_PATTERN.findall(text):
        if match not in seen:
            seen.add(match)
            ids.append(match)
    return ids


class MitreIdValidator:
  
    def __init__(self, chroma_manager: ChromaManager = None):
        self.chroma = chroma_manager or ChromaManager()

    def is_valid(self, attack_id: str) -> bool:
        # Technique / sub-technique IDs live in attack_db with exact metadata match.
        if attack_id.startswith("T"):
            return self.chroma.lookup_exact_attack_id(attack_id) is not None

       
        for collection_name in (config.COLLECTION_ACTOR, config.COLLECTION_DETECTION):
            collection = self.chroma.get_collection(collection_name)
            if collection.count() == 0:
                continue
            result = collection.get(where={"attack_id": attack_id})
            if result["ids"]:
                return True
        return False

    def find_invalid_ids(self, candidate_ids: List[str]) -> List[str]:
        return [cid for cid in candidate_ids if not self.is_valid(cid)]

    def validate_query(self, user_query: str) -> dict:
     
        candidate_ids = extract_mitre_ids(user_query)
        invalid = self.find_invalid_ids(candidate_ids)
        return {
            "ok": len(invalid) == 0,
            "checked_ids": candidate_ids,
            "invalid_ids": invalid,
        }


def refusal_message(invalid_ids: List[str]) -> str:
    ids_str = ", ".join(invalid_ids)
    plural = "s" if len(invalid_ids) > 1 else ""
    return (
        f"Technique ID{plural} {ids_str} do{'es' if len(invalid_ids) == 1 else ''} not "
        f"exist in the ingested MITRE ATT&CK dataset. I will not speculate about "
        f"unverified or non-existent ATT&CK identifiers. Please check the ID and "
        f"try again, or browse the ATT&CK Navigator at https://attack.mitre.org/."
    )


if __name__ == "__main__":
    validator = MitreIdValidator()
    for test_id in ["T1047", "T9999", "S0140", "FAKE123"]:
        print(test_id, "->", validator.is_valid(test_id))
