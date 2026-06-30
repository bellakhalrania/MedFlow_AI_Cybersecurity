import json
from config import config

_technique_index = None


def _load_index() -> dict:
    global _technique_index
    if _technique_index is not None:
        return _technique_index

    from rag.ingest_attack import load_attack_techniques
    techniques = load_attack_techniques(config.ATTACK_DATA_PATH)
    _technique_index = {t["technique_id"]: t for t in techniques}
    return _technique_index


def get_technique(technique_id: str) -> dict | None:
    return _load_index().get(technique_id)


def get_tactic(technique_id: str) -> str | None:
    technique = get_technique(technique_id)
    return technique.get("tactic") if technique else None
