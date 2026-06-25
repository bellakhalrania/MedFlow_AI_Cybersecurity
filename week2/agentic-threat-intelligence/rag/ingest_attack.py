"""
rag/ingest_attack.py
One-time (or periodic) ingestion script: loads the MITRE ATT&CK Enterprise
STIX bundle and stores embedded technique descriptions in ChromaDB.

Run with:  python -m rag.ingest_attack
Data source: https://github.com/mitre-attack/attack-stix-data
             (enterprise-attack/enterprise-attack.json)
"""

import json
from config import config
from rag.chunking import chunk_attack_technique
from rag.vector_store import add_chunks


def load_attack_techniques(path: str = None) -> list[dict]:
    path = path or config.ATTACK_DATA_PATH
    with open(path, "r", encoding="utf-8") as f:
        stix_bundle = json.load(f)

    techniques = []
    for obj in stix_bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue

        technique_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id")
                break

        if not technique_id:
            continue

        tactics = [
            phase.get("phase_name")
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]

        techniques.append(
            {
                "technique_id": technique_id,
                "name": obj.get("name", ""),
                "description": obj.get("description", ""),
                "tactic": ", ".join(tactics),
            }
        )
    return techniques


def ingest_all(path: str = None):
    techniques = load_attack_techniques(path)
    print(f"Loaded {len(techniques)} ATT&CK techniques from STIX bundle.")

    for i, technique in enumerate(techniques, start=1):
        chunks = chunk_attack_technique(technique)
        add_chunks(chunks)
        if i % 50 == 0:
            print(f"  ingested {i}/{len(techniques)} techniques...")

    print("ATT&CK ingestion complete.")


if __name__ == "__main__":
    ingest_all()
