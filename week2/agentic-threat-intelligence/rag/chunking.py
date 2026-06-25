"""
rag/chunking.py
Splits long ATT&CK technique descriptions into smaller chunks for embedding,
while keeping technique_id/name as metadata on every chunk.
"""

from typing import List, Dict


def chunk_text(text: str, max_chars: int = 800, overlap: int = 100) -> List[str]:
    if len(text) <= max_chars:
        return [text]

    chunks = []
    start = 0
    while start < len(text):
        end = start + max_chars
        chunks.append(text[start:end])
        start = end - overlap
    return chunks


def chunk_attack_technique(technique: Dict) -> List[Dict]:
    """Returns a list of {text, metadata} chunks for one ATT&CK technique."""
    description = technique.get("description", "")
    chunks = chunk_text(description)
    return [
        {
            "text": chunk,
            "metadata": {
                "technique_id": technique.get("technique_id"),
                "name": technique.get("name"),
                "tactic": technique.get("tactic", ""),
            },
        }
        for chunk in chunks
    ]
