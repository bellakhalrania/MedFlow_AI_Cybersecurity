"""
rag/attack_chain_retriever.py
Given a sequence of already-mapped techniques (a partial attack chain),
retrieve ATT&CK techniques that commonly follow them - used by the
Prediction Agent in addition to raw LLM reasoning, to ground predictions
in retrieved ATT&CK knowledge rather than pure model guesswork.
"""

from rag.vector_store import query_similar


def retrieve_likely_next_techniques(technique_names: list[str], n_results: int = 5) -> str:
    """
    Builds a synthetic query from the current technique chain and retrieves
    semantically related techniques (proxy for "commonly follows" since the
    base ATT&CK STIX data doesn't encode explicit next-step relationships).
    """
    if not technique_names:
        return "No techniques observed yet."

    query = "Attack chain progression following: " + ", ".join(technique_names)
    results = query_similar(query, n_results=n_results)

    documents = results.get("documents", [[]])[0]
    metadatas = results.get("metadatas", [[]])[0]

    if not documents:
        return "No related techniques found."

    blocks = [
        f"[{meta.get('technique_id')}] {meta.get('name')}: {doc}"
        for doc, meta in zip(documents, metadatas)
    ]
    return "\n\n".join(blocks)
