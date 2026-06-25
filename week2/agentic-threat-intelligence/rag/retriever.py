"""
rag/retriever.py
High-level retrieval helper used by attack_mapping_agent.py.
Turns a raw event description into the top-N most relevant ATT&CK
technique snippets, formatted as RAG context for the LLM prompt.
"""

from rag.vector_store import query_similar


def retrieve_attack_context(event_description: str, n_results: int = 3) -> str:
    results = query_similar(event_description, n_results=n_results)

    documents = results.get("documents", [[]])[0]
    metadatas = results.get("metadatas", [[]])[0]

    if not documents:
        return "No relevant ATT&CK techniques found."

    context_blocks = []
    for doc, meta in zip(documents, metadatas):
        context_blocks.append(
            f"[{meta.get('technique_id')}] {meta.get('name')}: {doc}"
        )
    return "\n\n".join(context_blocks)
