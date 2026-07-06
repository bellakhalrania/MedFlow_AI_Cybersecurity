"""
rag/vector_store.py
Connects to a local persistent ChromaDB instance and exposes simple
add/query helpers for the ATT&CK technique collection.
"""

import chromadb
from config import config
from rag.embeddings import embed_texts

_client = None


def get_client():
    global _client
    if _client is None:
        _client = chromadb.PersistentClient(path=config.CHROMA_PERSIST_DIR)
    return _client


def get_attack_collection():
    client = get_client()
    return client.get_or_create_collection(name=config.CHROMA_COLLECTION_ATTACK)


def get_cve_collection():
    client = get_client()
    return client.get_or_create_collection(name="cve_database")


def add_chunks(chunks: list[dict], collection_name: str = config.CHROMA_COLLECTION_ATTACK):
    """chunks: list of {text, metadata} dicts (see rag/chunking.py)."""
    if not chunks:
        return
    
    if collection_name == config.CHROMA_COLLECTION_ATTACK:
        collection = get_attack_collection()
    elif collection_name == "cve_database":
        collection = get_cve_collection()
    else:
        raise ValueError(f"Unknown collection: {collection_name}")
    
    texts = [c["text"] for c in chunks]
    metadatas = [c["metadata"] for c in chunks]
    
    # Generate appropriate IDs based on collection type
    if collection_name == config.CHROMA_COLLECTION_ATTACK:
        ids = [f"{m.get('technique_id', 'unknown')}-{i}" for i, m in enumerate(metadatas)]
    else:
        ids = [f"{m.get('cve_id', 'unknown')}-{i}" for i, m in enumerate(metadatas)]
    
    embeddings = embed_texts(texts)

    collection.upsert(
        ids=ids,
        embeddings=embeddings,
        documents=texts,
        metadatas=metadatas,
    )


def query_similar(query_text: str, n_results: int = 3, collection_name: str = config.CHROMA_COLLECTION_ATTACK) -> dict:
    if collection_name == config.CHROMA_COLLECTION_ATTACK:
        collection = get_attack_collection()
    elif collection_name == "cve_database":
        collection = get_cve_collection()
    else:
        raise ValueError(f"Unknown collection: {collection_name}")
    
    embedding = embed_texts([query_text])[0]
    return collection.query(query_embeddings=[embedding], n_results=n_results)
