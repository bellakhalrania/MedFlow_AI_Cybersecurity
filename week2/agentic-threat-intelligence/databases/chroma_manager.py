"""
databases/chroma_manager.py
Thin convenience layer over rag/vector_store.py, kept here so all database
connections (Neo4j + Chroma) are discoverable from one `databases/` package.
"""

from rag.vector_store import get_client, get_attack_collection, add_chunks, query_similar

__all__ = ["get_client", "get_attack_collection", "add_chunks", "query_similar"]
