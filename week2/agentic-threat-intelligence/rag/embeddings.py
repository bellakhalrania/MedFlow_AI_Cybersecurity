"""
rag/embeddings.py
Wraps a local sentence-transformers model so we never depend on an external
embeddings API for the RAG layer (keeps ATT&CK search fast and offline-capable).
"""

from sentence_transformers import SentenceTransformer
from config import config

_model = None


def get_embedding_model() -> SentenceTransformer:
    global _model
    if _model is None:
        _model = SentenceTransformer(config.EMBEDDING_MODEL)
    return _model


def embed_texts(texts: list[str]) -> list[list[float]]:
    model = get_embedding_model()
    return model.encode(texts, show_progress_bar=False).tolist()
