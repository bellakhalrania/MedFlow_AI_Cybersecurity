import sys
from pathlib import Path
from typing import List

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config

_model = None  

def get_model():
    global _model
    if _model is None:
        from sentence_transformers import SentenceTransformer
        print(f"[embeddings] Loading {config.EMBEDDING_MODEL_NAME} (first call only)...")
        _model = SentenceTransformer(config.EMBEDDING_MODEL_NAME)
    return _model


def embed_documents(texts: List[str], batch_size: int = 32) -> List[List[float]]:
    """Embed a batch of passages/documents for storage in ChromaDB."""
    model = get_model()
    embeddings = model.encode(
        texts,
        batch_size=batch_size,
        normalize_embeddings=True,   # cosine similarity behaves correctly
        show_progress_bar=len(texts) > 50,
    )
    return embeddings.tolist()


def embed_query(query: str) -> List[float]:
    """Embed a single user query. Applies the bge retrieval instruction
    prefix, which materially improves recall vs. embedding the raw query."""
    model = get_model()
    prefixed = config.BGE_QUERY_INSTRUCTION + query
    embedding = model.encode([prefixed], normalize_embeddings=True)
    return embedding[0].tolist()


if __name__ == "__main__":
    
    sample_docs = [
        "Technique T1003: OS Credential Dumping. Adversaries may attempt to "
        "dump credentials to obtain account login and credential material.",
        "Ryuk uses vssadmin to delete shadow copies, preventing recovery.",
    ]
    vecs = embed_documents(sample_docs)
    print(f"[smoke test] embedded {len(vecs)} docs, dim={len(vecs[0])}")

    qvec = embed_query("How does ransomware delete shadow copies?")
    print(f"[smoke test] query embedding dim={len(qvec)}")
