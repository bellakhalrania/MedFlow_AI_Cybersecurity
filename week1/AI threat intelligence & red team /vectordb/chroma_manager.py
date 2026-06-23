import sys
from pathlib import Path
from typing import List, Dict, Any, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config

import chromadb
from chromadb.config import Settings

class ChromaManager:
    def __init__(self, persist_dir: Path = config.CHROMA_DIR):
        persist_dir.mkdir(parents=True, exist_ok=True)
        self.client = chromadb.PersistentClient(
            path=str(persist_dir),
            settings=Settings(anonymized_telemetry=False),
        )
        self._collections = {}

    def get_collection(self, name: str):
        if name not in self._collections:
            self._collections[name] = self.client.get_or_create_collection(
                name=name,
                metadata={"hnsw:space": "cosine"},
            )
        return self._collections[name]

    # ------------------------------------------------------------------
    def ingest(
        self,
        collection_name: str,
        records: List[Dict[str, Any]],
        embeddings: List[List[float]],
        batch_size: int = 256,
    ) -> None:
        collection = self.get_collection(collection_name)

        for i in range(0, len(records), batch_size):
            batch = records[i:i + batch_size]
            batch_embeds = embeddings[i:i + batch_size]

            collection.upsert(
                ids=[r["id"] for r in batch],
                documents=[r["document"] for r in batch],
                metadatas=[r["metadata"] for r in batch],
                embeddings=batch_embeds,
            )

    # ------------------------------------------------------------------
    def query(
        self,
        collection_name: str,
        query_embedding: List[float],
        top_k: int = config.TOP_K_RETRIEVAL,
        where: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:

        collection = self.get_collection(collection_name)

        if collection.count() == 0:
            return []

        result = collection.query(
            query_embeddings=[query_embedding],
            n_results=min(top_k, collection.count()),
            where=where,
        )

        hits = []

        for doc, meta, dist in zip(
            result["documents"][0],
            result["metadatas"][0],
            result["distances"][0],
        ):
            hits.append(
                {
                    "document": doc,
                    "metadata": meta,
                    "distance": dist,
                }
            )

        return hits

    # ------------------------------------------------------------------
    def similarity_search(
        self,
        collection_name: str,
        query_embedding: List[float],
        top_k: int = 5,
    ):
        """
        Raw similarity search without LLM.
        """

        collection = self.get_collection(collection_name)

        if collection.count() == 0:
            return {
                "documents": [[]],
                "metadatas": [[]],
                "distances": [[]],
            }

        return collection.query(
            query_embeddings=[query_embedding],
            n_results=min(top_k, collection.count()),
            include=[
                "documents",
                "metadatas",
                "distances",
            ],
        )

    def lookup_exact_attack_id(self, attack_id: str) -> Optional[Dict[str, Any]]:
        """Direct metadata filter lookup -- used by the ID validator. This is
        NOT a vector search; it's an exact match, which is what we need to
        confirm whether a technique ID genuinely exists."""
        collection = self.get_collection(config.COLLECTION_ATTACK)
        if collection.count() == 0:
            return None
        result = collection.get(where={"attack_id": attack_id})
        if not result["ids"]:
            return None
        return {
            "document": result["documents"][0],
            "metadata": result["metadatas"][0],
        }

    def collection_stats(self) -> Dict[str, int]:
        return {name: self.get_collection(name).count() for name in config.ALL_COLLECTIONS}

   
if __name__ == "__main__":
    mgr = ChromaManager()
    print("[chroma] Current collection sizes:", mgr.collection_stats())


