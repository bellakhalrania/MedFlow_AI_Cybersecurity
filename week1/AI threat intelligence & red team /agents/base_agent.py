import sys
from pathlib import Path
from typing import List, Dict, Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config
from vectordb.chroma_manager import ChromaManager
from embeddings.embedding_pipeline import embed_query
from validation.id_validator import MitreIdValidator, refusal_message
from llm.groq_client import generate_grounded_answer


class BaseAgent:
    name: str = "base_agent"
    collections: List[str] = []
    system_prompt: str = "You are a helpful cybersecurity assistant."

    def __init__(self, chroma_manager: ChromaManager = None):
        self.chroma = chroma_manager or ChromaManager()
        self.validator = MitreIdValidator(self.chroma)

   
    def retrieve(self, query: str, top_k: int = config.TOP_K_RETRIEVAL) -> List[Dict[str, Any]]:
       
        query_vector = embed_query(query)

        all_hits: List[Dict[str, Any]] = []
        for collection_name in self.collections:
            hits = self.chroma.query(collection_name, query_vector, top_k=top_k)
            for h in hits:
                h["collection"] = collection_name
            all_hits.extend(hits)

        
        all_hits.sort(key=lambda h: h["distance"])
        return all_hits[:top_k]

  
    def answer(self, query: str) -> Dict[str, Any]:
       
        validation = self.validator.validate_query(query)
        if not validation["ok"]:
            return {
                "agent": self.name,
                "answer": refusal_message(validation["invalid_ids"]),
                "blocked": True,
                "invalid_ids": validation["invalid_ids"],
                "sources": [],
            }

      
        hits = self.retrieve(query)

       
        answer_text = generate_grounded_answer(
            user_query=query,
            retrieved_chunks=hits,
            agent_system_prompt=self.system_prompt,
        )

        return {
            "agent": self.name,
            "answer": answer_text,
            "blocked": False,
            "invalid_ids": [],
            "sources": [
                {
                    "collection": h["collection"],
                    "metadata": h["metadata"],
                    "distance": round(h["distance"], 4),
                }
                for h in hits
            ],
        }
