import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config
from embeddings.embedding_pipeline import embed_query
from vectordb.chroma_manager import ChromaManager


def search(query: str, top_k: int = 10):
    db = ChromaManager()
    query_vector = embed_query(query)
    results = []

    for collection_name in config.ALL_COLLECTIONS:
        response = db.similarity_search(
            collection_name=collection_name,
            query_embedding=query_vector,
            top_k=top_k,
        )

        docs = response["documents"][0]
        metas = response["metadatas"][0]
        dists = response["distances"][0]

        for doc, meta, dist in zip(docs, metas, dists):
            results.append(
                {
                    "collection": collection_name,
                    "distance": dist,
                    "metadata": meta,
                    "document": doc,
                }
            )

    results.sort(key=lambda x: x["distance"])
    return results[:top_k]


def main() -> None:
    while True:
        query = input("\nSearch> ")

        if query.lower() in {"quit", "exit"}:
            break

        results = search(query)

        print("\n===== RESULTS =====\n")

        for i, result in enumerate(results, 1):
            name = (
                result["metadata"].get("name")
                or result["metadata"].get("attack_id")
                or "Unknown"
            )

            print(f"[{i}] {name}")
            print(f"Collection: {result['collection']}")
            print(f"Distance: {result['distance']:.4f}")
            print()
            print(result["document"][:1000])
            print("\n" + "=" * 80 + "\n")


if __name__ == "__main__":
    main()
