import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from data.download_mitre import download_mitre_bundle
from embeddings.embedding_pipeline import embed_documents
from parser.stix_parser import StixParser
from vectordb.chroma_manager import ChromaManager


def run_ingestion(only_collection: str = None, limit: int = None) -> None:
    # Step 1: make sure we have the raw data
    download_mitre_bundle()

    # Step 2: parse STIX -> 4 structured datasets
    parser = StixParser().load()
    datasets = parser.build_all()

    # Step 3 + 4: embed each dataset and push into its ChromaDB collection
    chroma = ChromaManager()

    for collection_name, records in datasets.items():
        if only_collection and collection_name != only_collection:
            continue
        if limit:
            records = records[:limit]
        if not records:
            continue

        print(f"\n[ingest] === {collection_name} ({len(records)} records) ===")
        texts = [r["document"] for r in records]
        vectors = embed_documents(texts)
        chroma.ingest(collection_name, records, vectors)

    print("\n[ingest] Done. Collection sizes:", chroma.collection_stats())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--collection", default=None, help="Only ingest this one collection")
    parser.add_argument("--limit", type=int, default=None, help="Cap records per collection (testing)")
    args = parser.parse_args()
    run_ingestion(only_collection=args.collection, limit=args.limit)


if __name__ == "__main__":
    main()
