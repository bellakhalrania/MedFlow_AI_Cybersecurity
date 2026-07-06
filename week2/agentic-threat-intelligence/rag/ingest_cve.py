"""
rag/ingest_cve.py
One-time (or periodic) ingestion script: loads CVE data from a JSON file
and stores vulnerability descriptions in ChromaDB for RAG-based retrieval.

Run with:  python -m rag.ingest_cve
Data source: data/cve_data/sample_cves.json (or path to CVE JSON file)
"""

import json
from config import config
from rag.chunking import chunk_attack_technique
from rag.vector_store import add_chunks


def load_cves(path: str = None) -> list[dict]:
    """Load CVE data from JSON file."""
    default_path = "data/cve_data/sample_cves.json"
    path = path or default_path
    
    try:
        with open(path, "r", encoding="utf-8") as f:
            cves = json.load(f)
        return cves
    except FileNotFoundError:
        print(f"Error: CVE data file not found at {path}")
        return []
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in CVE data file: {e}")
        return []


def chunk_cve(cve: dict) -> list[dict]:
    """Chunk a single CVE entry for embedding and retrieval."""
    cve_id = cve.get("cve_id", "unknown")
    description = cve.get("description", "")
    
    # Build affected software string
    affected_software = []
    for sw in cve.get("affected_software", []):
        name = sw.get("name", "")
        versions = ", ".join(sw.get("versions", []))
        if name:
            if versions:
                affected_software.append(f"{name} ({versions})")
            else:
                affected_software.append(name)
    
    software_str = "; ".join(affected_software) if affected_software else "Unknown"
    
    # Build comprehensive text for embedding
    text = f"{cve_id}: {description} Affected Software: {software_str}"
    
    # Create metadata
    metadata = {
        "cve_id": cve_id,
        "cvss_score": cve.get("cvss_score", 0.0),
        "severity": cve.get("severity", "UNKNOWN"),
        "published_date": cve.get("published_date", ""),
        "affected_software": software_str,
        "references": "; ".join(cve.get("references", []))
    }
    
    # Return as a single chunk (can be split further if needed)
    return [{"text": text, "metadata": metadata}]


def ingest_all(path: str = None):
    """Ingest all CVEs from the data file into ChromaDB."""
    cves = load_cves(path)
    
    if not cves:
        print("No CVEs loaded. Ingestion aborted.")
        return
    
    print(f"Loaded {len(cves)} CVEs from data file.")
    
    total_chunks = 0
    for i, cve in enumerate(cves, start=1):
        chunks = chunk_cve(cve)
        add_chunks(chunks, collection_name="cve_database")
        total_chunks += len(chunks)
        
        if i % 10 == 0:
            print(f"  ingested {i}/{len(cves)} CVEs...")
    
    print(f"CVE ingestion complete. Added {total_chunks} chunks to 'cve_database' collection.")


if __name__ == "__main__":
    ingest_all()
