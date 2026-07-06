"""
rag/cve_retriever.py
Retrieves relevant CVEs from the ChromaDB cve_database collection
based on query text (software names, versions, or vulnerability descriptions).
"""

from rag.vector_store import query_similar


def retrieve_cves(query_text: str, n_results: int = 5) -> list[dict]:
    """
    Query the CVE database for vulnerabilities matching the query text.
    
    Args:
        query_text: Text describing software, versions, or vulnerability context
        n_results: Number of CVE results to return
        
    Returns:
        List of CVE dictionaries with metadata including:
        - cve_id: CVE identifier
        - cvss_score: CVSS severity score
        - severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW)
        - description: Vulnerability description
        - affected_software: Affected software and versions
        - published_date: Publication date
        - references: Reference URLs
    """
    if not query_text:
        return []
    
    # Query the CVE database collection
    results = query_similar(query_text, n_results=n_results, collection_name="cve_database")
    
    # Extract and format CVEs from results
    cves = []
    if results and "metadatas" in results and results["metadatas"]:
        for i, metadata in enumerate(results["metadatas"][0]):
            cve = {
                "cve_id": metadata.get("cve_id", "unknown"),
                "cvss_score": metadata.get("cvss_score", 0.0),
                "severity": metadata.get("severity", "UNKNOWN"),
                "description": metadata.get("description", ""),
                "affected_software": metadata.get("affected_software", ""),
                "published_date": metadata.get("published_date", ""),
                "references": metadata.get("references", ""),
                "relevance_score": results.get("distances", [[1.0]])[0][i] if results.get("distances") else 1.0
            }
            cves.append(cve)
    
    return cves


def retrieve_cves_for_software(software_name: str, version: str = None, n_results: int = 5) -> list[dict]:
    """
    Retrieve CVEs for a specific software and optionally version.
    
    Args:
        software_name: Name of the software (e.g., "Apache Log4j")
        version: Optional version string (e.g., "2.14.1")
        n_results: Number of CVE results to return
        
    Returns:
        List of CVE dictionaries
    """
    query = software_name
    if version:
        query = f"{software_name} {version}"
    
    return retrieve_cves(query, n_results=n_results)
