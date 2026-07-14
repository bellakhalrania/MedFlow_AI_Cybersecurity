"""
Simple test script to verify ChromaDB connectivity and functionality.
Run this to check if ChromaDB is working correctly.
"""

import sys
from rag.vector_store import get_client, get_attack_collection, get_cve_collection, query_similar
from config import config

def test_chromadb_connection():
    """Test basic ChromaDB connection."""
    print("=" * 60)
    print("Testing ChromaDB Connection")
    print("=" * 60)
    
    try:
        client = get_client()
        print(f"✓ ChromaDB client initialized")
        print(f"  Persist directory: {config.CHROMA_PERSIST_DIR}")
        return True
    except Exception as e:
        print(f"✗ Failed to connect to ChromaDB: {e}")
        return False

def test_attack_collection():
    """Test MITRE ATT&CK collection."""
    print("\n" + "=" * 60)
    print("Testing MITRE ATT&CK Collection")
    print("=" * 60)
    
    try:
        collection = get_attack_collection()
        count = collection.count()
        print(f"✓ Attack collection exists")
        print(f"  Collection name: {config.CHROMA_COLLECTION_ATTACK}")
        print(f"  Document count: {count}")
        
        if count == 0:
            print("  ⚠ Warning: Collection is empty. Run 'python -m rag.ingest_attack' to populate it.")
            return False
        
        # Test a simple query
        test_query = "malicious process execution"
        results = query_similar(test_query, n_results=2, collection_name=config.CHROMA_COLLECTION_ATTACK)
        
        if results and results.get("documents"):
            print(f"✓ Query test successful")
            print(f"  Test query: '{test_query}'")
            print(f"  Results returned: {len(results['documents'][0])} documents")
            return True
        else:
            print("✗ Query test failed - no results returned")
            return False
            
    except Exception as e:
        print(f"✗ Failed to test attack collection: {e}")
        return False

def test_cve_collection():
    """Test CVE collection."""
    print("\n" + "=" * 60)
    print("Testing CVE Collection")
    print("=" * 60)
    
    try:
        collection = get_cve_collection()
        count = collection.count()
        print(f"✓ CVE collection exists")
        print(f"  Collection name: cve_database")
        print(f"  Document count: {count}")
        
        if count == 0:
            print("  ⚠ Warning: Collection is empty. Run 'python -m rag.ingest_cve' to populate it.")
            return False
        
        # Test a simple query
        test_query = "log4j vulnerability"
        results = query_similar(test_query, n_results=2, collection_name="cve_database")
        
        if results and results.get("documents"):
            print(f"✓ Query test successful")
            print(f"  Test query: '{test_query}'")
            print(f"  Results returned: {len(results['documents'][0])} documents")
            return True
        else:
            print("✗ Query test failed - no results returned")
            return False
            
    except Exception as e:
        print(f"✗ Failed to test CVE collection: {e}")
        return False

def main():
    """Run all ChromaDB tests."""
    print("\nChromaDB Test Suite")
    print("=" * 60)
    
    results = {
        "connection": test_chromadb_connection(),
        "attack_collection": test_attack_collection(),
        "cve_collection": test_cve_collection(),
    }
    
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    
    for test_name, passed in results.items():
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"{status}: {test_name}")
    
    all_passed = all(results.values())
    
    print("\n" + "=" * 60)
    if all_passed:
        print("✓ All tests passed! ChromaDB is working correctly.")
        return 0
    else:
        print("✗ Some tests failed. Check the output above for details.")
        print("\nTroubleshooting tips:")
        print("  - Ensure ChromaDB persist directory exists: ./data/chroma_store")
        print("  - Run 'python -m rag.ingest_attack' to populate ATT&CK data")
        print("  - Run 'python -m rag.ingest_cve' to populate CVE data")
        return 1

if __name__ == "__main__":
    sys.exit(main())
