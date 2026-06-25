"""
databases/neo4j_manager.py
Manages the Neo4j driver connection and exposes a simple query runner used
by knowledge_graph/graph_builder.py and graph_queries.py.
"""

from neo4j import GraphDatabase
from config import config


class Neo4jManager:
    def __init__(self):
        self._driver = GraphDatabase.driver(
            config.NEO4J_URI, auth=(config.NEO4J_USER, config.NEO4J_PASSWORD)
        )

    def close(self):
        self._driver.close()

    def run_query(self, query: str, parameters: dict = None) -> list[dict]:
        parameters = parameters or {}
        with self._driver.session() as session:
            result = session.run(query, parameters)
            return [record.data() for record in result]

    def verify_connectivity(self) -> bool:
        try:
            self._driver.verify_connectivity()
            return True
        except Exception:
            return False


neo4j_manager = Neo4jManager()
