"""
knowledge_graph/graph_queries.py
Pre-built investigation queries for analysts, e.g. "show all hosts that
triggered technique T1059".
"""

from databases.neo4j_manager import neo4j_manager


def hosts_using_technique(technique_id: str) -> list[dict]:
    return neo4j_manager.run_query(
        """
        MATCH (h:Host)-[:GENERATED]->(e:Event)-[:MAPPED_TO]->(t:Technique {technique_id: $technique_id})
        RETURN DISTINCT h.name AS host
        """,
        {"technique_id": technique_id},
    )


def campaign_timeline(campaign_id: str) -> list[dict]:
    return neo4j_manager.run_query(
        """
        MATCH (e:Event)-[:PART_OF]->(c:Campaign {campaign_id: $campaign_id})
        RETURN e.event_id AS event_id, e.event_type AS event_type, e.timestamp AS timestamp
        ORDER BY e.timestamp
        """,
        {"campaign_id": campaign_id},
    )


def techniques_in_campaign(campaign_id: str) -> list[dict]:
    return neo4j_manager.run_query(
        """
        MATCH (t:Technique)-[:PART_OF]->(c:Campaign {campaign_id: $campaign_id})
        RETURN t.technique_id AS technique_id, t.name AS name
        """,
        {"campaign_id": campaign_id},
    )
