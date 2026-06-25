"""
knowledge_graph/graph_builder.py
Writes events, IOCs, techniques, and campaigns into Neo4j as a connected
graph, so analysts can run relationship queries (e.g. "show all hosts using
T1059").
"""

from typing import List, Dict
from databases.neo4j_manager import neo4j_manager


def persist_campaign(campaign: Dict, events: List[Dict], techniques: List[Dict]):
    campaign_id = campaign.get("campaign_id")
    if not campaign_id:
        return

    neo4j_manager.run_query(
        "MERGE (c:Campaign {campaign_id: $campaign_id}) SET c.name = $name",
        {"campaign_id": campaign_id, "name": campaign.get("name", "Unnamed Campaign")},
    )

    for event in events:
        host = event.get("host")
        event_id = event.get("event_id")
        if not event_id:
            continue

        neo4j_manager.run_query(
            """
            MERGE (e:Event {event_id: $event_id})
            SET e.event_type = $event_type, e.timestamp = $timestamp
            MERGE (e)-[:PART_OF]->(c:Campaign {campaign_id: $campaign_id})
            """,
            {
                "event_id": event_id,
                "event_type": event.get("event_type"),
                "timestamp": event.get("timestamp"),
                "campaign_id": campaign_id,
            },
        )

        if host:
            neo4j_manager.run_query(
                """
                MERGE (h:Host {name: $host})
                MERGE (e:Event {event_id: $event_id})
                MERGE (h)-[:GENERATED]->(e)
                """,
                {"host": host, "event_id": event_id},
            )

    for technique in techniques:
        technique_id = technique.get("technique_id")
        if not technique_id:
            continue

        neo4j_manager.run_query(
            """
            MERGE (t:Technique {technique_id: $technique_id})
            SET t.name = $name
            MERGE (t)-[:PART_OF]->(c:Campaign {campaign_id: $campaign_id})
            """,
            {
                "technique_id": technique_id,
                "name": technique.get("name", ""),
                "campaign_id": campaign_id,
            },
        )

        evidence_event_id = technique.get("evidence_event_id")
        if evidence_event_id:
            neo4j_manager.run_query(
                """
                MATCH (e:Event {event_id: $event_id})
                MERGE (t:Technique {technique_id: $technique_id})
                MERGE (e)-[:MAPPED_TO]->(t)
                """,
                {"event_id": evidence_event_id, "technique_id": technique_id},
            )
