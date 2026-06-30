from databases.neo4j_manager import neo4j_manager

CONSTRAINTS = [
    "CREATE CONSTRAINT host_id IF NOT EXISTS FOR (h:Host) REQUIRE h.name IS UNIQUE",
    "CREATE CONSTRAINT event_id IF NOT EXISTS FOR (e:Event) REQUIRE e.event_id IS UNIQUE",
    "CREATE CONSTRAINT technique_id IF NOT EXISTS FOR (t:Technique) REQUIRE t.technique_id IS UNIQUE",
    "CREATE CONSTRAINT campaign_id IF NOT EXISTS FOR (c:Campaign) REQUIRE c.campaign_id IS UNIQUE",
    "CREATE CONSTRAINT ioc_value IF NOT EXISTS FOR (i:IOC) REQUIRE i.value IS UNIQUE",
]


def apply_constraints():
    for stmt in CONSTRAINTS:
        neo4j_manager.run_query(stmt)
