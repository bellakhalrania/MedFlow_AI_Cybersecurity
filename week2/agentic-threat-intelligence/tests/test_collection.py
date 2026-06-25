from agents.collection_agent import CollectionAgent

def test_collection_agent_handles_empty_input():
    agent = CollectionAgent()
    assert agent.run([]) == []
