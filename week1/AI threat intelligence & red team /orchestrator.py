import sys
from pathlib import Path
from typing import Dict, Any, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vectordb.chroma_manager import ChromaManager
from agents.redteam_agent import RedTeamAgent
from agents.cti_agent import CTIAnalystAgent
from agents.attribution_agent import AttributionAgent
from agents.detection_agent import DetectionAgent


AGENT_KEYS = {
    "redteam": "Red Team Agent",
    "cti": "CTI Analyst Agent",
    "attribution": "Attribution Agent",
    "detection": "Detection Agent",
}

_ROUTING_KEYWORDS = {
    "attribution": [
        "who is behind", "which actor", "attribute", "attribution",
        "threat actor responsible", "apt group", "which group",
        "identify the actor", "who could be responsible",
    ],
    "detection": [
        "detect", "detection", "siem", "sigma rule", "log", "logging",
        "alert", "mitigat", "blue team", "monitor", "how can i find",
    ],
    "cti": [
        "healthcare", "hospital", "medical device", "ehr", "risk assessment",
        "threat intelligence", "risk to", "impact on", "patient",
    ],
    "redteam": [
        "kill chain", "attack chain", "red team", "persistence",
        "how does", "procedure", "ttps", "offensive", "penetration test",
    ],
}


class Orchestrator:
    def __init__(self):
        self.chroma = ChromaManager()
        self.agents = {
            "redteam": RedTeamAgent(self.chroma),
            "cti": CTIAnalystAgent(self.chroma),
            "attribution": AttributionAgent(self.chroma),
            "detection": DetectionAgent(self.chroma),
        }

    def route(self, query: str) -> str:
        """Lightweight keyword-based intent classifier. Falls back to
        'redteam' (general technique explanation) when nothing matches --
        it's the most general-purpose of the four agents."""
        q_lower = query.lower()
        scores = {key: 0 for key in self.agents}
        for key, keywords in _ROUTING_KEYWORDS.items():
            for kw in keywords:
                if kw in q_lower:
                    scores[key] += 1

        best_key = max(scores, key=scores.get)
        if scores[best_key] == 0:
            return "redteam"
        return best_key

    def ask(self, query: str, agent_key: Optional[str] = None) -> Dict[str, Any]:
        if agent_key is None:
            agent_key = self.route(query)
        if agent_key not in self.agents:
            raise ValueError(f"Unknown agent_key '{agent_key}'. Valid: {list(self.agents)}")

        agent = self.agents[agent_key]
        result = agent.answer(query)
        
        # Track metadata routing key
        result["routed_to"] = agent_key
        
        # Map the system key to the friendly display name
        agent_name = AGENT_KEYS.get(agent_key, "Unknown Agent")
        
        # Append the executing agent signature to the textual output response
        if "answer" in result:
            result["answer"] = f"{result['answer']}\n\n[Processed by: {agent_name}]"
        elif "response" in result:
            result["response"] = f"{result['response']}\n\n[Processed by: {agent_name}]"
            
        return result

    def stats(self) -> Dict[str, int]:
        return self.chroma.collection_stats()