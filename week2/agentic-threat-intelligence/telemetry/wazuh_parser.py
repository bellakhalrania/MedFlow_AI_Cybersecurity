"""
telemetry/wazuh_parser.py
Parses Wazuh SIEM alert exports (JSON format, e.g. from the Wazuh API or
filebeat output) into the platform's raw event format.
"""

import json
from typing import List, Dict


def parse_wazuh_alerts(filepath: str) -> List[Dict]:
    events = []
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read().strip()
        try:
            data = json.loads(content)
            data = data if isinstance(data, list) else [data]
        except json.JSONDecodeError:
            data = [json.loads(line) for line in content.splitlines() if line.strip()]

    for entry in data:
        rule = entry.get("rule", {})
        agent = entry.get("agent", {})
        events.append(
            {
                "source": "wazuh",
                "timestamp": entry.get("timestamp"),
                "host": agent.get("name"),
                "rule_description": rule.get("description"),
                "rule_level": rule.get("level"),
                "rule_groups": rule.get("groups"),
                "raw": entry,
            }
        )
    return events
