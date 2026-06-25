"""
telemetry/suricata_parser.py
Parses Suricata eve.json (EVE JSON output format) alert logs.
"""

import json
from typing import List, Dict


def parse_suricata_eve(filepath: str) -> List[Dict]:
    events = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            if entry.get("event_type") != "alert":
                continue  # only keep IDS alerts, skip flow/dns/http noise

            alert = entry.get("alert", {})
            events.append(
                {
                    "source": "suricata",
                    "timestamp": entry.get("timestamp"),
                    "src_ip": entry.get("src_ip"),
                    "dest_ip": entry.get("dest_ip"),
                    "signature": alert.get("signature"),
                    "category": alert.get("category"),
                    "severity": alert.get("severity"),
                    "raw": entry,
                }
            )
    return events
