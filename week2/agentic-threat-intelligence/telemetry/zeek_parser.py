"""
telemetry/zeek_parser.py
Parses Zeek (Bro) TSV/JSON connection and DNS logs (conn.log / dns.log) to
provide network context that enriches IOC and correlation analysis.
"""

import json
from typing import List, Dict


def parse_zeek_json_log(filepath: str) -> List[Dict]:
    """Zeek can output JSON logs directly (redef LogAscii::use_json=T)."""
    events = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            events.append(
                {
                    "source": "zeek",
                    "timestamp": entry.get("ts"),
                    "src_ip": entry.get("id.orig_h"),
                    "dest_ip": entry.get("id.resp_h"),
                    "proto": entry.get("proto"),
                    "service": entry.get("service"),
                    "query": entry.get("query"),  # present in dns.log
                    "raw": entry,
                }
            )
    return events
