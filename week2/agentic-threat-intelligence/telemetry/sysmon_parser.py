"""
telemetry/sysmon_parser.py
Parses Windows Sysmon events (from EVTX export or JSON-exported logs) into
the platform's raw event dict format, ready for collection_agent.py.

Supports two input modes:
  - JSON-lines export (most SIEMs can export Sysmon as JSON)
  - Raw EVTX file (via python-evtx), if available
"""

import json
from typing import List, Dict


def parse_sysmon_json(filepath: str) -> List[Dict]:
    """Parses a JSON or JSON-lines file of Sysmon events."""
    events = []
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read().strip()
        try:
            data = json.loads(content)
            data = data if isinstance(data, list) else [data]
        except json.JSONDecodeError:
            data = [json.loads(line) for line in content.splitlines() if line.strip()]

    for entry in data:
        events.append(
            {
                "source": "sysmon",
                "event_id": entry.get("EventID") or entry.get("event_id"),
                "timestamp": entry.get("UtcTime") or entry.get("timestamp"),
                "host": entry.get("Computer") or entry.get("host"),
                "process": entry.get("Image") or entry.get("process"),
                "command_line": entry.get("CommandLine"),
                "user": entry.get("User"),
                "src_ip": entry.get("SourceIp"),
                "dest_ip": entry.get("DestinationIp"),
                "raw": entry,
            }
        )
    return events


def parse_sysmon_evtx(filepath: str) -> List[Dict]:
    """Optional: parse a raw .evtx file directly using python-evtx."""
    try:
        from Evtx.Evtx import Evtx
        import xml.etree.ElementTree as ET
    except ImportError:
        raise ImportError("Install python-evtx to parse raw .evtx files: pip install python-evtx")

    events = []
    with Evtx(filepath) as log:
        for record in log.records():
            xml_str = record.xml()
            root = ET.fromstring(xml_str)
            ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
            event_data = {
                el.attrib.get("Name"): el.text
                for el in root.findall(".//e:EventData/e:Data", ns)
            }
            events.append({"source": "sysmon", "raw": event_data})
    return events
