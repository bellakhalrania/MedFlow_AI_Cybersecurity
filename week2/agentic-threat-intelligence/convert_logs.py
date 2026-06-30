"""
convert_logs.py
Example: parses real telemetry exports (Sysmon, Suricata, Wazuh) using the
platform's built-in parsers and combines them into one JSON file ready to
feed into main.py.

Usage:
    python convert_logs.py
"""

import json
from telemetry.sysmon_parser import parse_sysmon_json
from telemetry.suricata_parser import parse_suricata_eve
from telemetry.wazuh_parser import parse_wazuh_alerts

SYSMON_FILE = "data/raw_logs/sysmon_export.json"
SURICATA_FILE = "data/raw_logs/eve.json"
WAZUH_FILE = "data/raw_logs/wazuh_alerts.json"

OUTPUT_FILE = "data/sample_events/credential_dumping_incident.json"


def main():
    events = []
    events += parse_sysmon_json(SYSMON_FILE)
    events += parse_suricata_eve(SURICATA_FILE)
    events += parse_wazuh_alerts(WAZUH_FILE)

    # Sort by timestamp so the timeline reads chronologically
    events.sort(key=lambda e: e.get("timestamp") or "")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(events, f, indent=2)

    print(f"Combined {len(events)} events from 3 sources -> {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
