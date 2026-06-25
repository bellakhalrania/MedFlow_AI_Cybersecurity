"""
main.py
Entrypoint: loads sample (or real) telemetry, runs it through the full
LangGraph agent pipeline, and prints/saves the resulting intelligence report.

Usage:
    python main.py
    python main.py --events data/sample_events/sample_events.json
"""

import argparse
import json

from config import config
from graph.state import new_investigation_state
from graph.workflow import threat_intel_workflow
from memory.investigation_memory import investigation_memory


def load_events(path: str) -> list[dict]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def main():
    parser = argparse.ArgumentParser(description="Agentic Threat Intelligence Platform")
    parser.add_argument(
        "--events",
        default="data/sample_events/sample_events.json",
        help="Path to a JSON file of raw events to investigate",
    )
    args = parser.parse_args()

    config.validate()

    raw_events = load_events(args.events)
    initial_state = new_investigation_state(raw_events=raw_events)

    print(f"Running investigation on {len(raw_events)} raw events...\n")
    final_state = threat_intel_workflow.invoke(initial_state)

    investigation_memory.save(final_state)

    print("=" * 60)
    print("INTELLIGENCE REPORT")
    print("=" * 60)
    print(final_state.get("report", "(no report generated)"))


if __name__ == "__main__":
    main()
