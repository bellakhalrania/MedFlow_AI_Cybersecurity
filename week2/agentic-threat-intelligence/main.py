import argparse
import json

from config import config
from graph.state import new_investigation_state
from graph.workflow import threat_intel_workflow
from memory.investigation_memory import investigation_memory


def load_events(path: str) -> list[dict]:
    with open(path, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            f.seek(0)
            return [json.loads(line) for line in f if line.strip()]


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

    print("\n" + "=" * 60)
    print("RESPONSE ACTIONS")
    print("=" * 60)
    actions = final_state.get("actions_taken", [])
    if not actions:
        print("(no actions proposed)")
    for a in actions:
        action = a["action"]
        print(f"[{a['status'].upper()}] {action['action_type']} -> {action['target']} | {a['detail']}")


if __name__ == "__main__":
    main()
