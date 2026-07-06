import argparse
import logging

from config import config
from investigation_service import load_events, run_investigation


logger = logging.getLogger(__name__)


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
    print(f"Running investigation on {len(raw_events)} raw events...\n")
    try:
        final_state = run_investigation(raw_events)
    except Exception:
        logger.exception("Investigation run failed")
        return 1

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

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
