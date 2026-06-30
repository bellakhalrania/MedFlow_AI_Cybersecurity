from actions.audit_log import read_pending_approvals, record
from actions.connectors import ACTION_DISPATCH
from actions.action_models import ProposedAction, ActionResult, ActionType, ActionSeverity
from config import config


def main():
    pending = read_pending_approvals()
    if not pending:
        print("No pending actions.")
        return

    for entry in pending:
        print("\n" + "=" * 60)
        print(f"Campaign:    {entry['campaign_id']}")
        print(f"Action:      {entry['action_type']} -> {entry['target']}")
        print(f"Severity:    {entry['severity']}  Confidence: {entry['confidence']}")
        print(f"Rationale:   {entry['rationale']}")

        choice = input("Approve and execute? [y/N/skip]: ").strip().lower()
        if choice != "y":
            print("Skipped.")
            continue

        action = ProposedAction(
            action_type=ActionType(entry["action_type"]),
            target=entry["target"],
            severity=ActionSeverity(entry["severity"]),
            rationale=entry["rationale"],
            confidence=entry["confidence"],
        )
        handler = ACTION_DISPATCH.get(action.action_type)
        detail = handler(action.target) if handler else "No connector registered."

        result = ActionResult(action=action, status="executed", detail=detail, dry_run=config.DRY_RUN)
        record(result, campaign_id=entry["campaign_id"])
        print(f"-> {detail}")


if __name__ == "__main__":
    main()
