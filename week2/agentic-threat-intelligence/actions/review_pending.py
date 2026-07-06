import logging

from actions.audit_log import read_pending_approvals, record
from actions.connectors import ACTION_DISPATCH
from actions.action_models import (
    ProposedAction,
    ActionResult,
    ActionType,
    ActionSeverity,
    ActionStatus,
)
from config import config

logger = logging.getLogger(__name__)


def execute_action(entry: dict):

    action = ProposedAction(
        action_type=ActionType(entry["action_type"]),
        target=entry["target"],
        severity=ActionSeverity(entry["severity"]),
        rationale=entry["rationale"],
        confidence=entry["confidence"],
        technique_id=entry.get("technique_id"),
    )

    handler = ACTION_DISPATCH.get(action.action_type)

    if handler is None:

        result = ActionResult(
            action=action,
            status=ActionStatus.FAILED,
            detail="No connector registered.",
            dry_run=config.DRY_RUN,
        )

        record(result, campaign_id=entry["campaign_id"])

        print(result.detail)

        return

    try:

        detail = handler(action.target)

        result = ActionResult(
            action=action,
            status=ActionStatus.EXECUTED,
            detail=detail,
            dry_run=config.DRY_RUN,
        )

    except Exception as e:

        result = ActionResult(
            action=action,
            status=ActionStatus.FAILED,
            detail=str(e),
            dry_run=config.DRY_RUN,
        )

    record(result, campaign_id=entry["campaign_id"])

    print(result.detail)


def main():

    pending = read_pending_approvals()

    if not pending:
        print("No pending actions.")
        return

    print(f"\nFound {len(pending)} pending actions.\n")

    for i, entry in enumerate(pending, start=1):

        print("=" * 70)

        print(f"[{i}] Campaign      : {entry['campaign_id']}")
        print(f"Action          : {entry['action_type']}")
        print(f"Target          : {entry['target']}")
        print(f"Severity        : {entry['severity']}")
        print(f"Confidence      : {entry['confidence']}")
        print(f"Technique       : {entry.get('technique_id')}")
        print(f"Rationale       : {entry['rationale']}")

        print()

        choice = input(
            "Approve [y] | Reject [n] | Execute ALL [a] | Skip [Enter] : "
        ).strip().lower()

        if choice == "a":

            logger.info("Executing remaining actions...")

            execute_action(entry)

            for remaining in pending[i:]:
                execute_action(remaining)

            break

        elif choice == "y":

            execute_action(entry)

        elif choice == "n":

            print("Rejected.")

        else:

            print("Skipped.")


if __name__ == "__main__":
    main()