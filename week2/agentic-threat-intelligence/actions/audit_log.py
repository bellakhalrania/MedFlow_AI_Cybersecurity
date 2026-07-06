import json
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict

from actions.action_models import ActionResult

logger = logging.getLogger(__name__)

AUDIT_LOG_PATH = Path("./data/action_audit_log.jsonl")


def record(result: ActionResult, campaign_id: str = "") -> None:
    """
    Save every response action into the audit log.
    One JSON object per line.
    """

    AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "campaign_id": campaign_id,
        "action_type": result.action.action_type.value,
        "target": result.action.target,
        "severity": result.action.severity.value,
        "confidence": result.action.confidence,
        "technique_id": result.action.technique_id,
        "rationale": result.action.rationale,
        "status": result.status.value,
        "detail": result.detail,
        "dry_run": result.dry_run,
    }

    try:
        with AUDIT_LOG_PATH.open("a", encoding="utf-8") as f:
            json.dump(entry, f)
            f.write("\n")

        logger.info(
            "Audit log saved (%s -> %s)",
            entry["action_type"],
            entry["target"],
        )

    except Exception as e:
        logger.exception("Failed writing audit log: %s", e)


def read_pending_approvals() -> List[Dict]:
    """
    Return every action waiting for human approval.
    """

    if not AUDIT_LOG_PATH.exists():
        return []

    pending = []

    with AUDIT_LOG_PATH.open("r", encoding="utf-8") as f:

        for line in f:

            if not line.strip():
                continue

            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                logger.warning("Skipping corrupted audit log entry.")
                continue

            if entry.get("status") == "pending_approval":
                pending.append(entry)

    logger.info("Loaded %d pending approvals", len(pending))

    return pending


def read_all() -> List[Dict]:
    """
    Return all recorded actions.
    """

    if not AUDIT_LOG_PATH.exists():
        return []

    actions = []

    with AUDIT_LOG_PATH.open("r", encoding="utf-8") as f:

        for line in f:

            if line.strip():

                try:
                    actions.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    return actions