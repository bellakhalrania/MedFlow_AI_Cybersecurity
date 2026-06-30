import json
import os
from datetime import datetime, timezone
from actions.action_models import ActionResult

AUDIT_LOG_PATH = "./data/action_audit_log.jsonl"


def record(result: ActionResult, campaign_id: str = ""):
    os.makedirs(os.path.dirname(AUDIT_LOG_PATH), exist_ok=True)
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "campaign_id": campaign_id,
        "action_type": result.action.action_type,
        "target": result.action.target,
        "severity": result.action.severity,
        "confidence": result.action.confidence,
        "rationale": result.action.rationale,
        "status": result.status,
        "detail": result.detail,
        "dry_run": result.dry_run,
    }
    with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, default=str) + "\n")


def read_pending_approvals() -> list[dict]:
    if not os.path.exists(AUDIT_LOG_PATH):
        return []
    pending = []
    with open(AUDIT_LOG_PATH, "r", encoding="utf-8") as f:
        for line in f:
            entry = json.loads(line)
            if entry["status"] == "pending_approval":
                pending.append(entry)
    return pending
