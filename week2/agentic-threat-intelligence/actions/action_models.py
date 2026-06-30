from enum import Enum
from pydantic import BaseModel
from typing import Optional


class ActionType(str, Enum):
    BLOCK_IP = "block_ip"
    ISOLATE_HOST = "isolate_host"
    DISABLE_ACCOUNT = "disable_account"
    KILL_PROCESS = "kill_process"
    QUARANTINE_FILE = "quarantine_file"
    NOTIFY_ANALYST = "notify_analyst"  # always safe, never needs approval


class ActionSeverity(str, Enum):
    LOW = "low"        # reversible, low blast radius (e.g. notify, tag)
    MEDIUM = "medium"  # reversible but disruptive (e.g. block IP, disable account)
    HIGH = "high"      # disruptive + hard to reverse fast (e.g. isolate host)


class ProposedAction(BaseModel):
    action_type: ActionType
    target: str                      # IP, hostname, username, process id, file hash
    severity: ActionSeverity
    rationale: str
    technique_id: Optional[str] = None   # which ATT&CK technique triggered this
    confidence: float = 0.0


class ActionResult(BaseModel):
    action: ProposedAction
    status: str            # "executed" | "skipped_low_confidence" | "pending_approval" | "denied" | "failed"
    detail: str = ""
    dry_run: bool = True
