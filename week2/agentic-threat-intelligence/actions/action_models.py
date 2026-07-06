from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class ActionType(str, Enum):
    BLOCK_IP = "block_ip"
    ISOLATE_HOST = "isolate_host"
    DISABLE_ACCOUNT = "disable_account"
    KILL_PROCESS = "kill_process"
    QUARANTINE_FILE = "quarantine_file"
    NOTIFY_ANALYST = "notify_analyst"


class ActionSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ActionStatus(str, Enum):
    EXECUTED = "executed"
    PENDING_APPROVAL = "pending_approval"
    DENIED = "denied"
    FAILED = "failed"


class ProposedAction(BaseModel):
    action_type: ActionType

    target: str = Field(
        ...,
        min_length=1,
        description="Target of the action (IP, hostname, username, process, hash)"
    )

    severity: ActionSeverity

    rationale: str = Field(
        ...,
        min_length=5,
        max_length=500,
    )

    technique_id: Optional[str] = None

    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )

    @field_validator("target")
    @classmethod
    def clean_target(cls, value: str):
        return value.strip()

    @field_validator("rationale")
    @classmethod
    def clean_reason(cls, value: str):
        return value.strip()


class ActionResult(BaseModel):
    action: ProposedAction

    status: ActionStatus

    detail: str = ""

    dry_run: bool = True