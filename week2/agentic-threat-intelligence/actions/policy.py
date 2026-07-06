import time
from collections import defaultdict
from config import config
from actions.action_models import ProposedAction, ActionSeverity

# Targets that must NEVER be auto-actioned, regardless of confidence.
# Populate this with domain controllers, exec accounts, critical infra, etc.
PROTECTED_TARGETS = {
    "DC-FILESRV01",
    "domain admin",
}

# Action types that always require a human, no matter the confidence score.
ALWAYS_REQUIRE_APPROVAL = set()  # No actions always require approval

MIN_AUTO_EXECUTE_CONFIDENCE = 0.70
MAX_ACTIONS_PER_TARGET_PER_HOUR = 3

_action_history = defaultdict(list)  # target -> [timestamps]


def _rate_limit_exceeded(target: str) -> bool:
    now = time.time()
    window_start = now - 3600
    _action_history[target] = [t for t in _action_history[target] if t > window_start]
    return len(_action_history[target]) >= MAX_ACTIONS_PER_TARGET_PER_HOUR


def evaluate(action: ProposedAction) -> str:
    """Returns one of: 'auto_execute', 'pending_approval', 'denied'."""

    if not config.AUTO_RESPONSE_ENABLED:
        return "pending_approval"  # kill switch off -> everything needs a human

    if action.target in PROTECTED_TARGETS:
        return "denied"

    if action.confidence < MIN_AUTO_EXECUTE_CONFIDENCE:
        return "pending_approval"

    if _rate_limit_exceeded(action.target):
        return "pending_approval"

    _action_history[action.target].append(time.time())
    return "auto_execute"
