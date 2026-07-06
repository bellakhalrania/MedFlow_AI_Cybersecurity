import json
from typing import List, Dict, Any

from graph.state import new_investigation_state
from graph.workflow import get_workflow
from memory.investigation_memory import investigation_memory


def load_events(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            f.seek(0)
            return [json.loads(line) for line in f if line.strip()]


def run_investigation(raw_events: List[Dict[str, Any]]) -> Dict[str, Any]:
    initial_state = new_investigation_state(raw_events=raw_events)
    try:
        workflow = get_workflow()
        final_state = workflow.invoke(initial_state)
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as error:
        if error.__class__.__name__ == "PanicException":
            raise RuntimeError("Workflow backend panic") from error
        raise
    investigation_memory.save(final_state)
    return final_state
