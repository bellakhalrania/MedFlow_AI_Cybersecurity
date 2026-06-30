from typing import List, Dict
from llm.groq_client import invoke_llm
from llm.output_parsers import extract_json
from actions.action_models import ProposedAction, ActionResult
from actions.connectors import ACTION_DISPATCH
from actions import policy, audit_log
from config import config

RESPONSE_SYSTEM_PROMPT = """You are an incident response analyst. Given a
threat campaign with mapped ATT&CK techniques and IOCs, propose concrete
response actions. For each action, output:
{"action_type": "block_ip|isolate_host|disable_account|kill_process|quarantine_file|notify_analyst",
 "target": "...", "severity": "low|medium|high", "rationale": "...",
 "technique_id": "...", "confidence": 0.0}
Respond ONLY with a JSON array of action objects. Be conservative: only
propose disruptive actions (isolate_host, disable_account) when evidence is
strong. Always include at least one notify_analyst action summarizing the
situation."""


class ResponseAgent:
    def run(self, campaign: Dict, techniques: List[Dict], iocs: List[Dict]) -> List[ActionResult]:
        prompt = f"Campaign:\n{campaign}\n\nTechniques:\n{techniques}\n\nIOCs:\n{iocs}"
        response = invoke_llm(system_prompt=RESPONSE_SYSTEM_PROMPT, user_prompt=prompt)

        try:
            proposals = extract_json(response)
        except ValueError:
            proposals = []

        results = []
        for raw in proposals:
            try:
                action = ProposedAction(**raw)
            except Exception:
                continue  # skip malformed proposals rather than crash the run

            decision = policy.evaluate(action)
            result = self._handle_decision(action, decision)
            audit_log.record(result, campaign_id=campaign.get("campaign_id", ""))
            results.append(result)

        return results

    @staticmethod
    def _handle_decision(action: ProposedAction, decision: str) -> ActionResult:
        if decision == "denied":
            return ActionResult(action=action, status="denied", detail="Target is protected.", dry_run=config.DRY_RUN)

        if decision == "pending_approval":
            return ActionResult(
                action=action,
                status="pending_approval",
                detail="Awaiting human approval ",
                dry_run=config.DRY_RUN,
            )

        # auto_execute
        handler = ACTION_DISPATCH.get(action.action_type)
        if not handler:
            return ActionResult(action=action, status="failed", detail="No connector registered.", dry_run=config.DRY_RUN)

        try:
            detail = handler(action.target)
            return ActionResult(action=action, status="executed", detail=detail, dry_run=config.DRY_RUN)
        except Exception as e:
            return ActionResult(action=action, status="failed", detail=str(e), dry_run=config.DRY_RUN)
