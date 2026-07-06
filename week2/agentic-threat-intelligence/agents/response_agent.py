from typing import Dict, List
import logging

from llm.groq_client import invoke_llm
from llm.output_parsers import extract_json

from actions.action_models import ProposedAction, ActionResult
from actions.connectors import ACTION_DISPATCH
from actions import policy, audit_log

from config import config

logger = logging.getLogger(__name__)

RESPONSE_SYSTEM_PROMPT = """
You are a Senior Incident Response Analyst.

Based on:

- Threat campaign
- ATT&CK techniques
- Indicators of Compromise

Recommend the BEST response actions.

Available actions:

- block_ip (for malicious IPs/domains)
- isolate_host (for compromised hosts)
- disable_account (for compromised user accounts)
- kill_process (for malicious processes)
- quarantine_file (for malicious files)
- notify_analyst (for human review)

Rules:

- ALWAYS recommend at least 2-3 actions based on the evidence
- For malicious IOCs (verdict: malicious or suspicious), recommend block_ip
- For compromised hosts, recommend isolate_host
- For high-confidence threats (confidence >= 0.70), recommend containment
- Always include confidence (0.0-1.0)
- Always include severity (low/medium/high)
- Always include rationale
- Use exact target values from the IOCs
- Return ONLY JSON array

Example:

[
 {
   "action_type":"block_ip",
   "target":"185.231.55.12",
   "severity":"medium",
   "confidence":0.97,
   "technique_id":"T1071",
   "rationale":"Confirmed malicious C2 communication."
 },
 {
   "action_type":"isolate_host",
   "target":"WORKSTATION-01",
   "severity":"high",
   "confidence":0.85,
   "technique_id":"T1071",
   "rationale":"Host communicating with known C2 server."
 },
 {
   "action_type":"notify_analyst",
   "target":"security-team",
   "severity":"medium",
   "confidence":1.0,
   "technique_id":null,
   "rationale":"Human review required for incident response."
 }
]
"""


class ResponseAgent:

    def run(
        self,
        campaign: Dict,
        techniques: List[Dict],
        iocs: List[Dict],
    ) -> List[ActionResult]:

        logger.info("Running Response Agent")
        logger.info("Campaign: %s", campaign.get("name", "unknown"))
        logger.info("Techniques: %d", len(techniques))
        logger.info("IOCs: %d", len(iocs))

        prompt = f"""
Campaign:
{campaign}

Techniques:
{techniques}

IOCs:
{iocs}
"""

        try:
            response = invoke_llm(
                system_prompt=RESPONSE_SYSTEM_PROMPT,
                user_prompt=prompt,
            )

            logger.info("LLM response received: %s", response[:500])

            proposals = extract_json(response)
            logger.info("Parsed %d action proposals", len(proposals))
        except Exception as e:
            logger.error("Cannot parse LLM response: %s", e)
            logger.error("Raw response: %s", response if 'response' in locals() else "No response")
            logger.info("Using fallback action generation")
            proposals = self._generate_fallback_actions(iocs, campaign)

        results = []

        for proposal in proposals:

            try:
                action = ProposedAction(**proposal)
            except Exception as e:
                logger.warning("Invalid proposed action skipped: %s", e)
                continue

            logger.info(
                "Evaluating action %s -> %s",
                action.action_type,
                action.target,
            )

            decision = policy.evaluate(action)

            logger.info("Policy decision = %s", decision)

            result = self._execute(action, decision)

            audit_log.record(
                result,
                campaign_id=campaign.get("campaign_id", ""),
            )

            results.append(result)

        return results

    def _execute(
        self,
        action: ProposedAction,
        decision: str,
    ) -> ActionResult:

        if decision == "denied":

            logger.info("Action denied")

            return ActionResult(
                action=action,
                status="denied",
                detail="Protected target",
                dry_run=config.DRY_RUN,
            )

        if decision == "pending_approval":

            logger.info("Action waiting approval")

            return ActionResult(
                action=action,
                status="pending_approval",
                detail="Awaiting human approval",
                dry_run=config.DRY_RUN,
            )

        handler = ACTION_DISPATCH.get(action.action_type)

        if handler is None:

            logger.error("No connector for %s", action.action_type)

            return ActionResult(
                action=action,
                status="failed",
                detail="Connector not implemented",
                dry_run=config.DRY_RUN,
            )

        try:

            logger.info(
                "Executing %s on %s",
                action.action_type,
                action.target,
            )

            detail = handler(action.target)

            logger.info("Execution successful")

            return ActionResult(
                action=action,
                status="executed",
                detail=detail,
                dry_run=config.DRY_RUN,
            )

        except Exception as e:

            logger.exception("Execution failed")

            return ActionResult(
                action=action,
                status="failed",
                detail=str(e),
                dry_run=config.DRY_RUN,
            )

    def _generate_fallback_actions(self, iocs: List[Dict], campaign: Dict) -> List[Dict]:
        """Generate fallback actions based on IOC analysis when LLM fails."""
        logger.info("Generating fallback actions from IOCs")
        
        actions = []
        technique_id = campaign.get("related_techniques", [{}])[0].get("technique_id") if campaign.get("related_techniques") else None
        
        # Extract hostname from campaign timeline if available
        hostname = None
        timeline = campaign.get("timeline", [])
        if timeline:
            hostname = timeline[0].get("host")
        
        for ioc in iocs:
            verdict = ioc.get("verdict", "unknown")
            value = ioc.get("value", "")
            ioc_type = ioc.get("ioc_type", "")
            confidence = ioc.get("confidence", 0.0)
            
            if verdict in ["malicious", "suspicious"] and confidence >= 0.6:
                if ioc_type in ["ip", "ipv4", "ipv6"]:
                    actions.append({
                        "action_type": "block_ip",
                        "target": value,
                        "severity": "high" if verdict == "malicious" else "medium",
                        "confidence": confidence,
                        "technique_id": technique_id,
                        "rationale": f"Block {verdict} {ioc_type} based on IOC analysis"
                    })
                elif ioc_type == "domain":
                    actions.append({
                        "action_type": "block_ip",
                        "target": value,
                        "severity": "high",
                        "confidence": confidence,
                        "technique_id": technique_id,
                        "rationale": f"Block malicious domain {value}"
                    })
                elif ioc_type == "url":
                    domain = value.split("/")[2] if "/" in value else value
                    actions.append({
                        "action_type": "block_ip",
                        "target": domain,
                        "severity": "high",
                        "confidence": confidence,
                        "technique_id": technique_id,
                        "rationale": f"Block malicious URL domain {domain}"
                    })
                elif ioc_type == "process_name" and confidence >= 0.7:
                    actions.append({
                        "action_type": "notify_analyst",
                        "target": "security-team",
                        "severity": "medium",
                        "confidence": confidence,
                        "technique_id": technique_id,
                        "rationale": f"Review suspicious process {value}"
                    })
        
        # Add isolate_host if hostname is available and there are malicious IOCs
        if hostname and any(ioc.get("verdict") in ["malicious", "suspicious"] for ioc in iocs):
            actions.append({
                "action_type": "isolate_host",
                "target": hostname,
                "severity": "high",
                "confidence": 0.7,
                "technique_id": technique_id,
                "rationale": f"Isolate compromised host {hostname} due to malicious activity"
            })
        
        # Always add notify_analyst
        actions.append({
            "action_type": "notify_analyst",
            "target": "security-team",
            "severity": "medium",
            "confidence": 1.0,
            "technique_id": None,
            "rationale": "Human review required for incident response"
        })
        
        logger.info("Generated %d fallback actions", len(actions))
        return actions