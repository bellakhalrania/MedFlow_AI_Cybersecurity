# tests/test_response_agent.py
from unittest.mock import patch, MagicMock
import pytest

from agents.response_agent import ResponseAgent
from actions.action_models import ProposedAction, ActionResult


def make_action(**overrides):
    defaults = dict(
        action_type="block_ip",
        target="1.2.3.4",
        severity="high",
        confidence=0.9,
        technique_id="T1071",
        rationale="test rationale",
    )
    defaults.update(overrides)
    return ProposedAction(**defaults)


class TestProposedActionValidation:
    def test_invalid_action_type_rejected_by_model(self):
        with pytest.raises(Exception):  # pydantic.ValidationError
            make_action(action_type="not_a_real_action")


class TestResponseAgentRun:
    def setup_method(self):
        self.agent = ResponseAgent()

    # --------------------------------------------------
    # Test 1: Happy path — LLM returns valid proposals, all allowed & executed
    # --------------------------------------------------
    @patch("agents.response_agent.audit_log")
    @patch("agents.response_agent.policy")
    @patch("agents.response_agent.ACTION_DISPATCH")
    @patch("agents.response_agent.extract_json")
    @patch("agents.response_agent.invoke_llm")
    def test_successful_run_executes_actions(
        self, mock_llm, mock_extract, mock_dispatch, mock_policy, mock_audit
    ):
        mock_llm.return_value = "irrelevant raw text"
        mock_extract.return_value = [
            {
                "action_type": "block_ip",
                "target": "185.231.55.12",
                "severity": "medium",
                "confidence": 0.97,
                "technique_id": "T1071",
                "rationale": "Confirmed malicious C2 communication.",
            }
        ]
        mock_policy.evaluate.return_value = "allowed"
        mock_dispatch.get.return_value = lambda target: f"blocked {target}"

        campaign = {"campaign_id": "abc-123", "name": "Test Campaign"}
        results = self.agent.run(campaign, [], [])

        assert len(results) == 1
        assert results[0].status == "executed"
        mock_audit.record.assert_called_once()

    # --------------------------------------------------
    # Test 2: Invalid JSON from LLM -> falls back to _generate_fallback_actions
    # --------------------------------------------------
    @patch("agents.response_agent.audit_log")
    @patch("agents.response_agent.policy")
    @patch("agents.response_agent.ACTION_DISPATCH")
    @patch("agents.response_agent.extract_json")
    @patch("agents.response_agent.invoke_llm")
    def test_extract_json_failure_triggers_fallback(
        self, mock_llm, mock_extract, mock_dispatch, mock_policy, mock_audit
    ):
        mock_llm.return_value = "NOT VALID JSON"
        mock_extract.side_effect = ValueError("bad json")
        mock_policy.evaluate.return_value = "allowed"
        mock_dispatch.get.return_value = lambda target: "done"

        iocs = [
            {"value": "evil.com", "ioc_type": "domain", "verdict": "malicious", "confidence": 0.9}
        ]
        campaign = {"campaign_id": "abc-123", "name": "Test Campaign"}

        results = self.agent.run(campaign, [], iocs)

        # fallback always adds notify_analyst + block_ip for the malicious domain
        action_types = [r.action.action_type for r in results]
        assert "notify_analyst" in action_types
        assert "block_ip" in action_types

    # --------------------------------------------------
    # Test 3: invoke_llm itself raises -> also falls back
    # --------------------------------------------------
    @patch("agents.response_agent.audit_log")
    @patch("agents.response_agent.policy")
    @patch("agents.response_agent.ACTION_DISPATCH")
    @patch("agents.response_agent.extract_json")
    @patch("agents.response_agent.invoke_llm")
    def test_invoke_llm_exception_triggers_fallback(
        self, mock_llm, mock_extract, mock_dispatch, mock_policy, mock_audit
    ):
        mock_llm.side_effect = Exception("groq unreachable")
        mock_policy.evaluate.return_value = "allowed"
        mock_dispatch.get.return_value = lambda target: "done"

        campaign = {"campaign_id": "abc-123"}
        results = self.agent.run(campaign, [], [])

        # fallback with no iocs still returns the always-on notify_analyst
        assert len(results) == 1
        assert results[0].action.action_type == "notify_analyst"
        mock_extract.assert_not_called()

    # --------------------------------------------------
    # Test 4: Invalid proposed action (missing required field) is skipped,
    #         valid ones still processed
    # --------------------------------------------------
    @patch("agents.response_agent.audit_log")
    @patch("agents.response_agent.policy")
    @patch("agents.response_agent.ACTION_DISPATCH")
    @patch("agents.response_agent.extract_json")
    @patch("agents.response_agent.invoke_llm")
    def test_invalid_action_shape_skipped(
        self, mock_llm, mock_extract, mock_dispatch, mock_policy, mock_audit
    ):
        mock_llm.return_value = "raw"
        mock_extract.return_value = [
            {"action_type": "block_ip"},  # missing required fields -> should fail validation
            {
                "action_type": "notify_analyst",
                "target": "security-team",
                "severity": "medium",
                "confidence": 1.0,
                "technique_id": None,
                "rationale": "review",
            },
        ]
        mock_policy.evaluate.return_value = "allowed"
        mock_dispatch.get.return_value = lambda target: "done"

        results = self.agent.run({"campaign_id": "abc-123"}, [], [])

        # Only the valid one should have made it through
        assert len(results) == 1
        assert results[0].action.action_type == "notify_analyst"

    # --------------------------------------------------
    # Test 5: If ALL proposals are invalid, run returns empty list
    #         without crashing and without calling policy/audit
    # --------------------------------------------------
    @patch("agents.response_agent.audit_log")
    @patch("agents.response_agent.policy")
    @patch("agents.response_agent.ACTION_DISPATCH")
    @patch("agents.response_agent.extract_json")
    @patch("agents.response_agent.invoke_llm")
    def test_all_invalid_actions_returns_empty(
        self, mock_llm, mock_extract, mock_dispatch, mock_policy, mock_audit
    ):
        mock_llm.return_value = "raw"
        mock_extract.return_value = [{"not_a_valid_field": "oops"}]

        results = self.agent.run({"campaign_id": "abc-123"}, [], [])

        assert results == []
        mock_policy.evaluate.assert_not_called()
        mock_audit.record.assert_not_called()

    # --------------------------------------------------
    # Test 6: policy denies action -> status "denied", no handler invoked
    # --------------------------------------------------
    @patch("agents.response_agent.audit_log")
    @patch("agents.response_agent.policy")
    @patch("agents.response_agent.ACTION_DISPATCH")
    @patch("agents.response_agent.extract_json")
    @patch("agents.response_agent.invoke_llm")
    def test_policy_denied_action(
        self, mock_llm, mock_extract, mock_dispatch, mock_policy, mock_audit
    ):
        mock_llm.return_value = "raw"
        mock_extract.return_value = [
            {
                "action_type": "isolate_host",
                "target": "DOMAIN-CONTROLLER-01",
                "severity": "high",
                "confidence": 0.9,
                "technique_id": "T1071",
                "rationale": "critical asset",
            }
        ]
        mock_policy.evaluate.return_value = "denied"

        results = self.agent.run({"campaign_id": "abc-123"}, [], [])

        assert results[0].status == "denied"
        mock_dispatch.get.assert_not_called()

    # --------------------------------------------------
    # Test 7: policy pending_approval -> status reflects that, no execution
    # --------------------------------------------------
    @patch("agents.response_agent.audit_log")
    @patch("agents.response_agent.policy")
    @patch("agents.response_agent.ACTION_DISPATCH")
    @patch("agents.response_agent.extract_json")
    @patch("agents.response_agent.invoke_llm")
    def test_policy_pending_approval(
        self, mock_llm, mock_extract, mock_dispatch, mock_policy, mock_audit
    ):
        mock_llm.return_value = "raw"
        mock_extract.return_value = [
            {
                "action_type": "disable_account",
                "target": "jdoe",
                "severity": "high",
                "confidence": 0.8,
                "technique_id": "T1078",
                "rationale": "compromised creds",
            }
        ]
        mock_policy.evaluate.return_value = "pending_approval"

        results = self.agent.run({"campaign_id": "abc-123"}, [], [])

        assert results[0].status == "pending_approval"
        mock_dispatch.get.assert_not_called()

    # --------------------------------------------------
    # Test 8: audit_log.record called with campaign_id from campaign dict
    # --------------------------------------------------
    @patch("agents.response_agent.audit_log")
    @patch("agents.response_agent.policy")
    @patch("agents.response_agent.ACTION_DISPATCH")
    @patch("agents.response_agent.extract_json")
    @patch("agents.response_agent.invoke_llm")
    def test_audit_log_called_with_campaign_id(
        self, mock_llm, mock_extract, mock_dispatch, mock_policy, mock_audit
    ):
        mock_llm.return_value = "raw"
        mock_extract.return_value = [
            {
                "action_type": "notify_analyst",
                "target": "security-team",
                "severity": "medium",
                "confidence": 1.0,
                "technique_id": None,
                "rationale": "review",
            }
        ]
        mock_policy.evaluate.return_value = "allowed"
        mock_dispatch.get.return_value = lambda target: "done"

        self.agent.run({"campaign_id": "xyz-789"}, [], [])

        _, kwargs = mock_audit.record.call_args
        assert kwargs["campaign_id"] == "xyz-789"

    # --------------------------------------------------
    # Test 9: missing campaign_id defaults to ""
    # --------------------------------------------------
    @patch("agents.response_agent.audit_log")
    @patch("agents.response_agent.policy")
    @patch("agents.response_agent.ACTION_DISPATCH")
    @patch("agents.response_agent.extract_json")
    @patch("agents.response_agent.invoke_llm")
    def test_missing_campaign_id_defaults_to_empty_string(
        self, mock_llm, mock_extract, mock_dispatch, mock_policy, mock_audit
    ):
        mock_llm.return_value = "raw"
        mock_extract.return_value = [
            {
                "action_type": "notify_analyst",
                "target": "security-team",
                "severity": "medium",
                "confidence": 1.0,
                "technique_id": None,
                "rationale": "review",
            }
        ]
        mock_policy.evaluate.return_value = "allowed"
        mock_dispatch.get.return_value = lambda target: "done"

        self.agent.run({}, [], [])  # no campaign_id key

        _, kwargs = mock_audit.record.call_args
        assert kwargs["campaign_id"] == ""


class TestResponseAgentExecute:
    """Unit tests for _execute in isolation — avoids re-driving the whole
    LLM/parsing pipeline just to test dispatch/handler logic."""

    def setup_method(self):
        self.agent = ResponseAgent()

    @patch("agents.response_agent.config")
    def test_denied_returns_denied_result(self, mock_config):
        mock_config.DRY_RUN = True
        action = make_action()

        result = self.agent._execute(action, "denied")

        assert result.status == "denied"
        assert result.detail == "Protected target"
        assert result.dry_run is True

    @patch("agents.response_agent.config")
    def test_pending_approval_returns_pending_result(self, mock_config):
        mock_config.DRY_RUN = False
        action = make_action()

        result = self.agent._execute(action, "pending_approval")

        assert result.status == "pending_approval"
        assert result.detail == "Awaiting human approval"
        assert result.dry_run is False

    @patch("agents.response_agent.config")
    @patch("agents.response_agent.ACTION_DISPATCH")
    def test_no_handler_returns_failed(self, mock_dispatch, mock_config):
        mock_config.DRY_RUN = True
        mock_dispatch.get.return_value = None  # simulate connector not implemented
        action = make_action(action_type="quarantine_file")  # valid enum value

        result = self.agent._execute(action, "allowed")

        assert result.status == "failed"
        assert result.detail == "Connector not implemented"

    @patch("agents.response_agent.config")
    @patch("agents.response_agent.ACTION_DISPATCH")
    def test_handler_success_returns_executed(self, mock_dispatch, mock_config):
        mock_config.DRY_RUN = True
        mock_dispatch.get.return_value = lambda target: f"blocked {target}"
        action = make_action(target="1.2.3.4")

        result = self.agent._execute(action, "allowed")

        assert result.status == "executed"
        assert result.detail == "blocked 1.2.3.4"

    @patch("agents.response_agent.config")
    @patch("agents.response_agent.ACTION_DISPATCH")
    def test_handler_exception_returns_failed(self, mock_dispatch, mock_config):
        mock_config.DRY_RUN = True

        def boom(target):
            raise RuntimeError("connector timeout")

        mock_dispatch.get.return_value = boom
        action = make_action()

        result = self.agent._execute(action, "allowed")

        assert result.status == "failed"
        assert result.detail == "connector timeout"


class TestGenerateFallbackActions:
    """Unit tests for _generate_fallback_actions in isolation."""

    def setup_method(self):
        self.agent = ResponseAgent()

    def test_no_iocs_still_returns_notify_analyst(self):
        actions = self.agent._generate_fallback_actions([], {})

        assert len(actions) == 1
        assert actions[0]["action_type"] == "notify_analyst"
        assert actions[0]["confidence"] == 1.0
        assert actions[0]["technique_id"] is None

    def test_malicious_ip_below_confidence_threshold_ignored(self):
        iocs = [{"value": "1.2.3.4", "ioc_type": "ip", "verdict": "malicious", "confidence": 0.4}]

        actions = self.agent._generate_fallback_actions(iocs, {})

        types = [a["action_type"] for a in actions]
        assert "block_ip" not in types
        assert types == ["notify_analyst"]  # only the always-on one

    def test_malicious_ip_at_or_above_threshold_generates_block(self):
        iocs = [{"value": "1.2.3.4", "ioc_type": "ip", "verdict": "malicious", "confidence": 0.9}]

        actions = self.agent._generate_fallback_actions(iocs, {})

        block_actions = [a for a in actions if a["action_type"] == "block_ip"]
        assert len(block_actions) == 1
        assert block_actions[0]["target"] == "1.2.3.4"
        assert block_actions[0]["severity"] == "high"

    def test_suspicious_verdict_gets_medium_severity(self):
        iocs = [{"value": "1.2.3.4", "ioc_type": "ipv4", "verdict": "suspicious", "confidence": 0.65}]

        actions = self.agent._generate_fallback_actions(iocs, {})

        block_actions = [a for a in actions if a["action_type"] == "block_ip"]
        assert block_actions[0]["severity"] == "medium"

    def test_domain_ioc_generates_block_ip_action(self):
        iocs = [{"value": "evil.com", "ioc_type": "domain", "verdict": "malicious", "confidence": 0.95}]

        actions = self.agent._generate_fallback_actions(iocs, {})

        block_actions = [a for a in actions if a["action_type"] == "block_ip"]
        assert block_actions[0]["target"] == "evil.com"

    def test_url_ioc_extracts_domain_for_block_target(self):
        iocs = [
            {
                "value": "https://evil.com/payload.exe",
                "ioc_type": "url",
                "verdict": "malicious",
                "confidence": 0.9,
            }
        ]

        actions = self.agent._generate_fallback_actions(iocs, {})

        block_actions = [a for a in actions if a["action_type"] == "block_ip"]
        assert block_actions[0]["target"] == "evil.com"

    def test_process_name_ioc_generates_notify_analyst(self):
        iocs = [
            {
                "value": "mimikatz.exe",
                "ioc_type": "process_name",
                "verdict": "malicious",
                "confidence": 0.8,
            }
        ]

        actions = self.agent._generate_fallback_actions(iocs, {})

        # one from the process-specific rationale + one always-on
        process_notifies = [
            a for a in actions
            if a["action_type"] == "notify_analyst" and "mimikatz.exe" in a["rationale"]
        ]
        assert len(process_notifies) == 1

    def test_process_name_below_confidence_ignored(self):
        iocs = [
            {
                "value": "mimikatz.exe",
                "ioc_type": "process_name",
                "verdict": "malicious",
                "confidence": 0.5,
            }
        ]

        actions = self.agent._generate_fallback_actions(iocs, {})

        assert all("mimikatz.exe" not in a["rationale"] for a in actions)

    def test_benign_verdict_generates_no_action(self):
        iocs = [{"value": "1.2.3.4", "ioc_type": "ip", "verdict": "benign", "confidence": 0.99}]

        actions = self.agent._generate_fallback_actions(iocs, {})

        assert actions == [
            {
                "action_type": "notify_analyst",
                "target": "security-team",
                "severity": "medium",
                "confidence": 1.0,
                "technique_id": None,
                "rationale": "Human review required for incident response",
            }
        ]

    def test_hostname_from_campaign_timeline_triggers_isolate_host(self):
        iocs = [{"value": "1.2.3.4", "ioc_type": "ip", "verdict": "malicious", "confidence": 0.9}]
        campaign = {"timeline": [{"host": "WORKSTATION-01"}]}

        actions = self.agent._generate_fallback_actions(iocs, campaign)

        isolate_actions = [a for a in actions if a["action_type"] == "isolate_host"]
        assert len(isolate_actions) == 1
        assert isolate_actions[0]["target"] == "WORKSTATION-01"

    def test_no_hostname_in_timeline_skips_isolate_host(self):
        iocs = [{"value": "1.2.3.4", "ioc_type": "ip", "verdict": "malicious", "confidence": 0.9}]
        campaign = {"timeline": []}

        actions = self.agent._generate_fallback_actions(iocs, campaign)

        assert all(a["action_type"] != "isolate_host" for a in actions)

    def test_hostname_present_but_no_malicious_iocs_skips_isolate_host(self):
        iocs = [{"value": "1.2.3.4", "ioc_type": "ip", "verdict": "benign", "confidence": 0.9}]
        campaign = {"timeline": [{"host": "WORKSTATION-01"}]}

        actions = self.agent._generate_fallback_actions(iocs, campaign)

        assert all(a["action_type"] != "isolate_host" for a in actions)

    def test_technique_id_pulled_from_campaign_related_techniques(self):
        iocs = [{"value": "1.2.3.4", "ioc_type": "ip", "verdict": "malicious", "confidence": 0.9}]
        campaign = {"related_techniques": [{"technique_id": "T1071"}]}

        actions = self.agent._generate_fallback_actions(iocs, campaign)

        block_actions = [a for a in actions if a["action_type"] == "block_ip"]
        assert block_actions[0]["technique_id"] == "T1071"

    def test_no_related_techniques_leaves_technique_id_none(self):
        iocs = [{"value": "1.2.3.4", "ioc_type": "ip", "verdict": "malicious", "confidence": 0.9}]

        actions = self.agent._generate_fallback_actions(iocs, {})

        block_actions = [a for a in actions if a["action_type"] == "block_ip"]
        assert block_actions[0]["technique_id"] is None

    def test_always_appends_notify_analyst_last(self):
        iocs = [{"value": "1.2.3.4", "ioc_type": "ip", "verdict": "malicious", "confidence": 0.9}]

        actions = self.agent._generate_fallback_actions(iocs, {})

        assert actions[-1]["action_type"] == "notify_analyst"
        assert actions[-1]["rationale"] == "Human review required for incident response"