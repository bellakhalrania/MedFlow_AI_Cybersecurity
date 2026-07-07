# tests/test_attack_mapping_agent.py
from unittest.mock import patch
import pytest
from agents.attack_mapping_agent import AttackMappingAgent


class TestAttackMappingAgent:
    def setup_method(self):
        self.agent = AttackMappingAgent()

    # --------------------------------------------------
    # Test 1: No events -> empty result, no calls made
    # --------------------------------------------------
    @patch("agents.attack_mapping_agent.invoke_llm")
    @patch("agents.attack_mapping_agent.retrieve_attack_context")
    def test_no_events(self, mock_retrieve, mock_llm):
        result = self.agent.run([])
        assert result == []
        mock_retrieve.assert_not_called()
        mock_llm.assert_not_called()

    # --------------------------------------------------
    # Test 2: Successful mapping attaches evidence_event_id
    # --------------------------------------------------
    @patch("agents.attack_mapping_agent.invoke_llm")
    @patch("agents.attack_mapping_agent.retrieve_attack_context")
    def test_successful_mapping(self, mock_retrieve, mock_llm):
        mock_retrieve.return_value = "T1059.001: PowerShell execution"
        mock_llm.return_value = """
        {
            "technique_id": "T1059.001",
            "technique_name": "PowerShell",
            "tactic": "Execution",
            "confidence": 0.9
        }
        """
        events = [
            {
                "event_id": "1",
                "event_type": "process_creation",
                "process": "powershell.exe",
                "command_line": "powershell -enc ...",
                "user": "admin",
            }
        ]

        result = self.agent.run(events)

        assert len(result) == 1
        assert result[0]["technique_id"] == "T1059.001"
        assert result[0]["evidence_event_id"] == "1"

    # --------------------------------------------------
    # Test 3: Invalid JSON -> event is skipped, not crashed on
    # --------------------------------------------------
    @patch("agents.attack_mapping_agent.invoke_llm")
    @patch("agents.attack_mapping_agent.retrieve_attack_context")
    def test_invalid_json_skips_event(self, mock_retrieve, mock_llm):
        mock_retrieve.return_value = "some context"
        mock_llm.return_value = "NOT VALID JSON"
        events = [{"event_id": "1", "event_type": "process_creation"}]

        result = self.agent.run(events)
        assert result == []

    # --------------------------------------------------
    # Test 4: Mixed batch — one event maps, one fails
    # --------------------------------------------------
    @patch("agents.attack_mapping_agent.invoke_llm")
    @patch("agents.attack_mapping_agent.retrieve_attack_context")
    def test_mixed_batch_partial_success(self, mock_retrieve, mock_llm):
        mock_retrieve.return_value = "T1059.001: PowerShell execution"
        mock_llm.side_effect = [
            '{"technique_id": "T1059.001", "technique_name": "PowerShell", "tactic": "Execution", "confidence": 0.9}',
            "NOT VALID JSON",
        ]
        events = [
            {"event_id": "1", "event_type": "process_creation", "process": "powershell.exe"},
            {"event_id": "2", "event_type": "unknown"},
        ]

        result = self.agent.run(events)

        assert len(result) == 1
        assert result[0]["evidence_event_id"] == "1"

    # --------------------------------------------------
    # Test 5: retrieve_attack_context is called per event with event text
    # --------------------------------------------------
    @patch("agents.attack_mapping_agent.invoke_llm")
    @patch("agents.attack_mapping_agent.retrieve_attack_context")
    def test_retrieve_called_with_event_description(self, mock_retrieve, mock_llm):
        mock_retrieve.return_value = "T1059: Command and Scripting Interpreter"
        mock_llm.return_value = '{"technique_id": "T1059", "confidence": 0.8}'
        events = [
            {"event_id": "1", "process": "cmd.exe", "command_line": "whoami"}
        ]

        self.agent.run(events)

        called_arg = mock_retrieve.call_args[0][0]
        assert "process=cmd.exe" in called_arg
        assert "command_line=whoami" in called_arg

    # --------------------------------------------------
    # Test 6: _event_to_text drops fields that are None
    # --------------------------------------------------
    def test_event_to_text_excludes_none_fields(self):
        event = {
            "event_type": "process_creation",
            "process": "cmd.exe",
            "command_line": None,
            "user": None,
            "src_ip": "10.0.0.5",
            "dest_ip": None,
        }
        text = AttackMappingAgent._event_to_text(event)

        assert "process=cmd.exe" in text
        assert "src_ip=10.0.0.5" in text
        assert "command_line=None" not in text
        assert "user=None" not in text
        assert "dest_ip=None" not in text

    # --------------------------------------------------
    # Test 7: Hallucinated technique (string context) is dropped
    # --------------------------------------------------
    @patch("agents.attack_mapping_agent.invoke_llm")
    @patch("agents.attack_mapping_agent.retrieve_attack_context")
    def test_ungrounded_technique_dropped_string_context(self, mock_retrieve, mock_llm):
        # Retrieved context only supports T1059
        mock_retrieve.return_value = "T1059: Command and Scripting Interpreter"
        # LLM invents an unrelated technique never mentioned in retrieved context
        mock_llm.return_value = """
        {
            "technique_id": "T1210",
            "technique_name": "Exploitation of Remote Services",
            "tactic": "Lateral Movement",
            "confidence": 0.9
        }
        """
        events = [{"event_id": "1", "process": "cmd.exe", "command_line": "whoami"}]

        result = self.agent.run(events)
        assert result == []

    # --------------------------------------------------
    # Test 8: Grounded technique (string context) passes through
    # --------------------------------------------------
    @patch("agents.attack_mapping_agent.invoke_llm")
    @patch("agents.attack_mapping_agent.retrieve_attack_context")
    def test_grounded_technique_passes_string_context(self, mock_retrieve, mock_llm):
        mock_retrieve.return_value = "T1059.001: PowerShell execution"
        mock_llm.return_value = """
        {
            "technique_id": "T1059.001",
            "technique_name": "PowerShell",
            "tactic": "Execution",
            "confidence": 0.9
        }
        """
        events = [{"event_id": "1", "process": "powershell.exe"}]

        result = self.agent.run(events)
        assert len(result) == 1
        assert result[0]["technique_id"] == "T1059.001"

    # --------------------------------------------------
    # Test 9: Hallucinated technique (structured list context) is dropped
    # --------------------------------------------------
    @patch("agents.attack_mapping_agent.invoke_llm")
    @patch("agents.attack_mapping_agent.retrieve_attack_context")
    def test_ungrounded_technique_dropped_structured_context(self, mock_retrieve, mock_llm):
        mock_retrieve.return_value = [
            {"technique_id": "T1059", "description": "Command and Scripting Interpreter"}
        ]
        mock_llm.return_value = """
        {"technique_id": "T1210", "technique_name": "Exploitation of Remote Services", "confidence": 0.9}
        """
        events = [{"event_id": "1", "process": "cmd.exe"}]

        result = self.agent.run(events)
        assert result == []

    # --------------------------------------------------
    # Test 10: extract_json returns a list instead of dict — must not crash
    # --------------------------------------------------
    @patch("agents.attack_mapping_agent.invoke_llm")
    @patch("agents.attack_mapping_agent.retrieve_attack_context")
    def test_list_shaped_llm_response_does_not_crash(self, mock_retrieve, mock_llm):
        mock_retrieve.return_value = "T1059.001: PowerShell execution"
        mock_llm.return_value = """
        [
            {"technique_id": "T1059.001", "technique_name": "PowerShell", "tactic": "Execution", "confidence": 0.9}
        ]
        """
        events = [{"event_id": "1", "process": "powershell.exe"}]

        result = self.agent.run(events)
        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["technique_id"] == "T1059.001"

    # --------------------------------------------------
    # Test 11: extract_json returns an empty list -> event skipped
    # --------------------------------------------------
    @patch("agents.attack_mapping_agent.invoke_llm")
    @patch("agents.attack_mapping_agent.retrieve_attack_context")
    def test_empty_list_response_skips_event(self, mock_retrieve, mock_llm):
        mock_retrieve.return_value = "T1059.001: PowerShell execution"
        mock_llm.return_value = "[]"
        events = [{"event_id": "1", "process": "powershell.exe"}]

        result = self.agent.run(events)
        assert result == []