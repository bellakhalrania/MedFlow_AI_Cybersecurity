# tests/test_correlation_agent.py
from unittest.mock import patch
import pytest
from agents.correlation_agent import CorrelationAgent


class TestCorrelationAgent:
    def setup_method(self):
        self.agent = CorrelationAgent()

    # --------------------------------------------------
    # Test 1: No events -> empty dict, nothing else called
    # --------------------------------------------------
    @patch("agents.correlation_agent.persist_campaign")
    @patch("agents.correlation_agent.invoke_llm")
    def test_no_events(self, mock_llm, mock_persist):
        result = self.agent.run([], [], [])
        assert result == {}
        mock_llm.assert_not_called()
        mock_persist.assert_not_called()

    # --------------------------------------------------
    # Test 2: Successful correlation
    # --------------------------------------------------
    @patch("agents.correlation_agent.persist_campaign")
    @patch("agents.correlation_agent.invoke_llm")
    def test_successful_correlation(self, mock_llm, mock_persist):
        mock_llm.return_value = """
        {
            "campaign_id": "abc-123",
            "name": "Log4Shell Exploitation Campaign",
            "timeline": [{"event_id": "1"}],
            "related_techniques": ["T1059.001"]
        }
        """
        events = [{"event_id": "1"}]
        iocs = [{"value": "evil.com", "ioc_type": "domain"}]
        techniques = [{"technique_id": "T1059.001"}]

        result = self.agent.run(events, iocs, techniques)

        assert result["campaign_id"] == "abc-123"
        assert result["name"] == "Log4Shell Exploitation Campaign"
        assert result["related_techniques"] == ["T1059.001"]
        mock_persist.assert_called_once_with(result, events, techniques)

    # --------------------------------------------------
    # Test 3: campaign_id is preserved if LLM already provides one
    # --------------------------------------------------
    @patch("agents.correlation_agent.persist_campaign")
    @patch("agents.correlation_agent.invoke_llm")
    def test_existing_campaign_id_not_overwritten(self, mock_llm, mock_persist):
        mock_llm.return_value = '{"campaign_id": "fixed-id", "name": "Test"}'
        result = self.agent.run([{"event_id": "1"}], [], [])
        assert result["campaign_id"] == "fixed-id"

    # --------------------------------------------------
    # Test 4: campaign_id is generated if missing from LLM response
    # --------------------------------------------------
    @patch("agents.correlation_agent.persist_campaign")
    @patch("agents.correlation_agent.invoke_llm")
    def test_campaign_id_generated_if_missing(self, mock_llm, mock_persist):
        mock_llm.return_value = '{"name": "Test Campaign"}'
        result = self.agent.run([{"event_id": "1"}], [], [])
        assert "campaign_id" in result
        assert len(result["campaign_id"]) > 0

    # --------------------------------------------------
    # Test 5: Invalid JSON -> fallback campaign built from raw inputs
    # --------------------------------------------------
    @patch("agents.correlation_agent.persist_campaign")
    @patch("agents.correlation_agent.invoke_llm")
    def test_invalid_json_fallback(self, mock_llm, mock_persist):
        mock_llm.return_value = "NOT VALID JSON"
        events = [{"event_id": "1"}, {"event_id": "2"}]
        techniques = [{"technique_id": "T1059.001"}, {"technique_id": "T1210"}]

        result = self.agent.run(events, [], techniques)

        assert result["name"] == "Unclassified Activity"
        assert result["timeline"] == events
        assert result["related_techniques"] == ["T1059.001", "T1210"]
        assert "campaign_id" in result

    # --------------------------------------------------
    # Test 6: persist_campaign failure does not break the pipeline
    # --------------------------------------------------
    @patch("agents.correlation_agent.persist_campaign")
    @patch("agents.correlation_agent.invoke_llm")
    def test_persist_failure_is_swallowed(self, mock_llm, mock_persist):
        mock_llm.return_value = '{"campaign_id": "abc-123", "name": "Test"}'
        mock_persist.side_effect = Exception("graph db unreachable")

        events = [{"event_id": "1"}]
        result = self.agent.run(events, [], [])

        assert result["campaign_id"] == "abc-123"
        mock_persist.assert_called_once()

    # --------------------------------------------------
    # Test 7: persist_campaign is called with the right arguments
    # --------------------------------------------------
    @patch("agents.correlation_agent.persist_campaign")
    @patch("agents.correlation_agent.invoke_llm")
    def test_persist_called_with_events_and_techniques(self, mock_llm, mock_persist):
        mock_llm.return_value = '{"campaign_id": "abc-123", "name": "Test"}'
        events = [{"event_id": "1"}]
        techniques = [{"technique_id": "T1059.001"}]

        self.agent.run(events, [], techniques)

        args = mock_persist.call_args[0]
        assert args[1] == events
        assert args[2] == techniques

    # --------------------------------------------------
    # Test 8: Hallucinated related_techniques are filtered out
    # --------------------------------------------------
    @patch("agents.correlation_agent.persist_campaign")
    @patch("agents.correlation_agent.invoke_llm")
    def test_hallucinated_related_techniques_filtered(self, mock_llm, mock_persist):
        techniques = [{"technique_id": "T1059.001"}]
        events = [{"event_id": "1"}]

        mock_llm.return_value = """
        {
            "campaign_id": "abc-123",
            "name": "Test Campaign",
            "related_techniques": ["T1059.001", "T1210", "T1548.002"]
        }
        """

        result = self.agent.run(events, [], techniques)

        assert result["related_techniques"] == ["T1059.001"]

    # --------------------------------------------------
    # Test 9: Hallucinated timeline events are filtered out
    # --------------------------------------------------
    @patch("agents.correlation_agent.persist_campaign")
    @patch("agents.correlation_agent.invoke_llm")
    def test_hallucinated_timeline_event_filtered(self, mock_llm, mock_persist):
        events = [{"event_id": "1"}, {"event_id": "2"}]
        mock_llm.return_value = """
        {
            "campaign_id": "abc-123",
            "name": "Test Campaign",
            "timeline": [{"event_id": "1"}, {"event_id": "2"}, {"event_id": "999"}]
        }
        """

        result = self.agent.run(events, [], [])

        returned_ids = {e.get("event_id") for e in result.get("timeline", [])}
        assert returned_ids == {"1", "2"}

    # --------------------------------------------------
    # Test 10: extract_json returns a list instead of dict — must not crash
    # --------------------------------------------------
    @patch("agents.correlation_agent.persist_campaign")
    @patch("agents.correlation_agent.invoke_llm")
    def test_list_shaped_response_does_not_crash(self, mock_llm, mock_persist):
        mock_llm.return_value = '[{"campaign_id": "abc-123", "name": "Test"}]'
        events = [{"event_id": "1"}]

        result = self.agent.run(events, [], [])
        assert isinstance(result, dict)
        assert result["campaign_id"] == "abc-123"

    # --------------------------------------------------
    # Test 11: extract_json returns an empty list -> triggers fallback shape
    # --------------------------------------------------
    @patch("agents.correlation_agent.persist_campaign")
    @patch("agents.correlation_agent.invoke_llm")
    def test_empty_list_response_triggers_fallback(self, mock_llm, mock_persist):
        mock_llm.return_value = "[]"
        events = [{"event_id": "1"}]
        techniques = [{"technique_id": "T1059.001"}]

        result = self.agent.run(events, [], techniques)

        assert result["name"] == "Unclassified Activity"
        assert result["timeline"] == events