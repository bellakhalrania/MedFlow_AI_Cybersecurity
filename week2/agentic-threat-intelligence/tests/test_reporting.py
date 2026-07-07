"""Tests for ReportingAgent."""
import pytest
from unittest.mock import patch
from agents.reporting_agent import ReportingAgent


class TestReportingAgent:
    """Test suite for ReportingAgent."""

    @patch('agents.reporting_agent.save_report')
    @patch('agents.reporting_agent.invoke_llm')
    def test_reporting_agent_generates_report(self, mock_invoke_llm, mock_save_report):
        """Test that report is generated from state."""
        mock_invoke_llm.return_value = "# Test Report\n\nAnalysis complete."
        
        agent = ReportingAgent()
        state = {
            "events": [{"event_id": "e1"}],
            "iocs": [{"value": "192.168.1.1"}],
            "vulnerabilities": [],
            "techniques": [{"technique_id": "T1059.001"}],
            "campaign": {"name": "Test Campaign"},
            "prediction": {"likely_next_techniques": []}
        }
        
        result = agent.run(state)
        
        assert result == "# Test Report\n\nAnalysis complete."
        assert mock_invoke_llm.called
        assert mock_save_report.called

    @patch('agents.reporting_agent.save_report')
    @patch('agents.reporting_agent.invoke_llm')
    def test_reporting_agent_includes_all_state_in_prompt(self, mock_invoke_llm, mock_save_report):
        """Test that all state components are included in prompt."""
        mock_invoke_llm.return_value = "# Report"
        
        agent = ReportingAgent()
        state = {
            "events": [{"event_id": "e1"}],
            "iocs": [{"value": "192.168.1.1"}],
            "vulnerabilities": [{"cve_id": "CVE-2021-44228"}],
            "techniques": [{"technique_id": "T1059.001"}],
            "campaign": {"name": "Test Campaign"},
            "prediction": {"likely_next_techniques": ["T1055"]}
        }
        
        agent.run(state)
        
        # Verify all components were included
        call_args = mock_invoke_llm.call_args
        prompt = str(call_args)
        assert "Events" in prompt
        assert "IOCs" in prompt
        assert "Vulnerabilities" in prompt
        assert "ATT&CK Techniques" in prompt
        assert "Campaign" in prompt
        assert "Prediction" in prompt

    @patch('agents.reporting_agent.save_report')
    @patch('agents.reporting_agent.invoke_llm')
    def test_reporting_agent_saves_report_with_campaign(self, mock_invoke_llm, mock_save_report):
        """Test that report is saved with campaign info."""
        mock_invoke_llm.return_value = "# Report"
        
        agent = ReportingAgent()
        state = {
            "events": [],
            "iocs": [],
            "vulnerabilities": [],
            "techniques": [],
            "campaign": {"campaign_id": "test-123", "name": "Test Campaign"},
            "prediction": {}
        }
        
        agent.run(state)
        
        # Verify save_report was called with campaign
        mock_save_report.assert_called_once()
        call_args = mock_save_report.call_args
        assert call_args[1]["campaign"]["campaign_id"] == "test-123"

    @patch('agents.reporting_agent.save_report')
    @patch('agents.reporting_agent.invoke_llm')
    def test_reporting_agent_handles_empty_state(self, mock_invoke_llm, mock_save_report):
        """Test that empty state is handled."""
        mock_invoke_llm.return_value = "# Empty Report"
        
        agent = ReportingAgent()
        state = {
            "events": [],
            "iocs": [],
            "vulnerabilities": [],
            "techniques": [],
            "campaign": {},
            "prediction": {}
        }
        
        result = agent.run(state)
        
        assert result == "# Empty Report"
        assert mock_invoke_llm.called

    @patch('agents.reporting_agent.save_report')
    @patch('agents.reporting_agent.invoke_llm')
    def test_reporting_agent_handles_missing_campaign(self, mock_invoke_llm, mock_save_report):
        """Test that missing campaign is handled."""
        mock_invoke_llm.return_value = "# Report"
        
        agent = ReportingAgent()
        state = {
            "events": [],
            "iocs": [],
            "vulnerabilities": [],
            "techniques": [],
            "campaign": None,  # Missing campaign
            "prediction": {}
        }
        
        agent.run(state)
        
        # Should still work with None campaign
        mock_save_report.assert_called_once()
        call_args = mock_save_report.call_args
        assert call_args[1]["campaign"] is None
