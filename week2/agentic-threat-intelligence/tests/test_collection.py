import uuid
from unittest.mock import patch

from agents.collection_agent import CollectionAgent


class TestCollectionAgent:

    def setup_method(self):
        self.agent = CollectionAgent()

    # --------------------------------------------------
    # Test 1 : Empty input
    # --------------------------------------------------
    def test_empty_input(self):
        result = self.agent.run([])

        assert result == []

    # --------------------------------------------------
    # Test 2 : One event successfully normalized
    # --------------------------------------------------
    @patch("agents.collection_agent.invoke_llm")
    def test_single_event(self, mock_llm):

        mock_llm.return_value = """
        [
            {
                "timestamp":"2026-07-07T10:00:00Z",
                "hostname":"PC01",
                "event_type":"process_creation",
                "process_name":"powershell.exe"
            }
        ]
        """

        raw_events = [
            {
                "timestamp":"2026-07-07T10:00:00Z",
                "hostname":"PC01",
                "event_type":"process_creation",
                "process_name":"powershell.exe"
            }
        ]

        result = self.agent.run(raw_events)

        assert isinstance(result, list)

        assert len(result) == 1

        assert result[0]["hostname"] == "PC01"

        assert result[0]["process_name"] == "powershell.exe"

        assert "event_id" in result[0]

    # --------------------------------------------------
    # Test 3 : Existing event_id should NOT change
    # --------------------------------------------------
    @patch("agents.collection_agent.invoke_llm")
    def test_existing_event_id(self, mock_llm):

        mock_llm.return_value = """
        [
            {
                "event_id":"123456",
                "hostname":"PC01",
                "process_name":"powershell.exe"
            }
        ]
        """

        raw_events = [
            {
                "event_id":"123456",
                "hostname":"PC01",
                "process_name":"powershell.exe"
            }
        ]

        result = self.agent.run(raw_events)

        assert result[0]["event_id"] == "123456"

    # --------------------------------------------------
    # Test 4 : Batch processing (>20 events)
    # --------------------------------------------------
    @patch("agents.collection_agent.invoke_llm")
    def test_batch_processing(self, mock_llm):

        mock_llm.return_value = """
        [
            {
                "hostname":"PC",
                "process_name":"powershell.exe"
            }
        ]
        """

        raw_events = []

        for i in range(21):

            raw_events.append(
                {
                    "hostname":f"PC{i}",
                    "process_name":"powershell.exe"
                }
            )

        # each batch returns same event
        mock_llm.side_effect = [
            str(raw_events[:20]),
            str(raw_events[20:])
        ]

        result = self.agent.run(raw_events)

        assert len(result) == 21

    # --------------------------------------------------
    # Test 5 : Invalid JSON from LLM
    # --------------------------------------------------
    @patch("agents.collection_agent.invoke_llm")
    def test_invalid_json(self, mock_llm):

        mock_llm.return_value = "THIS IS NOT JSON"

        raw_events = [
            {
                "hostname":"PC01",
                "process_name":"powershell.exe"
            }
        ]

        result = self.agent.run(raw_events)

        # Should fallback to raw event
        assert result[0]["hostname"] == "PC01"

        assert result[0]["process_name"] == "powershell.exe"

        assert "event_id" in result[0]