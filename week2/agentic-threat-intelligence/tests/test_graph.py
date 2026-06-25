from graph.state import new_investigation_state

def test_new_state_has_expected_keys():
    state = new_investigation_state()
    for key in ["events", "iocs", "techniques", "campaign", "prediction", "report"]:
        assert key in state
